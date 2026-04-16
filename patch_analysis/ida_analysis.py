import argparse
import asyncio
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from common import logger


_IDA9_CANDIDATES = (
    # IDA 9.x dropped idat/idat64 entirely - the unified `ida.exe` runs headless
    # when invoked with -A. Branding moved to "IDA Professional".
    r"C:\Program Files\IDA Professional 9.3\idat.exe",
    r"C:\Program Files\IDA Professional 9.2\idat.exe",
    r"C:\Program Files\IDA Professional 9.1\idat.exe",
    r"C:\Program Files\IDA Professional 9.0\idat.exe",
    r"C:\Program Files\IDA Pro 9.3\idat.exe",
    r"C:\Program Files\IDA Pro 9.2\idat.exe",
    r"C:\Program Files\IDA Pro 9.1\idat.exe",
    r"C:\Program Files\IDA Pro 9.0\idat.exe",
)

_IDA8_CANDIDATES = (
    r"C:\Program Files\IDA Pro 8.4\idat64.exe",
    r"C:\Program Files\IDA Pro 8.3\idat64.exe",
    r"C:\Program Files\IDA Pro 8.2\idat64.exe",
    r"C:\Program Files\IDA Pro 8.1\idat64.exe",
    r"C:\Program Files\IDA Pro 8.0\idat64.exe",
)


def resolve_ida_path() -> Path:
    """Resolve the headless IDA binary.

    Order:
      1. ``IDA_PATH`` env var (absolute file path, takes precedence).
      2. Glob the usual IDA 9.x install roots for ``ida.exe`` (runs headless
         with ``-A``; the separate ``idat`` binary was removed in 9.0).
      3. Glob the usual IDA 8.x install roots for ``idat64.exe``.

    Falls back to the last IDA 8 candidate so ``is_valid_args`` can still
    produce a readable error when nothing is installed.
    """
    env = os.environ.get("IDA_PATH")
    if env:
        path = Path(env)
        if path.is_file():
            return path
        logger.warning(
            f"IDA_PATH={env!r} is not a file; falling back to autodetection"
        )

    for candidate in (*_IDA9_CANDIDATES, *_IDA8_CANDIDATES):
        path = Path(candidate)
        if path.is_file():
            return path

    return Path(_IDA8_CANDIDATES[-1])


@dataclass
class ExecArgs:
    target: Path
    log: str = None
    script: Path = Path("patch_analysis/idapython/analyze.py")
    args: list = None
    ida_path: Path = field(default_factory=resolve_ida_path)


def is_valid_args(args: ExecArgs):
    if not args.ida_path.is_file():
        logger.error(f"ERROR: IDA executable not found at {args.ida_path!r}")
        return False
    if not args.script.is_file():
        logger.error(f"ERROR: IDAPython script not found at {args.script!r}")
        return False
    if not args.target.exists():
        logger.error(f"ERROR: Target file not found at {args.target!r}")
        return False

    return True


def analyze_executable(args: ExecArgs | argparse.Namespace):
    if not is_valid_args(args):
        return -1, None, None

    cmd = [
        f'"{str(args.ida_path)}"',
        f'-L"{args.log}"' if args.log else '',
        "-A",
        f'-S"{args.script}"',
        f'"{str(args.target)}"'
    ]

    try:
        result = subprocess.run(
            " ".join(cmd),
            shell=True,
            check=False,
            universal_newlines=True
        )
    except Exception as e:
        print(f"Failed to launch IDA: {e}", file=sys.stderr)
        return -1

    return result.returncode


async def aanalyze_executable(args: ExecArgs):
    if not is_valid_args(args):
        return -1, None, None

    cmd = f'"{args.ida_path}"'
    if args.log:
        cmd += f' -L"{args.log}"'

    cmd += ' -A'

    script = [args.script]
    if args.args:
        script.extend(args.args)

    esc_script = subprocess.list2cmdline([subprocess.list2cmdline(script)])
    cmd += f" -S{esc_script}"

    cmd += f' "{args.target}"'

    process = await asyncio.create_subprocess_shell(cmd)
    await process.wait()
    return process.returncode


async def batch_analysis(files: list[ExecArgs], condition: Callable[[ExecArgs], bool] = lambda _: True):
    while files:
        current: list[ExecArgs] = []
        remains: list[ExecArgs] = []
        for file in files:
            if not any(x for x in current if x.target == file.target):
                current.append(file)
            else:
                remains.append(file)

        tasks = [aanalyze_executable(file) for file in current if condition(file)]

        await asyncio.gather(*tasks)
        files = remains


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run IDA Pro headless analysis on a target file."
    )
    parser.add_argument(
        "--ida-path",
        type=Path,
        default=resolve_ida_path(),
        help="Full path to ida.exe (IDA 9.x) or idat64.exe (IDA 8.x)"
    )
    parser.add_argument(
        "--log",
        type=str,
        default="log.txt",
        help="Log file path (relative or absolute)"
    )
    parser.add_argument(
        "--script",
        type=Path,
        default=Path("idapython/main.py"),
        help="Path to your IDAPython script"
    )
    parser.add_argument(
        "target",
        type=Path,
        help="The binary or SYS file to analyze"
    )

    args = parser.parse_args()

    analyze_executable(args)
