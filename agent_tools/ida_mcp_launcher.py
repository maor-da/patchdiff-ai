import asyncio
import os
import subprocess
import sys
from pathlib import Path

from common import logger


DEFAULT_PORT_BASE = 8745
DEFAULT_BOOT_TIMEOUT = 60.0


class IdaMcpLaunchError(RuntimeError):
    """Raised when idalib-mcp could not be started or its port failed to open."""


class IdaMcpLauncher:
    """Async context manager that launches a pair of idalib-mcp servers.

    Spawns ``idalib-mcp`` via ``subprocess.Popen`` with ``--isolated-contexts``
    so two idalib sessions can coexist in the same process tree. Ports are
    probed via a plain TCP ``asyncio.open_connection`` to avoid hanging on the
    long-lived SSE stream.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port_base: int | None = None,
        boot_timeout: float | None = None,
        binary: str | None = None,
    ):
        self.host = host
        self.port_base = port_base or int(
            os.environ.get("IDA_MCP_PORT_BASE", DEFAULT_PORT_BASE)
        )
        self.boot_timeout = boot_timeout or float(
            os.environ.get("IDA_MCP_BOOT_TIMEOUT", DEFAULT_BOOT_TIMEOUT)
        )
        self.binary = binary or os.environ.get("IDALIB_MCP_BIN", "idalib-mcp")
        self._procs: list[subprocess.Popen] = []

    async def __aenter__(self) -> "IdaMcpLauncher":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.stop_all()

    async def start(self, target: Path, port: int) -> str:
        cmd = [
            self.binary,
            "--host", self.host,
            "--port", str(port),
            "--isolated-contexts",
            str(target),
        ]
        logger.info(f"[idalib-mcp] launching: {' '.join(cmd)}")

        popen_kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        try:
            proc = subprocess.Popen(cmd, **popen_kwargs)
        except FileNotFoundError as exc:
            raise IdaMcpLaunchError(
                f"idalib-mcp binary not found (set IDALIB_MCP_BIN): {self.binary}"
            ) from exc

        self._procs.append(proc)

        try:
            await self._wait_port_open(self.host, port)
        except IdaMcpLaunchError:
            self.stop_all()
            raise

        return f"http://{self.host}:{port}/sse"

    async def start_pair(self, primary: Path, secondary: Path) -> tuple[str, str]:
        primary_url = await self.start(primary, self.port_base)
        secondary_url = await self.start(secondary, self.port_base + 1)
        return primary_url, secondary_url

    async def _wait_port_open(self, host: str, port: int) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.boot_timeout
        last_exc: BaseException | None = None

        while loop.time() < deadline:
            try:
                _, writer = await asyncio.open_connection(host, port)
            except (ConnectionRefusedError, OSError) as exc:
                last_exc = exc
                await asyncio.sleep(0.25)
                continue

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        raise IdaMcpLaunchError(
            f"idalib-mcp did not open {host}:{port} within "
            f"{self.boot_timeout:.0f}s (last error: {last_exc})"
        )

    def stop_all(self) -> None:
        for proc in self._procs:
            if proc.poll() is not None:
                continue
            try:
                proc.terminate()
            except Exception as exc:
                logger.warning(f"[idalib-mcp] terminate failed: {exc}")

        for proc in self._procs:
            if proc.poll() is not None:
                continue
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                logger.warning("[idalib-mcp] termination timed out, killing")
                try:
                    proc.kill()
                except Exception as exc:
                    logger.warning(f"[idalib-mcp] kill failed: {exc}")

        self._procs.clear()
