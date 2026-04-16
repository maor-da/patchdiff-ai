import difflib
import sqlite3
from pathlib import Path

from bindiff import BinDiff
import polars as pl

from common import PatchStoreEntry, logger, Timer
from patch_analysis import ida_analysis


async def bindiff_files(subjects: pl.DataFrame, curr_kb, prev_kb):
    with Timer('analyze and export'):
        analysis_tasks: list[ida_analysis.ExecArgs] = []
        for subject in subjects.filter(pl.col('kb') != 'base').iter_rows(named=True):
            subject = PatchStoreEntry().from_dict(subject, overwrite=True)
            analysis_tasks.append(ida_analysis.ExecArgs(target=Path(subject.path)))

        await ida_analysis.batch_analysis(analysis_tasks, lambda file: not file.target.with_name(
            file.target.name + '.BinExport').exists())

    diffs: list[BinDiff] = []

    with Timer('generate bindiff'):
        for subject in subjects.filter((pl.col('kb') == curr_kb)).iter_rows(named=True):
            subject = PatchStoreEntry().from_dict(subject, overwrite=True)
            logger.info(
                f'Diffing {subject.name} from {curr_kb} against {prev_kb}')  # TODO: If there is no prev version use base

            prev_subject = subjects.filter((pl.col('kb') == prev_kb) &
                                           (pl.col('name') == subject.name)).row(0, named=True)

            if not prev_subject:
                logger.warning(f'There is no {prev_kb} version available')
                continue

            prev_subject = PatchStoreEntry().from_dict(prev_subject, overwrite=True)

            curr_binexport = subject.path + '.BinExport'
            prev_binexport = prev_subject.path + '.BinExport'
            bindiff_path = f'{subject.path}.{prev_kb}.BinDiff'

            try:
                diff = BinDiff.from_binexport_files(curr_binexport, prev_binexport, bindiff_path)
            except sqlite3.DatabaseError:
                logger.warning(f'BinDiff database corrupted for {subject.name}, regenerating...')
                diff = BinDiff.from_binexport_files(curr_binexport, prev_binexport, bindiff_path, override=True)

            if not diff:
                logger.warning(f'Faild to bindiff {subject.name}')
                continue

            diffs.append(diff)

    return diffs


def create_diff_text(before: Path, after: Path):
    if not (before.exists() and after.exists()):
        return None, None, None

    before_code = before.read_text(encoding="utf-8")
    after_code = after.read_text(encoding="utf-8")

    udiff = difflib.unified_diff(
        before_code.splitlines(),
        after_code.splitlines(),
        fromfile=f'{before.name} before',
        tofile=f'{after.name} after',
        lineterm=""
    )

    return "\n".join(udiff), before_code, after_code
