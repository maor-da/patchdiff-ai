import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace

import polars as pl
from common import AgentModels, Timer, Threshold, logger, console
from args import get_cve_list, get_month_cve, print_report
from defaultdataclass import defaultdataclass, field
from supervisor.supervisor import Supervisor


# snapshot2 = tracemalloc.take_snapshot()
dbg = False


async def run(cve: str, config: dict = None):
    pd_ai = Supervisor()
    async for step in pd_ai.run(cve=cve, config=config):
        pass

    return True


async def patch_wedensday_assistant(argv: list[str]):
    cve_list, args = get_cve_list(argv)
    if cve_list is None or len(cve_list) == 0:
        return

    with Timer("Patch Wednesday Assistant"):
        config = {
            "interrupt": False if len(cve_list) > 1 else True,
            "threshold": Threshold(
                candidates=7.5, security_modification=0.25, report=0.1
            ),
            'evaluate': args.eval
        }
        console.info(f"[*] Start the system with config: {config}")
        tasks = [await asyncio.to_thread(run, cve=c, config=config) for c in cve_list]
        results = await asyncio.gather(*tasks, return_exceptions=(not dbg))
        logger.debug(f"Results: {results}")

    console.info("[+] Done.")

async def evaluate(save = False):
    cve_df = pl.DataFrame()
    cache = Path("rsrc/.eval_cve_df")

    if cache.exists() and not save:
        cve_df = pl.DataFrame.deserialize(cache)
    else:
        for month in [
            "2025-mar",
            "2025-apr",
            "2025-may",
            "2025-jun",
            "2025-jul",
            "2025-aug",
            "2025-sep",
            "2025-oct",
            "2025-nov",
            "2025-dec",
            "2026-jan",
        ]:
            args = SimpleNamespace()
            args.platform_ids = set(['12390'])
            year, mon = month.split("-")
            args.month = f"{year}-{mon.capitalize()}"
            cve, name, ids, df = get_month_cve(args)
            if save:
                for c in cve:
                    os_name = "".join(x.replace(" ", "_") for x in (name or []))
                    os_id = "".join(str(x) for x in (ids or []))
                    print_report(
                        c,
                        to_file=True,
                        monthly_path=f"{args.month}.{os_name}.{os_id}".lower(),
                    )
            
            cve_df = pl.concat([cve_df, df])
            
        if save:
            return

        cve_df.serialize(Path("rsrc/.eval_cve_df"), format="binary")

    # Filter top 20% of highest CVSS scores
    cve_df = cve_df.filter(
        pl.col("CVSS").is_not_null()
    ).sort(
        "CVSS", descending=True
    )
    
    # Take top 20%
    top_20_percent = int(len(cve_df) * 0.2)
    cve_df = cve_df.head(top_20_percent)
    
    # Update cve_list to only include filtered CVEs
    cve_list = cve_df["CVE"].to_list()
    

    with Timer("Patch Wednesday Assistant"):
        config = {
            "interrupt": False,
            "threshold": Threshold(
                candidates=7.5, security_modification=0.25, report=0.1
            ),
            'evaluate': True
        }
        console.info(f"[*] Start the system with config: {config}")
        tasks = [await asyncio.to_thread(run, cve=c, config=config) for c in cve_list]
        results = await asyncio.gather(*tasks, return_exceptions=(not dbg))
        logger.debug(f"Results: {results}")

    console.info("[+] Done.")


if __name__ == "__main__":
    try:
        asyncio.run(patch_wedensday_assistant(sys.argv[1:]), debug=dbg)
        # asyncio.run(evaluate(False), debug=dbg)
    except (EOFError, KeyboardInterrupt):
        pass
