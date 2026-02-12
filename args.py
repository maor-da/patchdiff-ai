import argparse
from pathlib import Path
import re

from agent_tools.vector_store import VectorStore
from common import console, save_to_file
from patch_downloader.filter_by_platform import (
    get_pt_cve_list_by_platform,
    print_cve_list,
)


def cve_type(value: str) -> str:
    """Validate CVE pattern CVE-YYYY-NNNNN (4–7 digits)."""
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", value, flags=re.IGNORECASE):
        raise argparse.ArgumentTypeError(
            "Invalid CVE format; expected CVE-YYYY-NNNN[…] (e.g. CVE-2025-32713)."
        )
    return value.upper()


def month_type(value: str) -> str:
    """Validate Patch‑Tuesday month pattern YYYY-MMM with English month abbrev."""
    if not re.fullmatch(
        r"\d{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)",
        value,
        flags=re.IGNORECASE,
    ):
        raise argparse.ArgumentTypeError(
            "Invalid month format; expected YYYY-MMM (e.g. 2025-Jul)."
        )
    # Normalise capitalisation (2025-Jul → 2025-Jul)
    year, mon = value.split("-")
    return f"{year}-{mon.capitalize()}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate a single CVE report or a Patch Tuesday batch report."
    )

    sub = p.add_subparsers(
        dest="mode", required=True, metavar="{cve,month,get_cached_report}"
    )

    # get_cached_report MODE
    cached_p = sub.add_parser("get_cached_report", help="Print cached report if exist")
    cache_mux = cached_p.add_mutually_exclusive_group(required=False)
    cache_mux.add_argument(
        "--cve",
        metavar="CVE-YYYY-NNNNN",
        help="CVE identifier (e.g. CVE-2025-32713).",
        type=cve_type,
    )
    cache_mux.add_argument(
        "--month",
        metavar="YYYY-MMM",
        help="Patch Tuesday month (e.g. 2025-Jul).",
        type=month_type,
    )
    cached_p.add_argument(
        "--platform-ids",
        dest="platform_ids",
        metavar="ID1,ID2",
        type=lambda s: {x.strip() for x in str(s).split(",") if x.strip()},
        help="Comma-separated list of platform IDs.",
        default=set(),
    )

    # cve MODE
    cve_p = sub.add_parser("cve", help="Generate report for a single CVE.")
    cve_p.add_argument(
        "cve_id",
        metavar="CVE-YYYY-NNNNN",
        help="CVE identifier (e.g. CVE-2025-32713).",
        type=cve_type,
    )
    cve_p.add_argument(
        "--eval",
        action="store_true",
        help="Enable evaluation mode.",
    )

    # month MODE
    month_p = sub.add_parser("month", help="Generate Patch Tuesday batch report.")
    month_p.add_argument(
        "month",
        metavar="YYYY-MMM",
        help="Patch Tuesday month (e.g. 2025-Jul).",
        type=month_type,
    )

    flt = month_p.add_mutually_exclusive_group(required=False)
    flt.add_argument(
        "--platform-name",
        dest="platform_name",
        metavar="NAME",
        help="Substring filter for platform name.",
    )
    flt.add_argument(
        "--platform-ids",
        dest="platform_ids",
        metavar="ID1,ID2",
        type=lambda s: {x.strip() for x in str(s).split(",") if x.strip()},
        help="Comma-separated list of platform IDs.",
        default=set(),
    )

    month_p.add_argument(
        "--eval",
        action="store_true",
        help="Enable evaluation mode.",
    )

    return p


def print_report(cve, to_file=False, monthly_path: str = None):
    reports = VectorStore.reports.get(where={"cve": cve})
    if reports.get("ids"):
        if to_file:
            if monthly_path:
                save_to_file(
                    reports,
                    path=Path(__file__).resolve().parent / "reports" / monthly_path,
                )
            else:
                save_to_file(reports)
        else:
            for r, m in zip(reports.get("documents"), reports.get("metadatas")):
                console.info(f"{m}\n{r}")
    else:
        print("Not found")


def get_month_cve(args):
    platform_name = getattr(args, "platform_name", None)
    platform_ids = getattr(args, "platform_ids", set())

    if not (platform_name or platform_ids):
        if input("Filter by name? [y/N] ").lower().startswith("y"):
            platform_name = input("Platform name substring: ").strip()
        else:
            ids = input("Comma-separated ProductIDs: ").strip()
            platform_ids = {s.strip() for s in (ids or "").split(",") if s}

    df, name, ids = get_pt_cve_list_by_platform(
        month=args.month, targets=platform_ids, name=platform_name
    )
    console.info(f"List {args.month} CVEs for {name} - {ids}\n\n {print_cve_list(df)}")
    cve = df.get_column("CVE").to_list()

    return cve, name, ids, df


def get_cve_list(argv: list[str]) -> list[str]:
    args = build_parser().parse_args(argv)

    if args.mode == "get_cached_report":
        if args.cve:
            print_report(args.cve, to_file=True)
        elif args.month:
            cve, name, ids, _ = get_month_cve(args)
            for c in cve:
                os_name = "".join(x.replace(" ", "_") for x in (name or []))
                os_id = "".join(str(x) for x in (ids or []))
                print_report(
                    c,
                    to_file=True,
                    monthly_path=f"{args.month}.{os_name}.{os_id}".lower(),
                )

        return [], args

    if args.mode == "cve":
        cve = [args.cve_id]
    elif args.mode == "month":
        cve, *_ = get_month_cve(args)

        if (
            not input(
                "This operation may take long time. Do you want to continue? [y/N] "
            )
            .lower()
            .startswith("y")
        ):
            return [], args

    return cve, args
