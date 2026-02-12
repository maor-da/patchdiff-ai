"""
Vulnerability Report Analysis Module

Indexes vulnerability report files, computes quality metrics, and generates statistics for patch analysis.
"""

import polars as pl
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

DEFAULT_CONFIDENCE_THRESHOLD = 0.6
DEFAULT_CHANGE_COUNT_THRESHOLD = 50
DEFAULT_QUALITY_SCORE_THRESHOLD = 0.4

TOP_REPORTS_LIMIT = 20
TOP_HOTSPOTS_LIMIT = 20

# Models to exclude from analysis
EXCLUDED_MODELS = [
    "azure.o3",
]

REPORT_COLUMNS = ["cve", "file", "kb", "cvss", "confidence", "change_count", "folder", "model_name"]
QUALITY_REPORT_COLUMNS = REPORT_COLUMNS + ["quality_score"]

pl.Config.set_tbl_cols(-1)
pl.Config.set_tbl_rows(20)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _get_unique_cves_with_cvss(df: pl.DataFrame) -> pl.DataFrame:
    """Deduplicate by CVE and filter for non-null CVSS values."""
    return df.unique(subset=["cve"], keep="first").filter(pl.col("cvss").is_not_null())


def _calculate_quality_score(df: pl.DataFrame, baseline: int = DEFAULT_CHANGE_COUNT_THRESHOLD) -> pl.DataFrame:
    """Add quality_score column: confidence * (baseline / (baseline + change_count))"""
    return df.with_columns(
        (pl.col("confidence") * (baseline / (baseline + pl.col("change_count")))).alias("quality_score")
    )


def _compute_basic_stats(df: pl.DataFrame) -> Dict:
    """Compute basic statistics including CVSS metrics."""
    cvss_df = _get_unique_cves_with_cvss(df)
    has_cvss = len(cvss_df) > 0
    
    return {
        "total_reports": len(df),
        "unique_cves": df["cve"].n_unique(),
        "unique_kbs": df["kb"].n_unique(),
        "unique_files": df["file"].n_unique(),
        "avg_confidence": df["confidence"].mean(),
        "median_confidence": df["confidence"].median(),
        "min_confidence": df["confidence"].min(),
        "max_confidence": df["confidence"].max(),
        "avg_change_count": df["change_count"].mean(),
        "median_change_count": df["change_count"].median(),
        "min_change_count": df["change_count"].min(),
        "max_change_count": df["change_count"].max(),
        "avg_cvss": cvss_df["cvss"].mean() if has_cvss else None,
        "median_cvss": cvss_df["cvss"].median() if has_cvss else None,
        "min_cvss": cvss_df["cvss"].min() if has_cvss else None,
        "max_cvss": cvss_df["cvss"].max() if has_cvss else None,
        "high_cvss_count": (cvss_df["cvss"] >= 7.0).sum() if has_cvss else 0,
        "critical_cvss_count": (cvss_df["cvss"] >= 9.0).sum() if has_cvss else 0,
        "cvss_available_count": len(cvss_df),
    }


def _compute_quality_distribution(df: pl.DataFrame) -> Dict:
    """Compute quality score quartile distribution."""
    qs = df["quality_score"]
    return {
        "quality_q25": qs.quantile(0.25),
        "quality_q50": qs.quantile(0.50),
        "quality_q75": qs.quantile(0.75),
    }


def _compute_correlations(df: pl.DataFrame) -> Dict:
    """Compute correlation metrics between other metrics and Confidence."""
    conf_df = df.filter(pl.col("confidence").is_not_null())
    if len(conf_df) < 2:
        return {
            "cvss_confidence_corr": None,
            "change_count_confidence_corr": None,
            "quality_score_confidence_corr": None,
        }
    
    cvss_corr = conf_df.filter(pl.col("cvss").is_not_null()).select(pl.corr("cvss", "confidence")).item() if len(conf_df.filter(pl.col("cvss").is_not_null())) >= 2 else None
    change_corr = conf_df.select(pl.corr("change_count", "confidence")).item()
    quality_corr = conf_df.select(pl.corr("quality_score", "confidence")).item()
    
    return {
        "cvss_confidence_corr": cvss_corr,
        "change_count_confidence_corr": change_corr,
        "quality_score_confidence_corr": quality_corr,
    }


def _compute_efficiency_metrics(df: pl.DataFrame) -> Dict:
    """Compute patch efficiency metrics."""
    unique_cves = df["cve"].n_unique()
    unique_files = df["file"].n_unique()
    
    # Files per CVE (scattered patches)
    files_per_cve_df = df.group_by("cve").agg(pl.col("file").n_unique().alias("file_count"))
    
    return {
        "cves_per_file": unique_cves / unique_files if unique_files > 0 else 0,
        "files_per_cve_avg": files_per_cve_df["file_count"].mean(),
        "files_per_cve_median": files_per_cve_df["file_count"].median(),
        "files_per_cve_max": files_per_cve_df["file_count"].max(),
    }


def _compute_high_quality_metrics(df: pl.DataFrame, conf_thresh: float, qual_thresh: float) -> Tuple[pl.DataFrame, Dict]:
    """Filter and count high-quality reports."""
    hq_df = df.filter((pl.col("confidence") > conf_thresh) & (pl.col("quality_score") > qual_thresh))
    return hq_df, {
        "high_quality_reports_count": len(hq_df),
        "high_quality_unique_cves": hq_df["cve"].n_unique() if len(hq_df) > 0 else 0,
    }


def _compute_group_stats(df: pl.DataFrame, group_col: str, conf_thresh: float, change_thresh: int) -> Tuple[pl.DataFrame, pl.DataFrame]:
    """Generic aggregation by group column (kb/model/folder)."""
    filtered_df = df.filter(pl.col(group_col).is_not_null())
    
    if len(filtered_df) == 0:
        return pl.DataFrame(), pl.DataFrame()
    
    basic = filtered_df.group_by(group_col).agg([
        pl.col("cve").count().alias("report_count"),
        pl.col("cve").n_unique().alias("unique_cves"),
        pl.col("confidence").mean().alias("avg_confidence"),
        pl.col("change_count").mean().alias("avg_change_count"),
        pl.col("quality_score").mean().alias("avg_quality_score"),
        pl.col("cvss").mean().alias("avg_cvss"),
    ]).sort(group_col)
    
    quality = filtered_df.group_by(group_col).agg([
        pl.col("cve").n_unique().alias("unique_cves"),
        pl.col("file").n_unique().alias("unique_files"),
        (pl.col("cve").n_unique().cast(pl.Float64) / pl.col("file").n_unique()).alias("cve_per_file_ratio"),
        (pl.col("confidence") > conf_thresh).sum().alias("high_confidence_count"),
        (pl.col("change_count") < change_thresh).sum().alias("low_complexity_count"),
        pl.col("confidence").mean().alias("avg_confidence"),
        pl.col("quality_score").mean().alias("avg_quality_score"),
        pl.col("cvss").mean().alias("avg_cvss"),
    ]).sort("avg_quality_score", descending=True)
    
    return basic, quality


def _compute_folder_analysis(df: pl.DataFrame, hq_df: pl.DataFrame) -> pl.DataFrame:
    """Analyze high-quality reports by folder."""
    total = df.group_by("folder").agg([pl.col("cve").n_unique().alias("total_unique_cves")])
    hq = hq_df.group_by("folder").agg([
        pl.col("cve").n_unique().alias("high_quality_unique_cves"),
        pl.col("cve").count().alias("high_quality_reports"),
        pl.col("confidence").mean().alias("avg_confidence"),
        pl.col("change_count").mean().alias("avg_change_count"),
        pl.col("quality_score").mean().alias("avg_quality_score"),
        pl.col("cvss").mean().alias("avg_cvss"),
    ])
    
    return total.join(hq, on="folder", how="left").select([
        "folder",
        pl.col("high_quality_unique_cves").fill_null(0),
        "total_unique_cves",
        pl.col("high_quality_reports").fill_null(0),
        "avg_confidence",
        "avg_change_count",
        "avg_quality_score",
        "avg_cvss",
    ]).sort("folder")


def _compute_temporal_analysis(df: pl.DataFrame) -> pl.DataFrame:
    """Temporal analysis by folder."""
    return df.group_by("folder").agg([
        pl.col("cve").count().alias("total_reports"),
        pl.col("cve").n_unique().alias("unique_cves"),
        pl.col("confidence").mean().alias("avg_confidence"),
        pl.col("change_count").mean().alias("avg_change_count"),
        pl.col("quality_score").mean().alias("avg_quality_score"),
        pl.col("cvss").mean().alias("avg_cvss"),
        pl.col("date").min().alias("earliest_date"),
        pl.col("date").max().alias("latest_date"),
    ]).sort("folder")


def _compute_file_hotspots(df: pl.DataFrame) -> pl.DataFrame:
    """Identify most frequently patched files."""
    return df.group_by("file").agg([
        pl.col("cve").n_unique().alias("cve_count"),
        pl.col("cve").count().alias("total_patches"),
        pl.col("confidence").mean().alias("avg_confidence"),
        pl.col("change_count").mean().alias("avg_change_count"),
        pl.col("quality_score").mean().alias("avg_quality_score"),
        pl.col("cvss").mean().alias("avg_cvss"),
    ]).sort("cve_count", descending=True).head(TOP_HOTSPOTS_LIMIT)


def _compute_file_kb_cve_concentration(df: pl.DataFrame) -> pl.DataFrame:
    """Identify files with most CVEs patched in a single KB update."""
    return df.group_by(["file", "kb"]).agg([
        pl.col("cve").n_unique().alias("cve_count"),
        pl.col("cve").unique().sort().alias("cves"),
        pl.col("confidence").mean().alias("avg_confidence"),
        pl.col("change_count").mean().alias("avg_change_count"),
        pl.col("quality_score").mean().alias("avg_quality_score"),
        pl.col("cvss").mean().alias("avg_cvss"),
    ]).sort("cve_count", descending=True).head(TOP_HOTSPOTS_LIMIT)


def _compute_cvss_severity_distribution(df: pl.DataFrame) -> pl.DataFrame:
    """Compute CVSS severity distribution."""
    cvss_df = _get_unique_cves_with_cvss(df)
    
    if len(cvss_df) == 0:
        return pl.DataFrame({
            "severity": ["Low", "Medium", "High", "Critical"],
            "count": [0, 0, 0, 0],
            "percentage": [0.0, 0.0, 0.0, 0.0]
        })
    
    total = len(cvss_df)
    return pl.DataFrame({
        "severity": ["Low (0.0-3.9)", "Medium (4.0-6.9)", "High (7.0-8.9)", "Critical (9.0-10.0)"],
        "count": [
            ((cvss_df["cvss"] >= 0.0) & (cvss_df["cvss"] < 4.0)).sum(),
            ((cvss_df["cvss"] >= 4.0) & (cvss_df["cvss"] < 7.0)).sum(),
            ((cvss_df["cvss"] >= 7.0) & (cvss_df["cvss"] < 9.0)).sum(),
            (cvss_df["cvss"] >= 9.0).sum(),
        ],
        "percentage": [
            (((cvss_df["cvss"] >= 0.0) & (cvss_df["cvss"] < 4.0)).sum() / total * 100),
            (((cvss_df["cvss"] >= 4.0) & (cvss_df["cvss"] < 7.0)).sum() / total * 100),
            (((cvss_df["cvss"] >= 7.0) & (cvss_df["cvss"] < 9.0)).sum() / total * 100),
            ((cvss_df["cvss"] >= 9.0).sum() / total * 100),
        ]
    })


def _compute_top_reports(df: pl.DataFrame) -> Dict[str, pl.DataFrame]:
    """Extract top/bottom quality reports and rankings."""
    rankings = {
        "top_quality": (QUALITY_REPORT_COLUMNS, "quality_score", True, None),
        "bottom_quality": (QUALITY_REPORT_COLUMNS, "quality_score", False, None),
        "most_complex": (REPORT_COLUMNS, "change_count", True, None),
        "highest_confidence": (REPORT_COLUMNS, "confidence", True, None),
        "highest_cvss": (REPORT_COLUMNS, "cvss", True, pl.col("cvss").is_not_null()),
        "critical_severity": (REPORT_COLUMNS, "cvss", True, pl.col("cvss") >= 9.0),
    }
    
    results = {}
    for name, (cols, sort_col, descending, filter_expr) in rankings.items():
        data = df.filter(filter_expr) if filter_expr is not None else df
        ranked = data.select(cols).sort([sort_col, "cve"], descending=[descending, False]).unique(
            subset=["cve"], keep="first", maintain_order=True
        )
        results[name] = ranked #if name == "critical_severity" else ranked.head(TOP_REPORTS_LIMIT)
    
    return results


# =============================================================================
# MAIN ANALYSIS FUNCTION
# =============================================================================


def analyze_reports(
    df: pl.DataFrame,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    change_count_threshold: int = DEFAULT_CHANGE_COUNT_THRESHOLD,
    quality_score_threshold: float = DEFAULT_QUALITY_SCORE_THRESHOLD,
) -> Dict:
    """
    Analyze vulnerability reports and compute comprehensive statistics.

    Args:
        df: DataFrame with report metadata
        confidence_threshold: Min confidence for high-quality filtering
        change_count_threshold: Baseline for quality score calculation
        quality_score_threshold: Min quality score for high-quality filtering

    Returns:
        Dictionary with analysis results
    """
    df_with_quality = _calculate_quality_score(df, change_count_threshold)
    
    analysis = _compute_basic_stats(df)
    analysis["avg_quality_score"] = df_with_quality["quality_score"].mean()
    analysis.update(_compute_quality_distribution(df_with_quality))
    analysis.update(_compute_correlations(df_with_quality))
    analysis.update(_compute_efficiency_metrics(df_with_quality))
    
    hq_df, hq_metrics = _compute_high_quality_metrics(df_with_quality, confidence_threshold, quality_score_threshold)
    analysis.update(hq_metrics)
    
    analysis["high_quality_by_folder"] = _compute_folder_analysis(df_with_quality, hq_df)
    analysis["by_folder"] = _compute_temporal_analysis(df_with_quality)
    
    kb_stats, kb_quality = _compute_group_stats(df_with_quality, "kb", confidence_threshold, change_count_threshold)
    analysis["by_kb"] = kb_stats
    analysis["kb_quality"] = kb_quality
    
    model_stats, model_quality = _compute_group_stats(df_with_quality, "model_name", confidence_threshold, change_count_threshold)
    analysis["by_model"] = model_stats
    analysis["model_quality"] = model_quality
    
    analysis["file_hotspots"] = _compute_file_hotspots(df_with_quality)
    analysis["file_kb_cve_concentration"] = _compute_file_kb_cve_concentration(df_with_quality)
    analysis["cvss_severity_distribution"] = _compute_cvss_severity_distribution(df_with_quality)
    
    top_reports = _compute_top_reports(df_with_quality)
    analysis.update({
        "top_quality_reports": top_reports["top_quality"],
        "bottom_quality_reports": top_reports["bottom_quality"],
        "most_complex_patches": top_reports["most_complex"],
        "highest_confidence_reports": top_reports["highest_confidence"],
        "highest_cvss_reports": top_reports["highest_cvss"],
        "critical_severity_reports": top_reports["critical_severity"],
    })
    
    return analysis


# =============================================================================
# INDEXING FUNCTION
# =============================================================================


def index_reports(reports_dir: str = "reports") -> pl.DataFrame:
    """
    Index all txt files in reports directory and extract metadata.

    Args:
        reports_dir: Path to reports directory

    Returns:
        DataFrame with report metadata

    Raises:
        ValueError: If directory doesn't exist or no valid files found
    """
    base_path = Path(reports_dir)
    if not base_path.exists():
        raise ValueError(f"Reports directory '{reports_dir}' does not exist")

    metadata_list = []
    errors = []
    all_keys = set()

    for txt_file in base_path.rglob("*.txt"):
        try:
            with open(txt_file, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()

            try:
                metadata = json.loads(first_line)
            except json.JSONDecodeError:
                import ast
                metadata = ast.literal_eval(first_line)

            # Skip reports from excluded models
            if metadata.get("model_name") in EXCLUDED_MODELS:
                continue

            all_keys.update(metadata.keys())
            metadata["filepath"] = str(txt_file)
            metadata["filename"] = txt_file.name
            metadata["folder"] = txt_file.parent.name
            metadata_list.append(metadata)

        except Exception as e:
            errors.append({"file": str(txt_file), "error": str(e)})

    if errors:
        print(f"Warning: Failed to parse {len(errors)} files:")
        for err in errors[:5]:
            print(f"  - {err['file']}: {err['error']}")
        if len(errors) > 5:
            print(f"  ... and {len(errors) - 5} more")

    print(f"Found metadata keys: {sorted(all_keys)}")
    
    if EXCLUDED_MODELS:
        print(f"Excluded models from indexing: {', '.join(EXCLUDED_MODELS)}")

    if not metadata_list:
        raise ValueError("No valid report files found")

    for metadata in metadata_list:
        for key in all_keys:
            if key not in metadata:
                metadata[key] = None

    df = pl.DataFrame(metadata_list, infer_schema_length=None)

    schema_overrides = {}
    if "date" in df.columns:
        schema_overrides["date"] = pl.Float64
    if "confidence" in df.columns:
        schema_overrides["confidence"] = pl.Float64
    if "change_count" in df.columns:
        schema_overrides["change_count"] = pl.Int64

    if schema_overrides:
        df = df.cast(schema_overrides)

    if "date" in df.columns:
        df = df.with_columns(pl.from_epoch(pl.col("date"), time_unit="s").alias("date"))

    print(f"Successfully indexed {len(df)} report files")
    print(f"Columns: {df.columns}")

    return df


# =============================================================================
# DISPLAY FUNCTION
# =============================================================================


def _print_section(title: str, width: int = 100):
    """Print section header."""
    print(f"\n{'=' * width}")
    print(f"{title:^{width}}")
    print('=' * width)


def _print_subsection(title: str, width: int = 100):
    """Print subsection header."""
    print(f"\n{title}")
    print('-' * width)


def _format_percentage(value: float, total: float) -> str:
    """Format value as percentage of total."""
    return f"{value}/{total} ({value/total*100:.1f}%)" if total > 0 else "N/A"


def print_analysis_report(
    analysis: Dict,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    change_count_threshold: int = DEFAULT_CHANGE_COUNT_THRESHOLD,
    quality_score_threshold: float = DEFAULT_QUALITY_SCORE_THRESHOLD,
) -> None:
    """
    Print formatted analysis report.

    Args:
        analysis: Analysis results from analyze_reports()
        confidence_threshold: Confidence threshold used
        change_count_threshold: Baseline for quality calculation
        quality_score_threshold: Quality score threshold used
    """
    W = 100
    
    _print_section("VULNERABILITY REPORT ANALYSIS", W)
    
    # Executive Summary
    _print_subsection("EXECUTIVE SUMMARY", W)
    print(f"{'┌' + '─' * (W-2) + '┐'}")
    print(f"│ {'Reports:':<30} {analysis['total_reports']:>10}   {'Unique CVEs:':<30} {analysis['unique_cves']:>10} │")
    print(f"│ {'Unique KBs:':<30} {analysis['unique_kbs']:>10}   {'Unique Files:':<30} {analysis['unique_files']:>10} │")
    print(f"│ {'High Quality CVEs:':<30} {analysis['high_quality_unique_cves']:>10}   {'Coverage:':<30} {_format_percentage(analysis['high_quality_unique_cves'], analysis['unique_cves']):>10} │")
    if analysis.get('avg_cvss'):
        print(f"│ {'Avg CVSS:':<30} {analysis['avg_cvss']:>10.2f}   {'Critical (≥9.0):':<30} {analysis['critical_cvss_count']:>10} │")
    print(f"└{'─' * (W-2)}┘")
    
    # Quality Metrics
    _print_subsection("QUALITY METRICS", W)
    print(f"Confidence:      Avg={analysis['avg_confidence']:.3f}  Med={analysis['median_confidence']:.3f}  "
          f"Range=[{analysis['min_confidence']:.3f}, {analysis['max_confidence']:.3f}]")
    print(f"Change Count:    Avg={analysis['avg_change_count']:.1f}  Med={analysis['median_change_count']:.0f}  "
          f"Range=[{analysis['min_change_count']}, {analysis['max_change_count']}]")
    print(f"Quality Score:   Avg={analysis['avg_quality_score']:.3f}  "
          f"Q25={analysis['quality_q25']:.3f}  Q50={analysis['quality_q50']:.3f}  Q75={analysis['quality_q75']:.3f}")
    
    # Severity Analysis
    if analysis.get('avg_cvss') is not None:
        _print_subsection("SEVERITY ANALYSIS (CVSS)", W)
        print(f"CVSS Statistics: Avg={analysis['avg_cvss']:.2f}  Med={analysis['median_cvss']:.2f}  "
              f"Range=[{analysis['min_cvss']:.1f}, {analysis['max_cvss']:.1f}]")
        print(f"Coverage:        {_format_percentage(analysis['cvss_available_count'], analysis['unique_cves'])} CVEs have CVSS data")
        print(f"High Severity:   {analysis['high_cvss_count']} CVEs (≥7.0)")
        print(f"Critical:        {analysis['critical_cvss_count']} CVEs (≥9.0)")
        print("\nSeverity Distribution:")
        print(analysis["cvss_severity_distribution"])
    
    # Insights & Correlations
    _print_subsection("INSIGHTS & CORRELATIONS", W)
    if analysis.get('cvss_confidence_corr') is not None:
        print(f"Correlation with Confidence:")
        print(f"  CVSS:             {analysis['cvss_confidence_corr']:>6.3f}")
        print(f"  Change Count:     {analysis['change_count_confidence_corr']:>6.3f}")
        print(f"  Quality Score:    {analysis['quality_score_confidence_corr']:>6.3f}")
    elif analysis.get('change_count_confidence_corr') is not None:
        print(f"Correlation with Confidence:")
        if analysis.get('cvss_confidence_corr') is not None:
            print(f"  CVSS:             {analysis['cvss_confidence_corr']:>6.3f}")
        print(f"  Change Count:     {analysis['change_count_confidence_corr']:>6.3f}")
        print(f"  Quality Score:    {analysis['quality_score_confidence_corr']:>6.3f}")
    
    print(f"\nPatch Efficiency:")
    print(f"  CVEs per File:           {analysis['cves_per_file']:.2f}")
    print(f"  Files per CVE (avg):     {analysis['files_per_cve_avg']:.2f}")
    print(f"  Files per CVE (median):  {analysis['files_per_cve_median']:.0f}")
    print(f"  Files per CVE (max):     {analysis['files_per_cve_max']:.0f}")
    
    # High Quality Reports
    _print_subsection(f"HIGH QUALITY REPORTS (confidence>{confidence_threshold} AND quality_score>{quality_score_threshold})", W)
    print(f"Total High Quality Reports: {analysis['high_quality_reports_count']}")
    print(f"Unique High Quality CVEs:   {analysis['high_quality_unique_cves']}")
    print(f"\nHigh Quality CVEs by Folder:")
    print(analysis["high_quality_by_folder"])
    
    # Dimensional Analysis
    _print_subsection("DIMENSIONAL ANALYSIS", W)
    print("\nBy Folder (Temporal):")
    print(analysis["by_folder"])
    
    print("\nBy KB:")
    print(analysis["by_kb"])
    
    if len(analysis["by_model"]) > 0:
        print("\nBy Model:")
        print(analysis["by_model"])
    
    # Rankings
    _print_subsection("TOP QUALITY REPORTS", W)
    print(f"Top {TOP_REPORTS_LIMIT} Highest Quality CVEs:")
    print(analysis["top_quality_reports"])
    
    if len(analysis["highest_cvss_reports"]) > 0:
        print(f"\nTop {TOP_REPORTS_LIMIT} Highest CVSS CVEs:")
        print(analysis["highest_cvss_reports"])
    
    if len(analysis["critical_severity_reports"]) > 0:
        print(f"\nCritical Severity CVEs (CVSS ≥ 9.0) - Total: {len(analysis['critical_severity_reports'])}")
        print(analysis["critical_severity_reports"])
    
    print(f"\nTop {TOP_REPORTS_LIMIT} Most Complex CVEs:")
    print(analysis["most_complex_patches"])
    
    print(f"\nTop {TOP_REPORTS_LIMIT} Highest Confidence CVEs:")
    print(analysis["highest_confidence_reports"])
    
    print(f"\nBottom {TOP_REPORTS_LIMIT} Lowest Quality CVEs:")
    print(analysis["bottom_quality_reports"])
    
    _print_subsection("FILE HOTSPOTS", W)
    print("Top 20 Most Frequently Patched Files:")
    print(analysis["file_hotspots"])
    
    print("\nTop 20 Files with Most CVEs per KB (Single Update Concentration):")
    print(analysis["file_kb_cve_concentration"])
    
    # Detailed Quality Assessments
    _print_subsection("QUALITY ASSESSMENTS", W)
    if analysis["model_quality"] is not None and len(analysis["model_quality"]) > 0:
        print("Model Quality Comparison:")
        print(analysis["model_quality"])
    
    print("\nKB Quality Assessment:")
    print(analysis["kb_quality"])


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    df = index_reports()
    print(f"\nDataFrame shape: {df.shape}")
    print(f"\nFirst few rows:")
    print(df.head())

    analysis = analyze_reports(df)
    print_analysis_report(analysis)
