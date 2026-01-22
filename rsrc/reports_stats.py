"""
Vulnerability Report Analysis Module

This module provides tools for indexing and analyzing vulnerability report files.
It extracts metadata from report files, computes quality metrics, and generates
comprehensive statistics for patch analysis.
"""

import polars as pl
import json
from pathlib import Path
from typing import Dict, Tuple
from dataclasses import dataclass


# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Quality thresholds and scoring parameters
DEFAULT_CONFIDENCE_THRESHOLD = 0.605  # Minimum confidence for high-quality filtering
DEFAULT_CHANGE_COUNT_THRESHOLD = 30  # Baseline for quality score calculation

# Display limits
TOP_REPORTS_LIMIT = 10
TOP_HOTSPOTS_LIMIT = 20

# Column groups for report display
REPORT_COLUMNS = [
    "cve",
    "file",
    "kb",
    "confidence",
    "change_count",
    "folder",
    "model_name",
]
QUALITY_REPORT_COLUMNS = REPORT_COLUMNS + ["quality_score"]

# Polars display configuration
pl.Config.set_tbl_cols(-1)
pl.Config.set_tbl_rows(20)


# =============================================================================
# TYPE DEFINITIONS
# =============================================================================


@dataclass
class QualityThresholds:
    """Quality thresholds for report analysis.
    
    confidence: Minimum confidence threshold for filtering high-quality reports
    change_count: Baseline value for quality score calculation (not used for filtering)
    """

    confidence: float = DEFAULT_CONFIDENCE_THRESHOLD
    change_count: int = DEFAULT_CHANGE_COUNT_THRESHOLD


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _calculate_quality_score(df: pl.DataFrame) -> pl.DataFrame:
    """
    Calculate quality score for reports using Scaled Inverse with Baseline formula.

    Quality score formula: confidence * (baseline / (baseline + change_count))
    where baseline = DEFAULT_CHANGE_COUNT_THRESHOLD (10)
    
    This formula ensures:
    - Higher confidence → higher score
    - Lower change_count → higher score
    - Scores are bounded to [0, 1]
    - Best possible score ≈ 0.909 (confidence=1.0, change_count=1)
    - Score gracefully decays as change_count increases

    Args:
        df: DataFrame with 'confidence' and 'change_count' columns

    Returns:
        DataFrame with added 'quality_score' column
    """
    baseline = DEFAULT_CHANGE_COUNT_THRESHOLD
    return df.with_columns(
        (
            pl.col("confidence") * (baseline / (baseline + pl.col("change_count")))
        ).alias("quality_score")
    )


def _compute_basic_stats(df: pl.DataFrame) -> Dict:
    """
    Compute basic statistical metrics.

    Args:
        df: Report DataFrame

    Returns:
        Dictionary with basic statistics
    """
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
    }


def _compute_high_quality_metrics(
    df: pl.DataFrame, thresholds: QualityThresholds
) -> Tuple[pl.DataFrame, Dict]:
    """
    Filter and analyze high-confidence reports.

    Filters reports based on confidence threshold only. The change_count
    is not used for filtering but contributes to quality score calculation.

    Args:
        df: Report DataFrame
        thresholds: Quality thresholds (only confidence is used for filtering)

    Returns:
        Tuple of (high_quality_df, metrics_dict)
    """
    high_quality_mask = pl.col("confidence") > thresholds.confidence
    high_quality_df = df.filter(high_quality_mask)

    metrics = {
        "high_quality_reports_count": len(high_quality_df),
        "high_quality_unique_cves": (
            high_quality_df["cve"].n_unique() if len(high_quality_df) > 0 else 0
        ),
    }

    return high_quality_df, metrics


def _compute_folder_analysis(
    df: pl.DataFrame, high_quality_df: pl.DataFrame
) -> Tuple[pl.DataFrame, pl.DataFrame]:
    """
    Analyze reports by folder with high-quality metrics.

    Args:
        df: Full report DataFrame
        high_quality_df: Filtered high-quality reports

    Returns:
        Tuple of (high_quality_by_folder, temporal_analysis)
    """
    # Total CVEs by folder
    total_cves_by_folder = df.group_by("folder").agg(
        [pl.col("cve").n_unique().alias("total_unique_cves")]
    )

    # High-quality CVEs by folder
    high_quality_cves_by_folder = high_quality_df.group_by("folder").agg(
        [
            pl.col("cve").n_unique().alias("high_quality_unique_cves"),
            pl.col("cve").count().alias("high_quality_reports"),
            pl.col("confidence").mean().alias("avg_confidence"),
            pl.col("change_count").mean().alias("avg_change_count"),
            pl.col("quality_score").mean().alias("avg_quality_score"),
        ]
    )

    # Combine results
    high_quality_by_folder = (
        total_cves_by_folder.join(high_quality_cves_by_folder, on="folder", how="left")
        .select(
            [
                "folder",
                pl.col("high_quality_unique_cves").fill_null(0),
                "total_unique_cves",
                pl.col("high_quality_reports").fill_null(0),
                "avg_confidence",
                "avg_change_count",
                "avg_quality_score",
            ]
        )
        .sort("folder")
    )

    # Temporal analysis
    temporal_analysis = (
        df.group_by("folder")
        .agg(
            [
                pl.col("cve").count().alias("total_reports"),
                pl.col("cve").n_unique().alias("unique_cves"),
                pl.col("confidence").mean().alias("avg_confidence"),
                pl.col("change_count").mean().alias("avg_change_count"),
                pl.col("quality_score").mean().alias("avg_quality_score"),
                pl.col("date").min().alias("earliest_date"),
                pl.col("date").max().alias("latest_date"),
            ]
        )
        .sort("folder")
    )

    return high_quality_by_folder, temporal_analysis


def _compute_kb_analysis(
    df: pl.DataFrame, thresholds: QualityThresholds
) -> Tuple[pl.DataFrame, pl.DataFrame]:
    """
    Analyze reports by KB (Knowledge Base patch).

    Args:
        df: Report DataFrame
        thresholds: Quality thresholds

    Returns:
        Tuple of (basic_kb_stats, kb_quality_assessment)
    """
    basic_stats = (
        df.group_by("kb")
        .agg(
            [
                pl.col("cve").count().alias("report_count"),
                pl.col("cve").n_unique().alias("unique_cves"),
                pl.col("confidence").mean().alias("avg_confidence"),
                pl.col("change_count").mean().alias("avg_change_count"),
                pl.col("quality_score").mean().alias("avg_quality_score"),
            ]
        )
        .sort("kb")
    )

    quality_assessment = (
        df.group_by("kb")
        .agg(
            [
                pl.col("cve").n_unique().alias("unique_cves"),
                pl.col("file").n_unique().alias("unique_files"),
                (
                    pl.col("cve").n_unique().cast(pl.Float64)
                    / pl.col("file").n_unique()
                ).alias("cve_per_file_ratio"),
                (pl.col("confidence") > thresholds.confidence)
                .sum()
                .alias("high_confidence_count"),
                pl.col("confidence").mean().alias("avg_confidence"),
            ]
        )
        .sort("high_confidence_count", descending=True)
    )

    return basic_stats, quality_assessment


def _compute_model_analysis(
    df: pl.DataFrame, thresholds: QualityThresholds
) -> Tuple[pl.DataFrame, pl.DataFrame]:
    """
    Analyze reports by AI model.

    Args:
        df: Report DataFrame
        thresholds: Quality thresholds

    Returns:
        Tuple of (basic_model_stats, model_quality_comparison)
    """
    model_df = df.filter(pl.col("model_name").is_not_null())

    if len(model_df) == 0:
        return pl.DataFrame(), None

    basic_stats = (
        model_df.group_by("model_name")
        .agg(
            [
                pl.col("cve").count().alias("report_count"),
                pl.col("confidence").mean().alias("avg_confidence"),
                pl.col("change_count").mean().alias("avg_change_count"),
            ]
        )
        .sort("model_name")
    )

    model_quality = (
        _calculate_quality_score(model_df)
        .group_by("model_name")
        .agg(
            [
                pl.len().alias("report_count"),
                pl.col("confidence").mean().alias("avg_confidence"),
                pl.col("change_count").mean().alias("avg_change_count"),
                pl.col("quality_score").mean().alias("avg_quality_score"),
                (pl.col("confidence") > thresholds.confidence)
                .sum()
                .alias("high_confidence_count"),
                (pl.col("change_count") < thresholds.change_count)
                .sum()
                .alias("low_complexity_count"),
            ]
        )
        .sort("avg_quality_score", descending=True)
    )

    return basic_stats, model_quality


def _compute_file_hotspots(df: pl.DataFrame) -> pl.DataFrame:
    """
    Identify most frequently patched files.

    Args:
        df: Report DataFrame with quality_score column

    Returns:
        DataFrame with file hotspot analysis including quality scores
    """
    return (
        df.group_by("file")
        .agg(
            [
                pl.col("cve").n_unique().alias("cve_count"),
                pl.col("cve").count().alias("total_patches"),
                pl.col("confidence").mean().alias("avg_confidence"),
                pl.col("change_count").mean().alias("avg_change_count"),
                pl.col("quality_score").mean().alias("avg_quality_score"),
            ]
        )
        .sort("cve_count", descending=True)
        .head(TOP_HOTSPOTS_LIMIT)
    )


def _compute_top_reports(df_with_quality: pl.DataFrame) -> Dict[str, pl.DataFrame]:
    """
    Extract top and bottom quality reports.

    Args:
        df_with_quality: DataFrame with quality_score column

    Returns:
        Dictionary with top/bottom reports by various metrics
    """
    return {
        "top_quality": df_with_quality.select(QUALITY_REPORT_COLUMNS)
        .sort("quality_score", descending=True)
        .head(TOP_REPORTS_LIMIT),
        "bottom_quality": df_with_quality.select(QUALITY_REPORT_COLUMNS)
        .sort("quality_score", descending=False)
        .head(TOP_REPORTS_LIMIT),
        "most_complex": df_with_quality.select(REPORT_COLUMNS)
        .sort("change_count", descending=True)
        .head(TOP_REPORTS_LIMIT),
        "highest_confidence": df_with_quality.select(REPORT_COLUMNS)
        .sort("confidence", descending=True)
        .head(TOP_REPORTS_LIMIT),
    }


# =============================================================================
# MAIN ANALYSIS FUNCTION
# =============================================================================


def analyze_reports(
    df: pl.DataFrame,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    change_count_threshold: int = DEFAULT_CHANGE_COUNT_THRESHOLD,
) -> Dict:
    """
    Analyze vulnerability reports and compute comprehensive statistics.

    Quality scoring uses the formula: confidence * (baseline / (baseline + change_count))
    where baseline = change_count_threshold (default 10). This ensures high confidence
    and low change counts produce higher quality scores.

    Args:
        df: DataFrame containing report metadata
        confidence_threshold: Minimum confidence for filtering high-quality reports
        change_count_threshold: Baseline for quality score calculation (not a filter)

    Returns:
        Dictionary containing analysis results with the following keys:
            - Basic stats: total_reports, unique_cves, avg_confidence, etc.
            - High quality: high_quality_reports_count, high_quality_by_folder
            - By dimension: by_kb, by_model, by_folder
            - Rankings: top_quality_reports, file_hotspots, etc.
    """
    thresholds = QualityThresholds(confidence_threshold, change_count_threshold)

    # Calculate quality scores
    df_with_quality = _calculate_quality_score(df)

    # Compute all analyses
    analysis = {}

    # Basic statistics
    analysis.update(_compute_basic_stats(df))
    analysis["avg_quality_score"] = df_with_quality["quality_score"].mean()

    # High-quality metrics
    high_quality_df, hq_metrics = _compute_high_quality_metrics(df_with_quality, thresholds)
    analysis.update(hq_metrics)

    # Folder analysis
    hq_by_folder, temporal = _compute_folder_analysis(df_with_quality, high_quality_df)
    analysis["high_quality_by_folder"] = hq_by_folder
    analysis["by_folder"] = temporal

    # KB analysis
    kb_stats, kb_quality = _compute_kb_analysis(df_with_quality, thresholds)
    analysis["by_kb"] = kb_stats
    analysis["kb_quality"] = kb_quality

    # Model analysis
    model_stats, model_quality = _compute_model_analysis(df_with_quality, thresholds)
    analysis["by_model"] = model_stats
    analysis["model_quality"] = model_quality

    # File hotspots (with quality scores)
    analysis["file_hotspots"] = _compute_file_hotspots(df_with_quality)

    # Top/bottom reports
    top_reports = _compute_top_reports(df_with_quality)
    analysis["top_quality_reports"] = top_reports["top_quality"]
    analysis["bottom_quality_reports"] = top_reports["bottom_quality"]
    analysis["most_complex_patches"] = top_reports["most_complex"]
    analysis["highest_confidence_reports"] = top_reports["highest_confidence"]

    return analysis


# =============================================================================
# INDEXING FUNCTION
# =============================================================================


def index_reports(reports_dir: str = "reports") -> pl.DataFrame:
    """
    Index all txt files in the reports directory and extract metadata.

    Reads the first line of each .txt file in the reports directory,
    parses it as JSON, and creates a unified DataFrame with all metadata.

    Args:
        reports_dir: Path to the reports directory

    Returns:
        DataFrame containing metadata from all report files with columns:
            - Original metadata: cve, kb, confidence, change_count, etc.
            - Added metadata: filepath, filename, folder
            - Date converted to datetime format

    Raises:
        ValueError: If reports directory doesn't exist or no valid files found
    """
    base_path = Path(reports_dir)

    if not base_path.exists():
        raise ValueError(f"Reports directory '{reports_dir}' does not exist")

    # Collect metadata from all txt files
    metadata_list = []
    errors = []
    all_keys = set()

    for txt_file in base_path.rglob("*.txt"):
        try:
            with open(txt_file, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()

            # Parse JSON (handle both formats)
            try:
                metadata = json.loads(first_line)
            except json.JSONDecodeError:
                import ast

                metadata = ast.literal_eval(first_line)

            all_keys.update(metadata.keys())

            # Add file path information
            metadata["filepath"] = str(txt_file)
            metadata["filename"] = txt_file.name
            metadata["folder"] = txt_file.parent.name

            metadata_list.append(metadata)

        except Exception as e:
            errors.append({"file": str(txt_file), "error": str(e)})

    # Log errors
    if errors:
        print(f"Warning: Failed to parse {len(errors)} files:")
        for err in errors[:5]:
            print(f"  - {err['file']}: {err['error']}")
        if len(errors) > 5:
            print(f"  ... and {len(errors) - 5} more")

    print(f"Found metadata keys: {sorted(all_keys)}")

    if not metadata_list:
        raise ValueError("No valid report files found")

    # Ensure all dictionaries have all keys
    for metadata in metadata_list:
        for key in all_keys:
            if key not in metadata:
                metadata[key] = None

    # Create DataFrame
    df = pl.DataFrame(metadata_list, infer_schema_length=None)

    # Cast to proper types
    schema_overrides = {}
    if "date" in df.columns:
        schema_overrides["date"] = pl.Float64
    if "confidence" in df.columns:
        schema_overrides["confidence"] = pl.Float64
    if "change_count" in df.columns:
        schema_overrides["change_count"] = pl.Int64

    if schema_overrides:
        df = df.cast(schema_overrides)

    # Convert date from Unix timestamp to datetime
    if "date" in df.columns:
        df = df.with_columns(pl.from_epoch(pl.col("date"), time_unit="s").alias("date"))

    print(f"Successfully indexed {len(df)} report files")
    print(f"Columns: {df.columns}")

    return df


# =============================================================================
# DISPLAY FUNCTION
# =============================================================================


def print_analysis_report(
    analysis: Dict,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    change_count_threshold: int = DEFAULT_CHANGE_COUNT_THRESHOLD,
) -> None:
    """
    Print formatted analysis report.

    Args:
        analysis: Analysis results dictionary from analyze_reports()
        confidence_threshold: Confidence threshold used for filtering
        change_count_threshold: Baseline used for quality score calculation
    """
    print("\n" + "=" * 80)
    print("VULNERABILITY REPORT ANALYSIS")
    print("=" * 80)

    # Overall Statistics
    print("\nOVERALL STATISTICS")
    print("-" * 80)
    print(f"Total Reports: {analysis['total_reports']}")
    print(f"Unique CVEs: {analysis['unique_cves']}")
    print(f"Unique KBs: {analysis['unique_kbs']}")
    print(f"Unique Files: {analysis['unique_files']}")

    # Quality Metrics
    print("\nQUALITY METRICS")
    print("-" * 80)
    print(f"Average Confidence: {analysis['avg_confidence']:.3f}")
    print(f"Median Confidence: {analysis['median_confidence']:.3f}")
    print(
        f"Confidence Range: {analysis['min_confidence']:.3f} - {analysis['max_confidence']:.3f}"
    )
    print(f"\nAverage Change Count: {analysis['avg_change_count']:.1f}")
    print(f"Median Change Count: {analysis['median_change_count']:.0f}")
    print(
        f"Change Count Range: {analysis['min_change_count']} - {analysis['max_change_count']}"
    )
    print(f"\nAverage Quality Score: {analysis['avg_quality_score']:.3f}")

    # High Confidence Reports
    print(
        f"\nHIGH CONFIDENCE REPORTS (confidence > {confidence_threshold})"
    )
    print("-" * 80)
    print(f"Quality Score Baseline (for scoring): {change_count_threshold}")
    print(f"Total High Confidence Reports: {analysis['high_quality_reports_count']}")
    print(f"Unique High Confidence CVEs: {analysis['high_quality_unique_cves']}")
    print("\nHigh Confidence CVEs by Folder:")
    print(analysis["high_quality_by_folder"])

    # Statistics by KB
    print("\nSTATISTICS BY KB")
    print("-" * 80)
    print(analysis["by_kb"])

    # Statistics by Model
    if len(analysis["by_model"]) > 0:
        print("\nSTATISTICS BY MODEL")
        print("-" * 80)
        print(analysis["by_model"])

    # Temporal Analysis
    print("\nTEMPORAL ANALYSIS (by Folder)")
    print("-" * 80)
    print(analysis["by_folder"])

    # Top Quality Reports
    print("\nTOP 10 HIGHEST QUALITY REPORTS")
    print("-" * 80)
    print(analysis["top_quality_reports"])

    # Most Complex Patches
    print("\nTOP 10 MOST COMPLEX PATCHES")
    print("-" * 80)
    print(analysis["most_complex_patches"])

    # Highest Confidence
    print("\nTOP 10 HIGHEST CONFIDENCE REPORTS")
    print("-" * 80)
    print(analysis["highest_confidence_reports"])

    # Bottom Quality
    print("\nBOTTOM 10 LOWEST QUALITY REPORTS")
    print("-" * 80)
    print(analysis["bottom_quality_reports"])

    # File Hotspots
    print("\nTOP 20 FILE HOTSPOTS (Most Frequently Patched)")
    print("-" * 80)
    print(analysis["file_hotspots"])

    # Model Quality Comparison
    if analysis["model_quality"] is not None:
        print("\nMODEL QUALITY COMPARISON")
        print("-" * 80)
        print(analysis["model_quality"])

    # KB Quality Assessment
    print("\nKB QUALITY ASSESSMENT")
    print("-" * 80)
    print(analysis["kb_quality"])


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Index all reports
    df = index_reports()
    print(f"\nDataFrame shape: {df.shape}")
    print(f"\nFirst few rows:")
    print(df.head())

    # Run analysis
    analysis = analyze_reports(df)

    # Print results
    print_analysis_report(analysis)
