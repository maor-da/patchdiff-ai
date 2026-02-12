#!/usr/bin/env python3
"""
Script to add CVSS scores to report file metadata headers.
Reads CVSS data from rsrc/.eval_cve_df and updates all report files in reports/ directory.
"""

import json
from pathlib import Path
import polars as pl
from typing import Dict, Optional


def load_cvss_data() -> Dict[str, Optional[float]]:
    """
    Load CVSS data from the serialized DataFrame and create a lookup dictionary.
    
    Returns:
        Dictionary mapping CVE ID to CVSS score (float or None)
    """
    cache_path = Path("rsrc/.eval_cve_df")
    
    if not cache_path.exists():
        raise FileNotFoundError(f"CVSS data file not found: {cache_path}")
    
    # Deserialize the Polars DataFrame
    cve_df = pl.DataFrame.deserialize(cache_path)
    
    # Create CVE -> CVSS lookup dictionary
    cvss_lookup = {}
    for row in cve_df.iter_rows(named=True):
        cve = row['CVE']
        cvss = row['CVSS']
        cvss_lookup[cve] = cvss
    
    print(f"[+] Loaded CVSS data for {len(cvss_lookup)} CVEs")
    print(f"    - CVEs with scores: {sum(1 for v in cvss_lookup.values() if v is not None)}")
    print(f"    - CVEs without scores: {sum(1 for v in cvss_lookup.values() if v is None)}")
    
    return cvss_lookup


def update_report_metadata(txt_file: Path, cvss_lookup: Dict[str, Optional[float]]) -> bool:
    """
    Update a single report file with CVSS data.
    
    Args:
        txt_file: Path to the report file
        cvss_lookup: Dictionary mapping CVE to CVSS score
        
    Returns:
        True if update was successful, False otherwise
    """
    try:
        # Read the entire file
        with open(txt_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        if not lines:
            print(f"    [!] Empty file: {txt_file}")
            return False
        
        # Parse the first line (JSON metadata)
        first_line = lines[0].strip()
        try:
            metadata = json.loads(first_line)
        except json.JSONDecodeError:
            # Try ast.literal_eval as fallback
            import ast
            metadata = ast.literal_eval(first_line)
        
        # Get CVE from metadata
        cve = metadata.get('cve')
        if not cve:
            print(f"    [!] No CVE found in metadata: {txt_file}")
            return False
        
        # Check if cvss already exists
        if 'cvss' in metadata:
            # print(f"    [~] CVSS already exists: {cve} in {txt_file.name}")
            return False
        
        # Look up CVSS score
        cvss = cvss_lookup.get(cve)
        
        # Add CVSS to metadata
        metadata['cvss'] = cvss
        
        # Write updated file
        with open(txt_file, "w", encoding="utf-8") as f:
            # Write updated metadata as first line
            f.write(json.dumps(metadata) + "\n")
            # Write rest of the file unchanged
            f.writelines(lines[1:])
        
        return True
        
    except Exception as e:
        print(f"    [!] Error processing {txt_file}: {e}")
        return False


def process_reports(reports_dir: str = "reports") -> None:
    """
    Process all report files and add CVSS data to their metadata.
    
    Args:
        reports_dir: Path to the reports directory
    """
    base_path = Path(reports_dir)
    
    if not base_path.exists():
        raise ValueError(f"Reports directory '{reports_dir}' does not exist")
    
    print(f"\n[*] Processing reports in: {base_path}")
    
    # Load CVSS data
    cvss_lookup = load_cvss_data()
    
    # Find all report files
    report_files = list(base_path.rglob("*.txt"))
    print(f"\n[*] Found {len(report_files)} report files")
    
    # Statistics
    stats = {
        'total': len(report_files),
        'updated': 0,
        'skipped': 0,
        'errors': 0,
        'cvss_found': 0,
        'cvss_missing': 0
    }
    
    # Process each file
    print("\n[*] Updating report files...")
    for i, txt_file in enumerate(report_files, 1):
        if i % 100 == 0 or i == 1:
            print(f"    Processing file {i}/{len(report_files)}...")
        
        try:
            # Read metadata to check CVE and CVSS status
            with open(txt_file, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
            
            try:
                metadata = json.loads(first_line)
            except json.JSONDecodeError:
                import ast
                metadata = ast.literal_eval(first_line)
            
            cve = metadata.get('cve')
            if cve:
                cvss = cvss_lookup.get(cve)
                if cvss is not None:
                    stats['cvss_found'] += 1
                else:
                    stats['cvss_missing'] += 1
            
            # Update the file
            if update_report_metadata(txt_file, cvss_lookup):
                stats['updated'] += 1
            else:
                stats['skipped'] += 1
                
        except Exception as e:
            print(f"    [!] Error with {txt_file}: {e}")
            stats['errors'] += 1
    
    # Print summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total files:           {stats['total']}")
    print(f"Files updated:         {stats['updated']}")
    print(f"Files skipped:         {stats['skipped']}")
    print(f"Files with errors:     {stats['errors']}")
    print(f"\nCVSS Statistics:")
    print(f"CVEs with CVSS:        {stats['cvss_found']}")
    print(f"CVEs without CVSS:     {stats['cvss_missing']}")
    print("=" * 70)


if __name__ == "__main__":
    process_reports()
