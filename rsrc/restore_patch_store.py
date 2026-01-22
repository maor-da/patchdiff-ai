#!/usr/bin/env python3
"""
Restore Patch Store Database

This script rebuilds the corrupted db/.patch_store_df by:
1. Loading metadata from _temp/extracted_*/report.cache files
2. Scanning db/patch_store/ directory for stored patch files
3. Matching files to their metadata and computing hashes
4. Creating a new patch store DataFrame

SAFETY: This script will NOT modify any files without explicit user confirmation.
"""

import sys
from pathlib import Path
from typing import Optional
import polars as pl

# Add parent directory to path to import project modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from common import PatchStoreEntry, console, logger, EXECUTABLE_EXTENSIONS, safe_serialize
from patch_analysis.files_collection import get_file_hash, get_pe_ms_id, version_tuple


def load_kb_caches(temp_dir: Path) -> Optional[pl.DataFrame]:
    """
    Load all report.cache files from extracted KB directories.
    
    Args:
        temp_dir: Path to _temp directory containing extracted KB folders
        
    Returns:
        Combined DataFrame with all KB metadata, or None if no caches found
    """
    console.info(f"[*] Searching for KB cache files in: {temp_dir}")
    
    cache_files = list(temp_dir.glob("extracted_*/report.cache"))
    
    if not cache_files:
        console.warning(f"[-] No report.cache files found in {temp_dir}")
        return None
    
    console.info(f"[+] Found {len(cache_files)} KB cache files")
    
    dataframes = []
    for cache_file in sorted(cache_files):
        try:
            df = pl.DataFrame.deserialize(cache_file)
            kb_name = cache_file.parent.name.replace("extracted_", "").split("-")[1].upper()
            console.info(f"    {kb_name}: {len(df)} entries")
            dataframes.append(df)
        except Exception as e:
            console.warning(f"[-] Failed to load {cache_file.name}: {e}")
            logger.exception(f"Error loading cache file {cache_file}")
    
    if not dataframes:
        console.warning("[-] No cache files could be loaded")
        return None
    
    # Combine all DataFrames
    combined_df = pl.concat(dataframes, how="vertical_relaxed")
    console.info(f"[+] Loaded {len(combined_df)} total metadata entries from {len(dataframes)} KBs")
    
    return combined_df


def parse_patch_store_path(file_path: Path, patch_store_root: Path) -> Optional[dict]:
    """
    Parse metadata from a patch_store file path.
    
    Expected structure: db/patch_store/{arch}_{package}_{pubkey}/{filename}/{kb_or_version}/{filename}
    
    Args:
        file_path: Full path to a file in patch_store
        patch_store_root: Root path of patch_store directory
        
    Returns:
        Dict with parsed metadata or None if path doesn't match expected structure
    """
    try:
        relative = file_path.relative_to(patch_store_root)
        parts = relative.parts
        
        if len(parts) < 3:
            return None
        
        # Parse {arch}_{package}_{pubkey}
        package_dir = parts[0]
        components = package_dir.split('_')
        if len(components) < 3:
            return None
        
        arch = components[0]
        pubkey = components[-1]
        package = '_'.join(components[1:-1])
        
        # Get filename and KB/version
        filename = parts[-1]
        kb_or_version = parts[-2]
        
        return {
            'path': str(file_path.absolute()),
            'name': filename.lower(),
            'arch': arch,
            'package': package,
            'pubkey': pubkey,
            'kb': kb_or_version,
        }
    except Exception as e:
        logger.debug(f"Failed to parse path {file_path}: {e}")
        return None


def match_file_to_metadata(file_info: dict, kb_metadata_df: pl.DataFrame) -> Optional[dict]:
    """
    Match a patch_store file to its metadata from KB caches.
    
    Args:
        file_info: Dict with parsed file information
        kb_metadata_df: DataFrame with KB metadata
        
    Returns:
        Merged dict with complete metadata or None if no match
    """
    try:
        # Try to find matching entry in KB metadata
        matched = kb_metadata_df.filter(
            (pl.col("name").str.to_lowercase() == file_info['name']) &
            (pl.col("arch") == file_info['arch']) &
            (pl.col("package") == file_info['package']) &
            (pl.col("pubkey") == file_info['pubkey']) &
            (pl.col("kb") == file_info['kb'])
        )
        
        if len(matched) > 0:
            # Use first match
            metadata = matched.row(0, named=True)
            # Merge with file_info, preferring actual file path
            result = {**metadata, **file_info}
            return result
        
    except Exception as e:
        logger.debug(f"Error matching file {file_info.get('name')}: {e}")
    
    return None


def create_patch_entry(file_info: dict, file_path: Path) -> Optional[PatchStoreEntry]:
    """
    Create a PatchStoreEntry from file information.
    
    Args:
        file_info: Dict with file metadata
        file_path: Path to the actual file
        
    Returns:
        PatchStoreEntry or None if creation fails
    """
    try:
        # Calculate hash and PE metadata from actual file
        file_hash = get_file_hash(file_path)
        ms_id = get_pe_ms_id(file_path)
        
        # Parse version from KB string if it looks like a version
        kb = file_info.get('kb', '')
        if '.' in kb and not kb.startswith('KB'):
            version = version_tuple(kb)
        elif 'version' in file_info and isinstance(file_info['version'], list):
            version = tuple(file_info['version'])
        else:
            # Try to extract number from KB string like "KB5065426" -> (5065426,)
            if kb.startswith('KB') and kb[2:].isdigit():
                version = (int(kb[2:]),)
            else:
                version = (0,)
        
        entry = PatchStoreEntry(
            name=file_info['name'],
            path=file_info['path'],
            kb=kb,
            hash=file_hash,
            arch=file_info['arch'],
            package=file_info['package'],
            pubkey=file_info['pubkey'],
            version=version,
            ms_id=ms_id
        )
        
        return entry
        
    except Exception as e:
        logger.warning(f"Failed to create entry for {file_path.name}: {e}")
        return None


def scan_patch_store(patch_store_dir: Path, kb_metadata_df: Optional[pl.DataFrame]) -> list[PatchStoreEntry]:
    """
    Scan patch_store directory and create entries for all files.
    
    Args:
        patch_store_dir: Path to db/patch_store directory
        kb_metadata_df: Combined KB metadata DataFrame (can be None)
        
    Returns:
        List of PatchStoreEntry objects
    """
    console.info(f"[*] Scanning patch store: {patch_store_dir}")
    
    # Get all executable files in patch_store
    all_files = []
    for ext in EXECUTABLE_EXTENSIONS:
        all_files.extend(patch_store_dir.rglob(f"*{ext}"))
    
    console.info(f"[+] Found {len(all_files)} executable files in patch store")
    
    entries = []
    matched_count = 0
    unmatched_count = 0
    error_count = 0
    
    for i, file_path in enumerate(all_files, 1):
        if i % 100 == 0:
            console.info(f"    Processing {i}/{len(all_files)}...")
        
        try:
            # Parse path to extract basic metadata
            file_info = parse_patch_store_path(file_path, patch_store_dir)
            if not file_info:
                logger.debug(f"Skipping file with unexpected path: {file_path}")
                error_count += 1
                continue
            
            # Try to match with KB metadata if available
            if kb_metadata_df is not None:
                matched_info = match_file_to_metadata(file_info, kb_metadata_df)
                if matched_info:
                    file_info = matched_info
                    matched_count += 1
                else:
                    unmatched_count += 1
                    logger.debug(f"No metadata match for: {file_info['name']} in {file_info['kb']}")
            else:
                unmatched_count += 1
            
            # Create entry
            entry = create_patch_entry(file_info, file_path)
            if entry:
                entries.append(entry)
            else:
                error_count += 1
                
        except Exception as e:
            error_count += 1
            logger.warning(f"Error processing {file_path}: {e}")
    
    console.info(f"[+] Processed {len(all_files)} files:")
    console.info(f"    - Matched to KB metadata: {matched_count}")
    console.info(f"    - Without metadata: {unmatched_count}")
    console.info(f"    - Errors: {error_count}")
    console.info(f"    - Total entries created: {len(entries)}")
    
    return entries


def check_existing_database(output_file: Path) -> bool:
    """
    Check if the existing database file is corrupted or needs restoration.
    
    Args:
        output_file: Path to .patch_store_df file
        
    Returns:
        True if restoration is needed, False otherwise
    """
    console.info("[Validation] Checking existing database file")
    console.info("-" * 80)
    
    if not output_file.exists():
        console.warning(f"[!] Database file does not exist: {output_file}")
        console.info("[+] Restoration is needed")
        return True
    
    try:
        # Try to load existing database
        existing_df = pl.DataFrame.deserialize(output_file)
        
        console.info(f"[*] Existing database found")
        console.info(f"    - Shape: {existing_df.shape}")
        console.info(f"    - Columns: {existing_df.columns}")
        
        # Check if it's empty or corrupted
        if len(existing_df) == 0:
            console.warning(f"[!] Database file is empty (0 rows)")
            console.info("[+] Restoration is needed")
            return True
        
        # Check if it has the expected columns
        expected_columns = ['name', 'path', 'kb', 'hash', 'arch', 'package', 'pubkey', 'version', 'ms_id', 'uid']
        missing_columns = [col for col in expected_columns if col not in existing_df.columns]
        
        if missing_columns:
            console.warning(f"[!] Database is missing columns: {missing_columns}")
            console.info("[+] Restoration is needed")
            return True
        
        console.info(f"[+] Database appears valid with {len(existing_df)} entries")
        console.info("")
        response = input("Database seems OK. Do you still want to restore it? (yes/no): ").strip().lower()
        
        if response not in ['yes', 'y']:
            console.info("[-] Restoration cancelled by user")
            return False
        
        return True
        
    except Exception as e:
        console.error(f"[!] Failed to load existing database: {e}")
        logger.exception("Error loading existing database")
        console.info("[+] Database is corrupted - restoration is needed")
        return True


def main():
    """Main restore function."""
    console.info("=" * 80)
    console.info("Patch Store Database Restoration Tool")
    console.info("=" * 80)
    
    # Setup paths (relative to project root)
    project_root = Path(__file__).parent.parent
    temp_dir = project_root / "_temp"
    patch_store_dir = project_root / "db" / "patch_store"
    output_file = project_root / "db" / ".patch_store_df"
    
    console.info(f"[*] Project root: {project_root}")
    console.info(f"[*] Patch store: {patch_store_dir}")
    console.info(f"[*] Output file: {output_file}")
    console.info("")
    
    # Verify directories exist
    if not patch_store_dir.exists():
        console.error(f"[-] Patch store directory not found: {patch_store_dir}")
        return 1
    
    # Check if restoration is needed
    if not check_existing_database(output_file):
        return 0
    
    console.info("")
    
    # Step 1: Load KB metadata caches
    console.info("[Step 1] Loading KB metadata from cache files")
    console.info("-" * 80)
    
    kb_metadata_df = None
    if temp_dir.exists():
        kb_metadata_df = load_kb_caches(temp_dir)
    else:
        console.warning(f"[-] Temp directory not found: {temp_dir}")
        console.warning("[-] Will proceed without KB metadata (version info may be incomplete)")
    
    console.info("")
    
    # Step 2: Scan patch store and create entries
    console.info("[Step 2] Scanning patch store and creating entries")
    console.info("-" * 80)
    
    entries = scan_patch_store(patch_store_dir, kb_metadata_df)
    
    if not entries:
        console.error("[-] No entries created. Cannot proceed.")
        return 1
    
    console.info("")
    
    # Step 3: Create DataFrame preview
    console.info("[Step 3] Creating DataFrame Preview")
    console.info("-" * 80)
    
    try:
        # Create DataFrame from entries
        df = pl.DataFrame([entry.to_dict() for entry in entries])
        
        console.info(f"[*] DataFrame created successfully")
        console.info(f"    - Shape: {df.shape}")
        console.info(f"    - Columns: {df.columns}")
        console.info("")
        
        # Show preview with all columns
        console.info("[Preview] First 5 rows (all columns):")
        console.info("-" * 80)
        with pl.Config(tbl_cols=-1, tbl_rows=5, set_tbl_width_chars=200):
            print(df.head(5))
        
        console.info("")
        console.info("[Preview] Last 3 rows (all columns):")
        console.info("-" * 80)
        with pl.Config(tbl_cols=-1, tbl_rows=3, set_tbl_width_chars=200):
            print(df.tail(3))
        
        console.info("")
        console.info("[Preview] Column statistics:")
        console.info("-" * 80)
        console.info(f"    - Total entries: {len(df)}")
        console.info(f"    - Unique KBs: {df['kb'].n_unique()}")
        console.info(f"    - Unique packages: {df['package'].n_unique()}")
        console.info(f"    - Unique files: {df['name'].n_unique()}")
        
        # Show KB distribution
        console.info("")
        console.info("[Preview] KB/Base Version distribution:")
        kb_counts = df.group_by('kb').agg(pl.len().alias('count')).sort('count', descending=True)
        with pl.Config(tbl_rows=20):
            print(kb_counts.head(20))
        
    except Exception as e:
        console.error(f"[-] Failed to create DataFrame preview: {e}")
        logger.exception("Error creating DataFrame preview")
        return 1
    
    # Step 4: Ask for confirmation
    console.info("")
    console.info("[Step 4] Confirmation")
    console.info("-" * 80)
    console.info(f"Ready to write {len(entries)} entries to: {output_file}")
    
    if output_file.exists():
        console.warning(f"[!] WARNING: Output file already exists and will be OVERWRITTEN")
    
    console.info("")
    response = input("Do you want to write the database file? (yes/no): ").strip().lower()
    
    if response not in ['yes', 'y']:
        console.info("[-] Operation cancelled by user")
        return 0
    
    # Step 5: Write database file
    console.info("")
    console.info("[Step 5] Writing database file")
    console.info("-" * 80)
    
    try:
        # DataFrame already created in step 3, just serialize it
        output_file.parent.mkdir(parents=True, exist_ok=True)
        safe_serialize(df, output_file)
        
        console.info(f"[+] Successfully wrote database to: {output_file}")
        console.info(f"[+] File size: {output_file.stat().st_size:,} bytes")
        
        # Verify it can be read back
        test_df = pl.DataFrame.deserialize(output_file)
        console.info(f"[+] Verification: Successfully read back {len(test_df)} entries")
        
        console.info("")
        console.info("=" * 80)
        console.info("[SUCCESS] Patch store database has been restored!")
        console.info("=" * 80)
        
        return 0
        
    except Exception as e:
        console.error(f"[-] Failed to write database: {e}")
        logger.exception("Error writing database")
        return 1


if __name__ == "__main__":
    sys.exit(main())
