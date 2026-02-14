#!/usr/bin/env python3
"""
CLI tool for demonstrating PatchTools functionality.

This script provides command-line access to all major PatchTools capabilities:
- Apply delta patches to base files
- Validate patch files
- Reconstruct base files from WinSxS
- Extract and parse Windows manifests
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

# Add parent directory to path for imports
_parent_dir = Path(__file__).resolve().parent.parent
if str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))

try:
    from patch_extractor.patch_tools import PatchTools
except ImportError:
    from patch_tools import PatchTools

try:
    from common import logger, console
except ImportError:
    import logging
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)
    console = None


def cmd_apply(args) -> int:
    """Apply a delta patch to a base file."""
    patch_path = Path(args.patch)
    output_path = Path(args.output)
    base_path = Path(args.base) if args.base else None
    
    if not patch_path.exists():
        print(f"Error: Patch file not found: {patch_path}", file=sys.stderr)
        return 1
    
    if base_path and not base_path.exists():
        print(f"Error: Base file not found: {base_path}", file=sys.stderr)
        return 1
    
    try:
        pt = PatchTools()
        
        # Read base file if provided
        base_data = None
        if base_path:
            print(f"Loading base file: {base_path}")
            base_data = base_path.read_bytes()
        else:
            print("Applying self-contained patch (no base file)")
        
        # Read patch file
        print(f"Loading patch file: {patch_path}")
        patch_data = patch_path.read_bytes()
        
        # Apply patch
        print("Applying patch...")
        try:
            result = pt.apply(
                memoryview(base_data) if base_data else None,
                memoryview(patch_data)
            )
            # If result is None and base was provided, try self-contained
            if not result and base_data:
                result = pt.apply(None, memoryview(patch_data))
        except RuntimeError:
            # If with-base fails, try self-contained
            result = pt.apply(None, memoryview(patch_data))
        
        # Handle recursive patching if enabled
        if args.recursive:
            iteration = 1
            while result and pt.is_patch(result):
                print(f"Applying recursive patch iteration {iteration}...")
                try:
                    result = pt.apply(
                        memoryview(base_data) if base_data else None,
                        memoryview(result)
                    )
                except RuntimeError:
                    result = pt.apply(None, memoryview(result))
                iteration += 1
        
        if result:
            # Write output
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(result)
            print(f"Success! Output written to: {output_path}")
            print(f"Output size: {len(result):,} bytes")
            return 0
        else:
            print("Error: Patch application returned no data", file=sys.stderr)
            return 1
            
    except RuntimeError as e:
        print(f"Error applying patch: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_validate(args) -> int:
    """Validate a patch file."""
    patch_path = Path(args.patch_file)
    
    if not patch_path.exists():
        print(f"Error: Patch file not found: {patch_path}", file=sys.stderr)
        return 1
    
    try:
        print(f"Validating patch file: {patch_path}")
        patch_data = patch_path.read_bytes()
        
        if PatchTools.is_patch(patch_data):
            print("✓ Valid patch file")
            print(f"  Size: {len(patch_data):,} bytes")
            
            # Get additional info by validating
            try:
                validated = PatchTools.validate_patch(memoryview(patch_data))
                sig = patch_data[:6]
                
                if sig.startswith(b"PA"):
                    print(f"  Format: PA30 signature detected")
                else:
                    print(f"  Format: CRC32-prefixed patch")
                    
                print(f"  Patch data size: {len(validated):,} bytes")
                
            except Exception as e:
                print(f"  Warning: Could not extract detailed info: {e}")
            
            return 0
        else:
            print("✗ Invalid patch file", file=sys.stderr)
            return 1
            
    except Exception as e:
        print(f"Error validating patch: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_find_base(args) -> int:
    """Find and reconstruct a base file from WinSxS."""
    dll_name = args.dll_name
    output_path = Path(args.output) if args.output else None
    
    try:
        print(f"Searching WinSxS for: {dll_name}")
        pt = PatchTools()
        
        # Find and load base
        print("Reconstructing base file (this may take a moment)...")
        base_data = pt.find_base_and_load(dll_name)
        
        print(f"✓ Successfully reconstructed base file")
        print(f"  Size: {len(base_data):,} bytes")
        
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(base_data)
            print(f"  Saved to: {output_path}")
        else:
            print(f"  (use --output to save the file)")
            
        return 0
        
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_manifest(args) -> int:
    """Get and parse a Windows manifest for a DLL."""
    dll_name = args.dll_name
    
    try:
        print(f"Searching for manifest: {dll_name}")
        pt = PatchTools()
        
        # Get manifest
        manifest_data = pt.get_manifest(dll_name)
        print(f"✓ Found manifest ({len(manifest_data):,} bytes)")
        
        if args.raw:
            # Show raw XML
            print("\nRaw manifest XML:")
            print("-" * 80)
            print(manifest_data.decode('utf-8', errors='replace'))
            print("-" * 80)
        else:
            # Parse and display structured info
            manifest_info = pt.parse_manifest(manifest_data)
            
            if manifest_info:
                print("\nManifest Information:")
                print("-" * 80)
                print(f"Name:                {manifest_info.get('name', 'N/A')}")
                print(f"Version:             {manifest_info.get('version', 'N/A')}")
                print(f"Architecture:        {manifest_info.get('architecture', 'N/A')}")
                print(f"Public Key Token:    {manifest_info.get('public_key_token', 'N/A')}")
                
                files = manifest_info.get('files', [])
                if files:
                    print(f"\nAssociated Files ({len(files)}):")
                    for i, file_info in enumerate(files, 1):
                        print(f"  {i}. {file_info.get('name', 'N/A')}")
                        if args.verbose:
                            print(f"     Hash:    {file_info.get('hash', 'N/A')}")
                            print(f"     HashAlg: {file_info.get('hashalg', 'N/A')}")
                else:
                    print("\nNo associated files found in manifest")
                print("-" * 80)
            else:
                print("Warning: Failed to parse manifest", file=sys.stderr)
                return 1
        
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(manifest_data)
            print(f"\nManifest saved to: {output_path}")
        
        return 0
        
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main(argv: list[str]) -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="PatchTools CLI - Demonstration of Windows delta patch operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Apply a patch to a base file
  %(prog)s apply --patch update.pa_ --base old.dll --output new.dll
  
  # Apply a self-contained patch (no base needed)
  %(prog)s apply --patch manifest.pa_ --output manifest.xml
  
  # Apply patches recursively
  %(prog)s apply --patch chained.pa_ --base old.dll --output new.dll --recursive
  
  # Validate a patch file
  %(prog)s validate patch_file.pa_
  
  # Reconstruct a DLL from WinSxS
  %(prog)s find-base kernel32.dll --output kernel32_base.dll
  
  # View manifest information
  %(prog)s manifest mstscax.dll
  
  # Export raw manifest XML
  %(prog)s manifest mstscax.dll --raw --output manifest.xml
        """
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output and stack traces')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    subparsers.required = True
    
    # Apply command
    apply_parser = subparsers.add_parser(
        'apply',
        help='Apply a delta patch to a base file',
        description='Apply a Windows delta patch to a base file, or apply a self-contained patch.'
    )
    apply_parser.add_argument('--patch', required=True,
                              help='Path to the patch file (.pa_, .psf, etc.)')
    apply_parser.add_argument('--base',
                              help='Path to the base/old file (optional for self-contained patches)')
    apply_parser.add_argument('--output', required=True,
                              help='Path for the output file')
    apply_parser.add_argument('--recursive', action='store_true',
                              help='Apply patches recursively until a non-patch result')
    apply_parser.set_defaults(func=cmd_apply)
    
    # Validate command
    validate_parser = subparsers.add_parser(
        'validate',
        help='Validate a patch file',
        description='Check if a file is a valid Windows delta patch.'
    )
    validate_parser.add_argument('patch_file',
                                 help='Path to the patch file to validate')
    validate_parser.set_defaults(func=cmd_validate)
    
    # Find-base command
    find_base_parser = subparsers.add_parser(
        'find-base',
        help='Find and reconstruct a base file from WinSxS',
        description='Search WinSxS directory for a DLL and reconstruct its base version by applying reverse patches.'
    )
    find_base_parser.add_argument('dll_name',
                                  help='Name of the DLL to find (e.g., kernel32.dll)')
    find_base_parser.add_argument('--output',
                                  help='Path to save the reconstructed file')
    find_base_parser.set_defaults(func=cmd_find_base)
    
    # Manifest command
    manifest_parser = subparsers.add_parser(
        'manifest',
        help='Get and parse a Windows manifest',
        description='Retrieve and parse a Windows component manifest from WinSxS/Manifests directory.'
    )
    manifest_parser.add_argument('dll_name',
                                 help='Name of the DLL to get manifest for (e.g., mstscax.dll)')
    manifest_parser.add_argument('--raw', action='store_true',
                                 help='Show raw XML instead of parsed information')
    manifest_parser.add_argument('--output',
                                 help='Path to save the manifest XML')
    manifest_parser.set_defaults(func=cmd_manifest)
    
    # Parse arguments
    args = parser.parse_args(argv)
    
    # Execute command
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
