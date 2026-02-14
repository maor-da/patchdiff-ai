# deltacli - Delta Compression CLI Tool

A comprehensive command-line tool for working with Windows Delta Compression files using the MSDelta / UpdateCompression APIs.

## Features

- **Apply Delta Patches**: Apply delta/patch files to source files to produce target output
- **Extract Metadata**: Display detailed information from delta file headers
- **Validate Patches**: Check delta file integrity and structure
- **Calculate Signatures**: Compute normalized file signatures for identifying base files
- **Self-Contained Patches**: Support for patches that don't require a source file
- **Recursive Patching**: Apply multiple deltas in sequence automatically
- **Color-Coded Output**: Easy-to-read terminal output with color support

## Building

### Requirements

- Visual Studio 2022 with C++ Desktop Development workload
- Windows SDK 10.0
- C++17 or later

### Build Instructions

```powershell
# Using MSBuild (from Visual Studio Developer Command Prompt or PowerShell)
msbuild native.vcxproj /p:Configuration=Release /p:Platform=x64

# Or open native.sln in Visual Studio and build
```

The compiled executable will be located at:
```
x64\Release\native.exe
```

## Usage

```
deltacli <command> [options]
```

### Commands

| Command   | Description                                           |
|-----------|-------------------------------------------------------|
| apply     | Apply a delta patch to produce a target file          |
| info      | Display delta file metadata and header information    |
| validate  | Validate delta file integrity and structure           |
| signature | Calculate normalized file signature                   |
| help      | Show help message                                     |

## Command Examples

### Apply Command

Apply a delta patch to a source file:

```powershell
native.exe apply -d patch.pa_ -s old.dll -o new.dll
```

Apply a self-contained patch (no source needed):

```powershell
native.exe apply -d manifest.pa_ -o manifest.xml
```

Apply patches recursively until non-patch output:

```powershell
native.exe apply -d chained.pa_ -s old.dll -o new.dll --recursive
```

**Options:**
- `-d, --delta <file>` - Delta/patch file (required)
- `-s, --source <file>` - Source/base file (optional for self-contained patches)
- `-o, --output <file>` - Output target file (required)
- `-r, --recursive` - Apply patches recursively
- `--allow-legacy` - Allow PA19 (legacy PatchAPI) format

### Info Command

Display detailed metadata from a delta file:

```powershell
native.exe info patch.pa_
# or
native.exe info -d patch.pa_
```

**Example output:**

```
Delta File Information
============================================================
  File:              patch.pa_
  File Size:         505476 bytes (493.63 KB)
  Format:            PA31

------------------------------------------------------------
  Metadata
------------------------------------------------------------
  File Type Set:     EXECUTABLES_2 (full set)
  File Type:         AMD64
  Target Size:       517728 bytes (505.59 KB)
  Target Time:       2026-01-31 03:04:37 UTC
  Hash Algorithm:    SHA-256
  Target Hash:       A2D233E4E3113F4F...

------------------------------------------------------------
  Flags: 0x0000000000000012
    [+] DELTA_FLAG_MARK                      Mark non-executable regions
    [+] DELTA_FLAG_IMPORTS                   Transform PE imports
    [+] DELTA_FLAG_AMD64_DISASM              Transform instructions (AMD64)
============================================================
```

### Validate Command

Validate delta file integrity:

```powershell
native.exe validate patch.pa_
# or
native.exe validate -d patch.pa_
```

**Example output:**

```
Validating: patch.pa_ (505476 bytes)
------------------------------------------------------------
  Format:            PA31
  Signature:         PA31
  Parseable:         Yes
  Target Size:       517728 bytes (505.59 KB)
  File Type:         AMD64
  Hash Algorithm:    SHA-256
  Target Hash:       A2D233E4E3113F4F...
------------------------------------------------------------
  [+] Valid delta file
```

### Signature Command

Calculate normalized file signature:

```powershell
native.exe signature -f kernel32.dll
```

Compare signatures of two files:

```powershell
native.exe signature -f old.dll --compare new.dll
```

Use different hash algorithm:

```powershell
native.exe signature -f file.dll -a sha256
```

**Options:**
- `-f, --file <file>` - File to calculate signature for (required)
- `-a, --algorithm <alg>` - Hash algorithm: `crc32`, `md5`, `sha1`, `sha256`, `none` (default: crc32)
- `-t, --filetype <type>` - File type set: `raw`, `exe1`, `exe2`, `latest` (default: latest)
- `--compare <file>` - Compare signature with another file

## Delta File Formats

The tool supports multiple delta file formats:

### PA30/PA31 Format
Direct patch format with signature starting with "PA". Most common format for Windows Update patches.

### CRC32-Prefixed Format
4-byte CRC32 checksum followed by the delta payload. The tool automatically validates the CRC32 before processing.

## Technical Details

### DLL Loading

The tool attempts to load delta compression DLLs in this order:
1. `UpdateCompression.dll` (local - searches in exe directory and parent directories)
2. `msdelta.dll` (system - from System32)

### Supported APIs

- **ApplyDeltaB** - Apply delta patches (required)
- **GetDeltaInfoB** - Extract metadata (requires msdelta.dll)
- **GetDeltaSignatureB** - Calculate signatures (requires msdelta.dll)
- **DeltaFree** - Free allocated memory (required)

### File Type Sets

| Type            | Value | Description                                    |
|-----------------|-------|------------------------------------------------|
| RAW_ONLY        | 0x01  | Raw files only, no special handling            |
| EXECUTABLES_1   | 0x0F  | I386, IA64, AMD64 PE files                     |
| EXECUTABLES_2   | 0xFF  | Full set including ARM and CLI4 formats        |

### Transform Flags

The tool displays all transform flags applied during delta creation:

- **DELTA_FLAG_MARK** - Mark non-executable regions
- **DELTA_FLAG_IMPORTS** - Transform PE imports
- **DELTA_FLAG_EXPORTS** - Transform PE exports
- **DELTA_FLAG_RESOURCES** - Transform PE resources
- **DELTA_FLAG_RELOCS** - Transform PE relocations
- **DELTA_FLAG_AMD64_DISASM** - Transform AMD64 instructions
- **DELTA_FLAG_IA64_DISASM** - Transform IA64 instructions
- **DELTA_FLAG_ARM_DISASM** - Transform ARM instructions
- **DELTA_FLAG_CLI_METADATA** - Transform CLI metadata
- And many more...

## Testing

The tool has been tested with:
- Windows Update patches (.pa_, .psf files)
- Self-contained patches
- CRC32-prefixed delta files
- Various executable types (AMD64, I386)

Example test files included in this repository:
- `mshtml/f/mshtml.dll` - PA31 self-contained patch
- `mshtml/f/indexeddblegacy.dll` - Small delta patch

## Error Handling

The tool provides detailed error messages including:
- Win32 error codes with descriptions
- File I/O errors
- DLL loading failures
- CRC32 validation failures
- Delta application errors

## References

- [Delta Compression API Documentation](https://learn.microsoft.com/en-us/previous-versions/bb417345(v=msdn.10))
- [ApplyDeltaB Function](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab)
- [MSDelta Overview](https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta)

## License

This tool is part of the PatchDiff-AI project. See the main repository LICENSE file for details.
