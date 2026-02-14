/*
 * deltacli - Delta Compression CLI Tool
 *
 * A feature-rich command-line tool for working with Windows Delta
 * Compression files using the MSDelta / UpdateCompression APIs.
 *
 * Commands:
 *   apply      - Apply a delta patch to a source file
 *   info       - Display delta file metadata and header information
 *   validate   - Validate delta file integrity and structure
 *   signature  - Calculate normalized file signatures
 *
 * References:
 *   https://learn.microsoft.com/en-us/previous-versions/bb417345(v=msdn.10)
 *   https://learn.microsoft.com/en-us/windows/win32/devnotes/msdelta-applydeltab
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cstdarg>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

// ============================================================
//  Delta API Types and Structures
// ============================================================

typedef UINT64 DELTA_FILE_TYPE;
typedef UINT64 DELTA_FLAG_TYPE;

struct DELTA_INPUT {
    union {
        LPCVOID lpcStart;
        LPVOID  lpStart;
    };
    SIZE_T uSize;
    BOOL   Editable;
};

struct DELTA_OUTPUT {
    LPVOID lpStart;
    SIZE_T uSize;
};

static constexpr DWORD DELTA_MAX_HASH_SIZE = 32;

struct DELTA_HASH {
    DWORD HashSize;
    UCHAR HashValue[DELTA_MAX_HASH_SIZE];
};

struct DELTA_HEADER_INFO {
    DELTA_FILE_TYPE FileTypeSet;
    DELTA_FILE_TYPE FileType;
    DELTA_FLAG_TYPE Flags;
    SIZE_T          TargetSize;
    FILETIME        TargetFileTime;
    DWORD           TargetHashAlgId;
    DELTA_HASH      TargetHash;
};

// Function pointer types for dynamically loaded API
using FnApplyDeltaB        = BOOL(WINAPI*)(DELTA_FLAG_TYPE, DELTA_INPUT, DELTA_INPUT, DELTA_OUTPUT*);
using FnGetDeltaInfoB      = BOOL(WINAPI*)(DELTA_INPUT, DELTA_HEADER_INFO*);
using FnGetDeltaSignatureB = BOOL(WINAPI*)(DELTA_FILE_TYPE, DWORD, DELTA_INPUT, DELTA_HASH*);
using FnDeltaFree          = BOOL(WINAPI*)(LPVOID);

// ============================================================
//  File Type Constants
// ============================================================

static constexpr DELTA_FILE_TYPE DFT_RAW         = 0x00000001ULL;
static constexpr DELTA_FILE_TYPE DFT_I386        = 0x00000002ULL;
static constexpr DELTA_FILE_TYPE DFT_IA64        = 0x00000004ULL;
static constexpr DELTA_FILE_TYPE DFT_AMD64       = 0x00000008ULL;
static constexpr DELTA_FILE_TYPE DFT_ARM         = 0x00000010ULL;
static constexpr DELTA_FILE_TYPE DFT_CLI4_I386   = 0x00000020ULL;
static constexpr DELTA_FILE_TYPE DFT_CLI4_AMD64  = 0x00000040ULL;
static constexpr DELTA_FILE_TYPE DFT_CLI4_ARM    = 0x00000080ULL;

static constexpr DELTA_FILE_TYPE DFTS_RAW_ONLY        = 0x00000001ULL;
static constexpr DELTA_FILE_TYPE DFTS_EXECUTABLES_1    = 0x0000000FULL;
static constexpr DELTA_FILE_TYPE DFTS_EXECUTABLES_2    = 0x000000FFULL;

// ============================================================
//  Delta Flag Constants
// ============================================================

static constexpr DELTA_FLAG_TYPE DF_NONE                      = 0x00000000ULL;
static constexpr DELTA_FLAG_TYPE DF_ALLOW_PA19                = 0x00000001ULL;

// Delta create / info flags
static constexpr DELTA_FLAG_TYPE DF_E8                        = 0x00000001ULL;
static constexpr DELTA_FLAG_TYPE DF_MARK                      = 0x00000002ULL;
static constexpr DELTA_FLAG_TYPE DF_IMPORTS                   = 0x00000004ULL;
static constexpr DELTA_FLAG_TYPE DF_EXPORTS                   = 0x00000008ULL;
static constexpr DELTA_FLAG_TYPE DF_RESOURCES                 = 0x00000010ULL;
static constexpr DELTA_FLAG_TYPE DF_RELOCS                    = 0x00000020ULL;
static constexpr DELTA_FLAG_TYPE DF_I386_SMASHLOCK            = 0x00000040ULL;
static constexpr DELTA_FLAG_TYPE DF_I386_JMPS                 = 0x00000080ULL;
static constexpr DELTA_FLAG_TYPE DF_I386_CALLS                = 0x00000100ULL;
static constexpr DELTA_FLAG_TYPE DF_AMD64_DISASM              = 0x00000200ULL;
static constexpr DELTA_FLAG_TYPE DF_AMD64_PDATA               = 0x00000400ULL;
static constexpr DELTA_FLAG_TYPE DF_IA64_DISASM               = 0x00000800ULL;
static constexpr DELTA_FLAG_TYPE DF_IA64_PDATA                = 0x00001000ULL;
static constexpr DELTA_FLAG_TYPE DF_UNBIND                    = 0x00002000ULL;
static constexpr DELTA_FLAG_TYPE DF_CLI_DISASM                = 0x00004000ULL;
static constexpr DELTA_FLAG_TYPE DF_CLI_METADATA              = 0x00008000ULL;
static constexpr DELTA_FLAG_TYPE DF_HEADERS                   = 0x00010000ULL;
static constexpr DELTA_FLAG_TYPE DF_IGNORE_FILE_SIZE_LIMIT    = 0x00020000ULL;
static constexpr DELTA_FLAG_TYPE DF_IGNORE_OPTIONS_SIZE_LIMIT = 0x00040000ULL;
static constexpr DELTA_FLAG_TYPE DF_ARM_DISASM                = 0x00080000ULL;
static constexpr DELTA_FLAG_TYPE DF_ARM_PDATA                 = 0x00100000ULL;
static constexpr DELTA_FLAG_TYPE DF_CLI4_METADATA             = 0x00200000ULL;
static constexpr DELTA_FLAG_TYPE DF_CLI4_DISASM               = 0x00400000ULL;
static constexpr DELTA_FLAG_TYPE DF_CLI4_UNBIND               = 0x00800000ULL;

// Flag lookup table for display
struct FlagEntry {
    DELTA_FLAG_TYPE value;
    const char* name;
    const char* description;
};

static const FlagEntry g_deltaFlags[] = {
    { DF_E8,                        "DELTA_FLAG_E8",                        "Transform E8 relative calls"           },
    { DF_MARK,                      "DELTA_FLAG_MARK",                      "Mark non-executable regions"           },
    { DF_IMPORTS,                   "DELTA_FLAG_IMPORTS",                   "Transform PE imports"                  },
    { DF_EXPORTS,                   "DELTA_FLAG_EXPORTS",                   "Transform PE exports"                  },
    { DF_RESOURCES,                 "DELTA_FLAG_RESOURCES",                 "Transform PE resources"                },
    { DF_RELOCS,                    "DELTA_FLAG_RELOCS",                    "Transform PE relocations"              },
    { DF_I386_SMASHLOCK,            "DELTA_FLAG_I386_SMASHLOCK",            "Repair smashed lock prefixes (I386)"   },
    { DF_I386_JMPS,                 "DELTA_FLAG_I386_JMPS",                "Transform relative jumps (I386)"       },
    { DF_I386_CALLS,                "DELTA_FLAG_I386_CALLS",                "Transform relative calls (I386)"       },
    { DF_AMD64_DISASM,              "DELTA_FLAG_AMD64_DISASM",              "Transform instructions (AMD64)"        },
    { DF_AMD64_PDATA,               "DELTA_FLAG_AMD64_PDATA",               "Transform pdata (AMD64)"              },
    { DF_IA64_DISASM,               "DELTA_FLAG_IA64_DISASM",               "Transform instructions (IA64)"        },
    { DF_IA64_PDATA,                "DELTA_FLAG_IA64_PDATA",                "Transform pdata (IA64)"               },
    { DF_UNBIND,                    "DELTA_FLAG_UNBIND",                    "Unbind source PE"                      },
    { DF_CLI_DISASM,                "DELTA_FLAG_CLI_DISASM",                "Transform CLI instructions"            },
    { DF_CLI_METADATA,              "DELTA_FLAG_CLI_METADATA",              "Transform CLI metadata"                },
    { DF_HEADERS,                   "DELTA_FLAG_HEADERS",                   "Transform PE headers"                  },
    { DF_IGNORE_FILE_SIZE_LIMIT,    "DELTA_FLAG_IGNORE_FILE_SIZE_LIMIT",    "Ignore file size limit"                },
    { DF_IGNORE_OPTIONS_SIZE_LIMIT, "DELTA_FLAG_IGNORE_OPTIONS_SIZE_LIMIT", "Ignore options size limit"             },
    { DF_ARM_DISASM,                "DELTA_FLAG_ARM_DISASM",                "Transform instructions (ARM)"          },
    { DF_ARM_PDATA,                 "DELTA_FLAG_ARM_PDATA",                 "Transform pdata (ARM)"                 },
    { DF_CLI4_METADATA,             "DELTA_FLAG_CLI4_METADATA",             "Transform CLI4 metadata"               },
    { DF_CLI4_DISASM,               "DELTA_FLAG_CLI4_DISASM",               "Transform CLI4 instructions"           },
    { DF_CLI4_UNBIND,               "DELTA_FLAG_CLI4_UNBIND",               "Unbind (CLI4)"                         },
};

static constexpr int g_numDeltaFlags = sizeof(g_deltaFlags) / sizeof(g_deltaFlags[0]);

// ============================================================
//  CRC32 Implementation (standard zlib-compatible)
// ============================================================

static DWORD g_crc32Table[256];
static bool  g_crc32Ready = false;

static void InitCRC32() {
    for (DWORD i = 0; i < 256; i++) {
        DWORD crc = i;
        for (int j = 0; j < 8; j++)
            crc = (crc & 1) ? ((crc >> 1) ^ 0xEDB88320UL) : (crc >> 1);
        g_crc32Table[i] = crc;
    }
    g_crc32Ready = true;
}

static DWORD CalcCRC32(const BYTE* data, size_t length) {
    if (!g_crc32Ready) InitCRC32();
    DWORD crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++)
        crc = (crc >> 8) ^ g_crc32Table[(crc ^ data[i]) & 0xFF];
    return crc ^ 0xFFFFFFFF;
}

// ============================================================
//  Win32 Error Helper
// ============================================================

static std::string Win32Error(DWORD code) {
    char* buf = nullptr;
    DWORD len = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    std::string msg;
    if (len > 0 && buf) {
        msg.assign(buf, len);
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r' || msg.back() == ' '))
            msg.pop_back();
        LocalFree(buf);
    }
    return msg;
}

// ============================================================
//  Console Output Helpers (color support)
// ============================================================

static HANDLE g_hStdOut      = INVALID_HANDLE_VALUE;
static WORD   g_defaultAttrs = 7;
static bool   g_useColors    = false;
static bool   g_consoleReady = false;

enum class Color : WORD {
    Default = 0,
    Red     = FOREGROUND_RED | FOREGROUND_INTENSITY,
    Green   = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    Yellow  = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
    Cyan    = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    White   = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    Gray    = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE,
};

static void InitConsole() {
    if (g_consoleReady) return;
    g_hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    g_useColors = (GetConsoleMode(g_hStdOut, &mode) != 0);
    if (g_useColors) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(g_hStdOut, &csbi))
            g_defaultAttrs = csbi.wAttributes;
        SetConsoleOutputCP(CP_UTF8);
    }
    g_consoleReady = true;
}

static void SetColor(Color c) {
    if (!g_useColors) return;
    SetConsoleTextAttribute(g_hStdOut,
        (c == Color::Default) ? g_defaultAttrs : static_cast<WORD>(c));
}

static void ResetColor() { SetColor(Color::Default); }

// Colored printf
static void CPrintf(Color c, const char* fmt, ...) {
    SetColor(c);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    ResetColor();
}

// ============================================================
//  Formatting Utilities
// ============================================================

static std::string FmtSize(size_t bytes) {
    char buf[80];
    if (bytes < 1024)
        snprintf(buf, sizeof(buf), "%zu bytes", bytes);
    else if (bytes < 1024 * 1024)
        snprintf(buf, sizeof(buf), "%zu bytes (%.2f KB)", bytes, bytes / 1024.0);
    else if (bytes < 1024ULL * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%zu bytes (%.2f MB)", bytes, bytes / (1024.0 * 1024.0));
    else
        snprintf(buf, sizeof(buf), "%zu bytes (%.2f GB)", bytes, bytes / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

static std::string FmtFileTime(const FILETIME& ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0)
        return "(not set)";
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d UTC",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static std::string FmtHash(const DELTA_HASH& hash) {
    if (hash.HashSize == 0) return "(none)";
    std::string s;
    s.reserve(hash.HashSize * 2);
    for (DWORD i = 0; i < hash.HashSize && i < DELTA_MAX_HASH_SIZE; i++) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X", hash.HashValue[i]);
        s += hex;
    }
    return s;
}

static const char* FmtFileType(DELTA_FILE_TYPE type) {
    switch (type) {
    case DFT_RAW:        return "RAW";
    case DFT_I386:       return "I386";
    case DFT_IA64:       return "IA64";
    case DFT_AMD64:      return "AMD64";
    case DFT_ARM:        return "ARM";
    case DFT_CLI4_I386:  return "CLI4_I386";
    case DFT_CLI4_AMD64: return "CLI4_AMD64";
    case DFT_CLI4_ARM:   return "CLI4_ARM";
    default:             return "UNKNOWN";
    }
}

static std::string FmtFileTypeSet(DELTA_FILE_TYPE ts) {
    if (ts == DFTS_RAW_ONLY)      return "RAW_ONLY";
    if (ts == DFTS_EXECUTABLES_1) return "EXECUTABLES_1 (I386+IA64+AMD64)";
    if (ts == DFTS_EXECUTABLES_2) return "EXECUTABLES_2 (full set)";

    // Build dynamic description for non-standard values
    std::string s;
    auto append = [&](DELTA_FILE_TYPE f, const char* n) {
        if (ts & f) { if (!s.empty()) s += " | "; s += n; }
    };
    append(DFT_RAW, "RAW");           append(DFT_I386, "I386");
    append(DFT_IA64, "IA64");         append(DFT_AMD64, "AMD64");
    append(DFT_ARM, "ARM");           append(DFT_CLI4_I386, "CLI4_I386");
    append(DFT_CLI4_AMD64, "CLI4_AMD64"); append(DFT_CLI4_ARM, "CLI4_ARM");
    return s.empty() ? "UNKNOWN" : s;
}

static const char* FmtHashAlg(DWORD algId) {
    switch (algId) {
    case 0:      return "None";
    case 32:     return "CRC32 (MSDelta built-in)";
    case 0x8001: return "MD2";
    case 0x8002: return "MD4";
    case 0x8003: return "MD5";
    case 0x8004: return "SHA-1";
    case 0x800C: return "SHA-256";
    case 0x800D: return "SHA-384";
    case 0x800E: return "SHA-512";
    default: {
        static char buf[32];
        snprintf(buf, sizeof(buf), "ALG_ID 0x%04X", algId);
        return buf;
    }
    }
}

static void PrintSep(int w = 60) {
    for (int i = 0; i < w; i++) putchar('=');
    putchar('\n');
}

static void PrintDash(int w = 60) {
    for (int i = 0; i < w; i++) putchar('-');
    putchar('\n');
}

// ============================================================
//  File I/O Utilities
// ============================================================

static bool ReadEntireFile(const std::string& path, std::vector<BYTE>& out) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        CPrintf(Color::Red, "Error: Cannot open '%s' (0x%08X: %s)\n",
                path.c_str(), err, Win32Error(err).c_str());
        return false;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(h, &fileSize) || fileSize.QuadPart < 0) {
        CloseHandle(h);
        CPrintf(Color::Red, "Error: Cannot determine size of '%s'\n", path.c_str());
        return false;
    }
    if (fileSize.QuadPart > (1LL << 31)) {
        CloseHandle(h);
        CPrintf(Color::Red, "Error: File '%s' exceeds 2 GB limit\n", path.c_str());
        return false;
    }

    out.resize(static_cast<size_t>(fileSize.QuadPart));
    if (out.empty()) {
        CloseHandle(h);
        return true;  // empty file is valid
    }

    DWORD bytesRead = 0;
    BOOL ok = ::ReadFile(h, out.data(), static_cast<DWORD>(out.size()), &bytesRead, nullptr);
    CloseHandle(h);

    if (!ok || bytesRead != static_cast<DWORD>(out.size())) {
        CPrintf(Color::Red, "Error: Failed to read '%s'\n", path.c_str());
        return false;
    }
    return true;
}

static bool WriteEntireFile(const std::string& path, const void* data, size_t size) {
    // Create parent directories if needed
    std::error_code ec;
    fs::path p(path);
    if (p.has_parent_path())
        fs::create_directories(p.parent_path(), ec);

    HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, 0,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        CPrintf(Color::Red, "Error: Cannot create '%s' (0x%08X: %s)\n",
                path.c_str(), err, Win32Error(err).c_str());
        return false;
    }

    DWORD bytesWritten = 0;
    BOOL ok = ::WriteFile(h, data, static_cast<DWORD>(size), &bytesWritten, nullptr);
    CloseHandle(h);

    if (!ok || bytesWritten != static_cast<DWORD>(size)) {
        CPrintf(Color::Red, "Error: Failed to write '%s'\n", path.c_str());
        return false;
    }
    return true;
}

// ============================================================
//  DeltaAPI Wrapper Class
//
//  Dynamically loads UpdateCompression.dll (local) or
//  msdelta.dll (system) and resolves API function pointers.
// ============================================================

class DeltaAPI {
public:
    ~DeltaAPI() {
        if (m_hPrimary)  FreeLibrary(m_hPrimary);
        if (m_hFallback) FreeLibrary(m_hFallback);
    }

    bool Init() {
        // Try local UpdateCompression.dll first, then system msdelta.dll
        m_hPrimary = TryLoadLocal("UpdateCompression.dll");
        if (!m_hPrimary) {
            m_hPrimary = LoadLibraryA("msdelta.dll");
            if (m_hPrimary) m_loadedPath = "msdelta.dll (system)";
        }
        if (!m_hPrimary) {
            CPrintf(Color::Red,
                "Error: Failed to load UpdateCompression.dll or msdelta.dll\n"
                "  Ensure UpdateCompression.dll is alongside this executable,\n"
                "  or that msdelta.dll is available in System32.\n");
            return false;
        }

        // Load core functions (required for basic operation)
        m_fnApply = reinterpret_cast<FnApplyDeltaB>(
            GetProcAddress(m_hPrimary, "ApplyDeltaB"));
        m_fnFree = reinterpret_cast<FnDeltaFree>(
            GetProcAddress(m_hPrimary, "DeltaFree"));

        if (!m_fnApply || !m_fnFree) {
            CPrintf(Color::Red,
                "Error: Core functions (ApplyDeltaB / DeltaFree) not exported by DLL\n");
            return false;
        }

        // Load optional functions (info & signature)
        m_fnInfo = reinterpret_cast<FnGetDeltaInfoB>(
            GetProcAddress(m_hPrimary, "GetDeltaInfoB"));
        m_fnSig = reinterpret_cast<FnGetDeltaSignatureB>(
            GetProcAddress(m_hPrimary, "GetDeltaSignatureB"));

        // If optional functions missing, try system msdelta.dll as fallback
        if ((!m_fnInfo || !m_fnSig) && m_loadedPath.find("msdelta") == std::string::npos) {
            HMODULE sys = LoadLibraryA("msdelta.dll");
            if (sys) {
                m_hFallback = sys;
                if (!m_fnInfo)
                    m_fnInfo = reinterpret_cast<FnGetDeltaInfoB>(
                        GetProcAddress(sys, "GetDeltaInfoB"));
                if (!m_fnSig)
                    m_fnSig = reinterpret_cast<FnGetDeltaSignatureB>(
                        GetProcAddress(sys, "GetDeltaSignatureB"));
            }
        }

        return true;
    }

    bool HasInfo()    const { return m_fnInfo != nullptr; }
    bool HasSig()     const { return m_fnSig  != nullptr; }
    const std::string& LoadedPath() const { return m_loadedPath; }

    // Apply a delta patch to produce the target
    bool ApplyDelta(DELTA_FLAG_TYPE flags,
                    const BYTE* src, size_t srcSz,
                    const BYTE* delta, size_t deltaSz,
                    std::vector<BYTE>& out) const {
        DELTA_INPUT si{}, di{};
        si.lpcStart = src;   si.uSize = srcSz;   si.Editable = FALSE;
        di.lpcStart = delta; di.uSize = deltaSz; di.Editable = FALSE;

        DELTA_OUTPUT o{};
        if (!m_fnApply(flags, si, di, &o))
            return false;

        if (o.lpStart && o.uSize > 0) {
            out.resize(o.uSize);
            memcpy(out.data(), o.lpStart, o.uSize);
        }
        if (o.lpStart) m_fnFree(o.lpStart);
        return true;
    }

    // Extract metadata from a delta header
    bool GetInfo(const BYTE* delta, size_t sz, DELTA_HEADER_INFO& info) const {
        if (!m_fnInfo) return false;
        DELTA_INPUT d{};
        d.lpcStart = delta; d.uSize = sz; d.Editable = FALSE;
        memset(&info, 0, sizeof(info));
        return m_fnInfo(d, &info) != FALSE;
    }

    // Calculate normalized file signature
    bool GetSignature(DELTA_FILE_TYPE fts, DWORD algId,
                      const BYTE* src, size_t sz,
                      DELTA_HASH& hash) const {
        if (!m_fnSig) return false;
        DELTA_INPUT s{};
        s.lpcStart = src; s.uSize = sz; s.Editable = FALSE;
        memset(&hash, 0, sizeof(hash));
        return m_fnSig(fts, algId, s, &hash) != FALSE;
    }

private:
    HMODULE m_hPrimary  = nullptr;
    HMODULE m_hFallback = nullptr;
    std::string m_loadedPath;

    FnApplyDeltaB        m_fnApply = nullptr;
    FnGetDeltaInfoB      m_fnInfo  = nullptr;
    FnGetDeltaSignatureB m_fnSig   = nullptr;
    FnDeltaFree          m_fnFree  = nullptr;

    // Search for DLL relative to exe location (handles nested build dirs)
    HMODULE TryLoadLocal(const char* name) {
        char exeBuf[MAX_PATH]{};
        GetModuleFileNameA(nullptr, exeBuf, MAX_PATH);
        fs::path exeDir = fs::path(exeBuf).parent_path();

        // Search: same dir, parent, grandparent, great-grandparent
        fs::path candidates[] = {
            exeDir,
            exeDir.parent_path(),
            exeDir.parent_path().parent_path(),
            exeDir.parent_path().parent_path().parent_path(),
        };

        for (const auto& dir : candidates) {
            auto full = dir / name;
            if (fs::exists(full)) {
                HMODULE h = LoadLibraryA(full.string().c_str());
                if (h) {
                    m_loadedPath = full.string();
                    return h;
                }
            }
        }
        return nullptr;
    }
};

// ============================================================
//  Delta Validation
//
//  Validates delta file structure: checks for PA signature
//  or CRC32-prefixed format (4-byte CRC + delta payload).
// ============================================================

struct Validation {
    bool        valid       = false;
    bool        crcPrefixed = false;
    DWORD       crcExpected = 0;
    DWORD       crcActual   = 0;
    const BYTE* data        = nullptr;  // actual delta payload
    size_t      size        = 0;
    std::string format;
    std::string sig;                    // e.g. "PA30"
};

static Validation ValidateDelta(const std::vector<BYTE>& buf) {
    Validation v;

    if (buf.size() < 4) {
        v.format = "Too small";
        return v;
    }

    bool startsPA = (buf.size() >= 2 && buf[0] == 'P' && buf[1] == 'A');
    bool innerPA  = (buf.size() >= 6 && buf[4] == 'P' && buf[5] == 'A');

    if (!startsPA || innerPA) {
        // CRC32-prefixed format: first 4 bytes = CRC32 of remaining data
        v.crcPrefixed = true;
        v.crcExpected = *reinterpret_cast<const DWORD*>(buf.data());
        v.crcActual   = CalcCRC32(buf.data() + 4, buf.size() - 4);
        v.valid       = (v.crcExpected == v.crcActual);
        v.data        = buf.data() + 4;
        v.size        = buf.size() - 4;

        if (innerPA) {
            v.sig = std::string(reinterpret_cast<const char*>(buf.data() + 4),
                                std::min<size_t>(4, buf.size() - 4));
            v.format = "CRC32 + " + v.sig;
        } else {
            v.format = "CRC32-prefixed";
        }
    } else {
        // Direct PA format (PA30, PA19, etc.)
        v.valid  = true;
        v.data   = buf.data();
        v.size   = buf.size();
        v.sig    = std::string(reinterpret_cast<const char*>(buf.data()),
                               std::min<size_t>(4, buf.size()));
        v.format = v.sig;
    }

    return v;
}

static bool LooksLikeDelta(const std::vector<BYTE>& buf) {
    return ValidateDelta(buf).valid;
}

// ============================================================
//  Command: apply
//
//  Apply a delta patch to a source file to produce the target.
//  Supports self-contained patches (no source) and recursive
//  patching for chained deltas.
// ============================================================

static int CmdApply(DeltaAPI& api, const std::string& deltaPath,
                    const std::string& srcPath, const std::string& outPath,
                    bool recursive, bool allowPA19) {
    // Read delta file
    std::vector<BYTE> deltaBuf;
    if (!ReadEntireFile(deltaPath, deltaBuf)) return 1;
    printf("Delta file:  %s (%s)\n", deltaPath.c_str(), FmtSize(deltaBuf.size()).c_str());

    // Read source file (optional for self-contained patches)
    std::vector<BYTE> srcBuf;
    if (!srcPath.empty()) {
        if (!ReadEntireFile(srcPath, srcBuf)) return 1;
        printf("Source file: %s (%s)\n", srcPath.c_str(), FmtSize(srcBuf.size()).c_str());
    } else {
        printf("Source file: (none - self-contained patch)\n");
    }

    // Validate delta structure
    auto val = ValidateDelta(deltaBuf);
    if (!val.valid) {
        CPrintf(Color::Red, "Error: Invalid delta file");
        if (val.crcPrefixed)
            printf(" (CRC32 mismatch: expected 0x%08X, got 0x%08X)",
                   val.crcExpected, val.crcActual);
        printf("\n");
        return 1;
    }
    printf("Format:      %s\n", val.format.c_str());

    // Build apply flags
    DELTA_FLAG_TYPE flags = DF_NONE;
    if (allowPA19) flags |= DF_ALLOW_PA19;

    printf("\nApplying delta...\n");

    std::vector<BYTE> output;
    const BYTE* srcData = srcBuf.empty() ? nullptr : srcBuf.data();
    size_t srcSize = srcBuf.size();

    if (!api.ApplyDelta(flags, srcData, srcSize, val.data, val.size, output)) {
        DWORD err = GetLastError();
        CPrintf(Color::Red, "Error: ApplyDeltaB failed (0x%08X: %s)\n",
                err, Win32Error(err).c_str());
        return 1;
    }

    if (output.empty()) {
        CPrintf(Color::Red, "Error: Delta produced empty output\n");
        return 1;
    }

    // Recursive patching: keep applying if the output is itself a delta
    if (recursive) {
        for (int iter = 1; iter <= 100 && LooksLikeDelta(output); iter++) {
            printf("  Recursive iteration %d...\n", iter);
            auto iv = ValidateDelta(output);
            std::vector<BYTE> next;
            if (!api.ApplyDelta(flags, srcData, srcSize,
                                iv.data, iv.size, next) || next.empty()) {
                CPrintf(Color::Yellow,
                    "  Warning: Iteration %d failed, using previous result\n", iter);
                break;
            }
            output = std::move(next);
        }
    }

    // Write output
    if (!WriteEntireFile(outPath, output.data(), output.size())) return 1;

    printf("\n");
    CPrintf(Color::Green, "[+] Success! ");
    printf("Output: %s (%s)\n", outPath.c_str(), FmtSize(output.size()).c_str());
    return 0;
}

// ============================================================
//  Command: info
//
//  Extract and display detailed metadata from a delta file
//  header, including file type, target size, timestamps,
//  hash/checksum, and all transform flags.
// ============================================================

static int CmdInfo(DeltaAPI& api, const std::string& deltaPath) {
    if (!api.HasInfo()) {
        CPrintf(Color::Red,
            "Error: GetDeltaInfoB not available in loaded DLL\n"
            "  This function requires msdelta.dll (Windows Vista+)\n");
        return 1;
    }

    std::vector<BYTE> buf;
    if (!ReadEntireFile(deltaPath, buf)) return 1;

    auto val = ValidateDelta(buf);

    printf("\n");
    CPrintf(Color::Cyan, "Delta File Information\n");
    PrintSep();

    printf("  %-18s %s\n", "File:",      deltaPath.c_str());
    printf("  %-18s %s\n", "File Size:",  FmtSize(buf.size()).c_str());
    printf("  %-18s %s\n", "Format:",     val.format.c_str());

    if (val.crcPrefixed) {
        char crcStr[80];
        snprintf(crcStr, sizeof(crcStr), "0x%08X %s",
                 val.crcExpected, val.valid ? "(valid)" : "(MISMATCH!)");
        printf("  %-18s ", "CRC32:");
        if (val.valid) CPrintf(Color::Green, "%s\n", crcStr);
        else           CPrintf(Color::Red,   "%s\n", crcStr);
    }

    if (!val.valid) {
        CPrintf(Color::Red, "\n  Validation failed - cannot extract metadata.\n");
        return 1;
    }

    // Extract header info via MSDelta API
    DELTA_HEADER_INFO info{};
    if (!api.GetInfo(val.data, val.size, info)) {
        DWORD err = GetLastError();
        CPrintf(Color::Yellow, "\n  GetDeltaInfoB failed (0x%08X: %s)\n",
                err, Win32Error(err).c_str());
        return 1;
    }

    PrintDash();
    CPrintf(Color::Cyan, "  Metadata\n");
    PrintDash();

    printf("  %-18s %s (0x%llX)\n", "File Type Set:",
           FmtFileTypeSet(info.FileTypeSet).c_str(),
           static_cast<unsigned long long>(info.FileTypeSet));
    printf("  %-18s %s (0x%llX)\n", "File Type:",
           FmtFileType(info.FileType),
           static_cast<unsigned long long>(info.FileType));
    printf("  %-18s %s\n", "Target Size:",    FmtSize(info.TargetSize).c_str());
    printf("  %-18s %s\n", "Target Time:",    FmtFileTime(info.TargetFileTime).c_str());
    printf("  %-18s %s (0x%04X)\n", "Hash Algorithm:",
           FmtHashAlg(info.TargetHashAlgId), info.TargetHashAlgId);
    printf("  %-18s %s\n", "Target Hash:",    FmtHash(info.TargetHash).c_str());

    // Display flags with descriptions
    PrintDash();
    printf("  Flags: 0x%016llX\n", static_cast<unsigned long long>(info.Flags));

    if (info.Flags == DF_NONE) {
        printf("    (none)\n");
    } else {
        for (int i = 0; i < g_numDeltaFlags; i++) {
            if (info.Flags & g_deltaFlags[i].value) {
                CPrintf(Color::Green, "    [+] ");
                printf("%-42s %s\n",
                       g_deltaFlags[i].name,
                       g_deltaFlags[i].description);
            }
        }
        // Check for any unknown/undocumented flags
        DELTA_FLAG_TYPE known = 0;
        for (int i = 0; i < g_numDeltaFlags; i++)
            known |= g_deltaFlags[i].value;
        DELTA_FLAG_TYPE unknown = info.Flags & ~known;
        if (unknown) {
            CPrintf(Color::Yellow, "    [?] ");
            printf("Unknown flags: 0x%016llX\n",
                   static_cast<unsigned long long>(unknown));
        }
    }

    PrintSep();
    return 0;
}

// ============================================================
//  Command: validate
//
//  Validate delta file integrity by checking the structure
//  (PA signature or CRC32 prefix) and attempting to parse
//  the header with GetDeltaInfoB.
// ============================================================

static int CmdValidate(DeltaAPI& api, const std::string& deltaPath) {
    std::vector<BYTE> buf;
    if (!ReadEntireFile(deltaPath, buf)) return 1;

    printf("\nValidating: %s (%s)\n", deltaPath.c_str(), FmtSize(buf.size()).c_str());
    PrintDash();

    auto val = ValidateDelta(buf);

    printf("  %-18s %s\n", "Format:", val.format.c_str());

    if (!val.sig.empty())
        printf("  %-18s %s\n", "Signature:", val.sig.c_str());

    if (val.crcPrefixed) {
        printf("  %-18s 0x%08X\n", "CRC32 Expected:", val.crcExpected);
        printf("  %-18s 0x%08X\n", "CRC32 Actual:",   val.crcActual);
        printf("  %-18s ", "CRC32 Check:");
        if (val.valid)
            CPrintf(Color::Green, "PASS\n");
        else
            CPrintf(Color::Red,   "FAIL\n");

        if (!val.valid) {
            PrintDash();
            CPrintf(Color::Red, "  [X] Invalid delta file (CRC32 mismatch)\n\n");
            return 1;
        }
    }

    // Try parsing the header to verify the delta is well-formed
    bool parseable = false;
    DELTA_HEADER_INFO info{};

    if (api.HasInfo()) {
        parseable = api.GetInfo(val.data, val.size, info);
        printf("  %-18s ", "Parseable:");
        if (parseable) {
            CPrintf(Color::Green, "Yes\n");
            printf("  %-18s %s\n", "Target Size:",    FmtSize(info.TargetSize).c_str());
            printf("  %-18s %s\n", "File Type:",       FmtFileType(info.FileType));
            printf("  %-18s %s\n", "Hash Algorithm:",  FmtHashAlg(info.TargetHashAlgId));
            printf("  %-18s %s\n", "Target Hash:",     FmtHash(info.TargetHash).c_str());
        } else {
            DWORD err = GetLastError();
            CPrintf(Color::Yellow, "No (0x%08X: %s)\n", err, Win32Error(err).c_str());
        }
    } else {
        printf("  %-18s %s\n", "Parseable:", "(GetDeltaInfoB unavailable)");
    }

    PrintDash();

    if (val.valid && (parseable || !api.HasInfo()))
        CPrintf(Color::Green, "  [+] Valid delta file\n");
    else if (val.valid)
        CPrintf(Color::Yellow, "  [~] Structurally valid but not parseable by MSDelta\n");
    else
        CPrintf(Color::Red, "  [X] Invalid delta file\n");

    printf("\n");
    return val.valid ? 0 : 1;
}

// ============================================================
//  Command: signature
//
//  Calculate a normalized file signature using MSDelta's
//  GetDeltaSignatureB. Supports various hash algorithms
//  and optional comparison between two files.
// ============================================================

static DWORD ParseAlg(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "crc32")  return 32;
    if (lower == "md5")    return 0x8003;
    if (lower == "sha1")   return 0x8004;
    if (lower == "sha256") return 0x800C;
    if (lower == "none")   return 0;
    return 32;  // default
}

static DELTA_FILE_TYPE ParseFTS(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "raw")    return DFTS_RAW_ONLY;
    if (lower == "exe1")   return DFTS_EXECUTABLES_1;
    if (lower == "exe2")   return DFTS_EXECUTABLES_2;
    if (lower == "latest") return DFTS_EXECUTABLES_2;
    return DFTS_EXECUTABLES_2;  // default
}

static int CmdSignature(DeltaAPI& api, const std::string& filePath,
                         const std::string& algStr, const std::string& ftsStr,
                         const std::string& cmpPath) {
    if (!api.HasSig()) {
        CPrintf(Color::Red,
            "Error: GetDeltaSignatureB not available in loaded DLL\n"
            "  This function requires msdelta.dll (Windows Vista+)\n");
        return 1;
    }

    DWORD alg = ParseAlg(algStr);
    DELTA_FILE_TYPE fts = ParseFTS(ftsStr);

    // Read primary file
    std::vector<BYTE> buf1;
    if (!ReadEntireFile(filePath, buf1)) return 1;

    printf("\n");
    CPrintf(Color::Cyan, "File Signature\n");
    PrintSep();

    printf("  %-14s %s\n", "File:",      filePath.c_str());
    printf("  %-14s %s\n", "Size:",      FmtSize(buf1.size()).c_str());
    printf("  %-14s %s\n", "Algorithm:", FmtHashAlg(alg));
    printf("  %-14s %s\n", "File Type:", FmtFileTypeSet(fts).c_str());

    DELTA_HASH h1{};
    if (!api.GetSignature(fts, alg, buf1.data(), buf1.size(), h1)) {
        DWORD err = GetLastError();
        CPrintf(Color::Red, "  Error: GetDeltaSignatureB failed (0x%08X: %s)\n",
                err, Win32Error(err).c_str());
        return 1;
    }
    printf("  %-14s %s\n", "Signature:", FmtHash(h1).c_str());

    // Compare mode: calculate signature for second file and compare
    if (!cmpPath.empty()) {
        std::vector<BYTE> buf2;
        if (!ReadEntireFile(cmpPath, buf2)) return 1;

        PrintDash();
        printf("  %-14s %s\n", "Compare:", cmpPath.c_str());
        printf("  %-14s %s\n", "Size:",    FmtSize(buf2.size()).c_str());

        DELTA_HASH h2{};
        if (!api.GetSignature(fts, alg, buf2.data(), buf2.size(), h2)) {
            DWORD err = GetLastError();
            CPrintf(Color::Red, "  Error: GetDeltaSignatureB failed (0x%08X: %s)\n",
                    err, Win32Error(err).c_str());
            return 1;
        }
        printf("  %-14s %s\n", "Signature:", FmtHash(h2).c_str());

        PrintDash();
        bool match = (h1.HashSize == h2.HashSize) &&
                     (memcmp(h1.HashValue, h2.HashValue, h1.HashSize) == 0);
        if (match)
            CPrintf(Color::Green, "  [+] Signatures MATCH\n");
        else
            CPrintf(Color::Yellow, "  [-] Signatures DO NOT match\n");
    }

    PrintSep();
    return 0;
}

// ============================================================
//  CLI Argument Parser & Help
// ============================================================

static void PrintUsage(const char* exe) {
    printf("\n");
    CPrintf(Color::Cyan, "deltacli");
    printf(" - Delta Compression CLI Tool\n\n");
    printf("Usage: %s <command> [options]\n\n", exe ? exe : "deltacli");

    CPrintf(Color::White, "Commands:\n");
    printf("  apply       Apply a delta patch to produce a target file\n");
    printf("  info        Display delta file metadata and header information\n");
    printf("  validate    Validate delta file integrity and structure\n");
    printf("  signature   Calculate normalized file signature\n");
    printf("  help        Show this help message\n\n");

    CPrintf(Color::White, "Apply Options:\n");
    printf("  -d, --delta <file>     Delta/patch file (required)\n");
    printf("  -s, --source <file>    Source/base file (optional for self-contained patches)\n");
    printf("  -o, --output <file>    Output target file (required)\n");
    printf("  -r, --recursive        Apply patches recursively until non-patch output\n");
    printf("  --allow-legacy         Allow PA19 (legacy PatchAPI) format\n\n");

    CPrintf(Color::White, "Info Options:\n");
    printf("  -d, --delta <file>     Delta file to inspect (required)\n\n");

    CPrintf(Color::White, "Validate Options:\n");
    printf("  -d, --delta <file>     Delta file to validate (required)\n\n");

    CPrintf(Color::White, "Signature Options:\n");
    printf("  -f, --file <file>      File to calculate signature for (required)\n");
    printf("  -a, --algorithm <alg>  Hash algorithm: crc32, md5, sha1, sha256, none\n");
    printf("                         (default: crc32)\n");
    printf("  -t, --filetype <type>  File type set: raw, exe1, exe2, latest\n");
    printf("                         (default: latest)\n");
    printf("  --compare <file>       Compare signature with another file\n\n");

    CPrintf(Color::White, "Examples:\n");
    printf("  %s apply -d patch.pa_ -s old.dll -o new.dll\n", exe);
    printf("  %s apply -d manifest.pa_ -o manifest.xml\n", exe);
    printf("  %s apply -d patch.pa_ -s old.dll -o new.dll -r\n", exe);
    printf("  %s info -d patch.pa_\n", exe);
    printf("  %s info patch.pa_\n", exe);
    printf("  %s validate -d patch.pa_\n", exe);
    printf("  %s validate patch.pa_\n", exe);
    printf("  %s signature -f kernel32.dll\n", exe);
    printf("  %s signature -f old.dll --compare new.dll\n", exe);
    printf("  %s signature -f file.dll -a md5 -t exe2\n", exe);
    printf("\n");
}

struct Args {
    std::string cmd;
    std::string delta;
    std::string source;
    std::string output;
    std::string file;
    std::string algorithm{"crc32"};
    std::string filetype{"latest"};
    std::string compare;
    bool recursive  = false;
    bool legacy     = false;
    bool help       = false;
};

static Args ParseArgs(int argc, char** argv) {
    Args a;
    if (argc < 2) {
        a.help = true;
        return a;
    }

    a.cmd = argv[1];
    if (a.cmd == "help" || a.cmd == "-h" || a.cmd == "--help" || a.cmd == "/?") {
        a.help = true;
        return a;
    }

    auto next = [&](int& i) -> const char* {
        return (i + 1 < argc) ? argv[++i] : "";
    };

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];

        if      (arg == "-d" || arg == "--delta")     a.delta     = next(i);
        else if (arg == "-s" || arg == "--source")    a.source    = next(i);
        else if (arg == "-o" || arg == "--output")    a.output    = next(i);
        else if (arg == "-f" || arg == "--file")      a.file      = next(i);
        else if (arg == "-a" || arg == "--algorithm") a.algorithm = next(i);
        else if (arg == "-t" || arg == "--filetype")  a.filetype  = next(i);
        else if (arg == "--compare")                  a.compare   = next(i);
        else if (arg == "-r" || arg == "--recursive") a.recursive = true;
        else if (arg == "--allow-legacy")             a.legacy    = true;
        else if (arg == "-h" || arg == "--help")      a.help      = true;
        else {
            // Accept positional argument for convenience
            if ((a.cmd == "validate" || a.cmd == "info") && a.delta.empty())
                a.delta = arg;
            else if (a.cmd == "signature" && a.file.empty())
                a.file = arg;
            else
                CPrintf(Color::Yellow, "Warning: unknown argument '%s'\n", arg.c_str());
        }
    }

    return a;
}

// ============================================================
//  Entry Point
// ============================================================

int main(int argc, char* argv[]) {
    InitConsole();

    Args args = ParseArgs(argc, argv);
    if (args.help) {
        PrintUsage(argv[0]);
        return 0;
    }

    // Initialize Delta API (load DLL)
    DeltaAPI api;
    if (!api.Init()) return 1;

    // Dispatch to the appropriate command handler
    if (args.cmd == "apply") {
        if (args.delta.empty()) {
            CPrintf(Color::Red, "Error: --delta is required for 'apply'\n");
            return 1;
        }
        if (args.output.empty()) {
            CPrintf(Color::Red, "Error: --output is required for 'apply'\n");
            return 1;
        }
        return CmdApply(api, args.delta, args.source, args.output,
                        args.recursive, args.legacy);
    }

    if (args.cmd == "info") {
        if (args.delta.empty()) {
            CPrintf(Color::Red, "Error: --delta is required for 'info'\n");
            return 1;
        }
        return CmdInfo(api, args.delta);
    }

    if (args.cmd == "validate") {
        if (args.delta.empty()) {
            CPrintf(Color::Red, "Error: --delta is required for 'validate'\n");
            return 1;
        }
        return CmdValidate(api, args.delta);
    }

    if (args.cmd == "signature") {
        if (args.file.empty()) {
            CPrintf(Color::Red, "Error: --file is required for 'signature'\n");
            return 1;
        }
        return CmdSignature(api, args.file, args.algorithm, args.filetype, args.compare);
    }

    CPrintf(Color::Red, "Error: Unknown command '%s'\n\n", args.cmd.c_str());
    PrintUsage(argv[0]);
    return 1;
}
