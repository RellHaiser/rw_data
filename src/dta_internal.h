// Internal state and helpers of rw_data.dll (originally all in D:\hd2project\_src\rw_data\rw_data.cpp).
#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#define RW_DATA_BUILD
#define RW_DATA_API
#include "rw_data.h"

class C_DtaRead;

// Archive formats -----------------------------------------------------------------------
//
// ISD0 / ISD1 archive:
//   +0  magic "ISD0" or "ISD1"
//   ISD0: +4  16-byte table header (encrypted): u32 ?, u32 table offset, u32 table size, u32 ?
//   ISD1: +4  20 bytes (encrypted): u32 ?, u32 table offset, u32 table size,
//             u32 table checksum, u32 header checksum (of these 24 bytes with it zeroed)
//   table: S_DtaFileEntry[], sorted by hash, encrypted
//   file:  S_DtaFileHeader (encrypted), the name (encrypted), then
//          ISD0: blocks, each a u32 (low 16 bits = stored size, high 16 = size of the
//                previous block) and the block (first byte = type, see below)
//          ISD1: u32[blockCount] (low 16 bits = stored size, high 16 = checksum),
//                u8[blockCount] block types (encrypted), then the blocks without the type byte
//   Every file is split in 32 KB blocks. Block types: 1 = LZSS, 0 and 2..7 = stored,
//   >= 8 = compressed 16-bit WAV (the first block starts with the 0x2C-byte RIFF header).
//   The key is a 64-bit XOR key (see DecryptBuffer); a header flag says whether the
//   blocks are encrypted too or only the WAV header.

constexpr uint32_t DTA_MAGIC_ISD0 = 0x30445349;   // "ISD0"
constexpr uint32_t DTA_MAGIC_ISD1 = 0x31445349;   // "ISD1"
constexpr uint32_t DTA_BLOCK_SIZE = 0x8000;       // decoded size of a block
constexpr uint32_t DTA_WAV_HEADER_SIZE = 0x2C;
constexpr uint16_t DTA_NAME_ENCRYPTED_BLOCKS = 0x8000;  // S_DtaFileHeader::nameLength flag

// Entry of an archive's file table (0x1C bytes in the archive).
struct S_DtaFileEntry {
    uint32_t hash;          // (name length << 16) | 16-bit sum of the upper-case name's bytes
    uint32_t headerOffset;  // the file's S_DtaFileHeader, followed by its name
    uint32_t dataOffset;    // the first block
    char nameTail[16];      // the last 16 characters of the upper-case name (not terminated)
};
static_assert(sizeof(S_DtaFileEntry) == 0x1C, "file table entries are 0x1C bytes");

// Header of a file in an archive (0x20 bytes, encrypted).
#pragma pack(push, 1)
struct S_DtaFileHeader {
    uint32_t unknown0;
    uint32_t unknown4;
    FILETIME time;
    uint32_t size;
    uint32_t blockCount;
    // ISD0: name length at +0x18. ISD1: +0x18 header checksum (of the header with it
    // zeroed), +0x1C name length, +0x1E checksum of the name and the block tables.
    union {
        struct {
            uint16_t nameLength;
            uint8_t unused1A[6];
        } v0;
        struct {
            uint32_t headerChecksum;
            uint16_t nameLength;
            uint16_t tablesChecksum;
        } v1;
    };
};
#pragma pack(pop)
static_assert(sizeof(S_DtaFileHeader) == 0x20, "file headers are 0x20 bytes");

// A mounted archive (S_ArchiveTable, 0x128 bytes in the original).
struct S_DtaArchiveTable {
    HANDLE file = INVALID_HANDLE_VALUE;
    uint64_t key = 0;
    std::string fileName;
    std::vector<S_DtaFileEntry> entries;
    int version = 0;   // 0 = ISD0, 1 = ISD1
};

// Entry of the archive search order.
struct S_DtaSearchSlot {
    C_DtaRead *archive;
    int table;          // index in g_archiveTables
};

// S_DtaOpenFile::flags
enum : uint32_t {
    DTA_FILE_DISK = 0x1,          // a file on disk (else in an archive)
    DTA_FILE_WRITE = 0x2,         // opened by dtaOpenWrite
    DTA_FILE_TEMP = 0x4,          // written through "<name>.tmp"
    DTA_FILE_WRITE_ERROR = 0x80,  // a write failed: the temporary file is discarded
};

// Read position of an open file; dtaRead works on a copy and stores it back on success.
struct S_DtaCursor {
    uint32_t blockOffset = 0;        // archive: offset of the current block from dataOffset;
                                     // disk: file offset of the buffer
    uint32_t position = 0;
    uint32_t blockPosition = 0;      // read position in the decoded block / buffer
    uint32_t block = 0;              // archive: current block
    uint32_t blockSize = 0;          // archive: stored size of the current block
    uint32_t previousBlockSize = 0;  // ISD0: stored size of the block before it
    uint32_t bufferSize = 0;         // bytes in the buffer
};

// An open file (0x60 bytes in the original).
struct S_DtaOpenFile {
    HANDLE file = INVALID_HANDLE_VALUE;  // INVALID_HANDLE_VALUE marks a free slot; for
                                         // archived files the archive's handle
    uint32_t flags = 0;
    FILETIME time = {};                  // archived files: the time stored in the archive
    uint32_t size = 0;
    uint32_t dataOffset = 0;             // archived files: offset of the first block
    uint32_t blockCount = 0;
    S_DtaCursor cursor;
    uint64_t key = 0;                    // archived files: the archive's key
    std::string tempFileName;            // DTA_FILE_TEMP: "<name>.tmp"
    std::vector<uint8_t> buffer;         // 32 KB: the decoded block / the file data
    std::vector<uint8_t> wavHeader;      // RIFF header of compressed WAV files (else empty)
    bool blockTables = false;            // ISD1: the block sizes are in the tables below
    std::vector<uint16_t> blockSizes;
    std::vector<uint16_t> blockChecksums;
    std::vector<uint8_t> blockTypes;
    bool bufferValid = false;
    bool blocksEncrypted = false;        // whole blocks are encrypted, not only the WAV header

    bool IsFree() const { return file == INVALID_HANDLE_VALUE; }
};

// A file log (S_FileLog, 0x28 bytes in the original).
struct S_DtaFileLog {
    int handle = -1;                   // dta write handle, -1 once closed
    std::vector<int> extensions;       // packed upper-case extensions (see PackExtension)
    std::vector<std::string> dirs;     // upper-case directory prefixes
    std::string pathBefore;            // written before every name
};

// Global state --------------------------------------------------------------------------

// The DLL serialises every call through one critical section.
class C_CriticalSection {
public:
    C_CriticalSection() { InitializeCriticalSection(&m_section); }    // 0x1000964b
    ~C_CriticalSection() { DeleteCriticalSection(&m_section); }       // 0x1000967f
    C_CriticalSection(const C_CriticalSection &) = delete;
    C_CriticalSection &operator=(const C_CriticalSection &) = delete;
    void Enter() { EnterCriticalSection(&m_section); }
    void Leave() { LeaveCriticalSection(&m_section); }

private:
    CRITICAL_SECTION m_section;
};

// Scoped lock of g_lock; Unlock releases it early (before calling the error callback,
// like the original).
class C_DtaLock {
public:
    C_DtaLock();
    ~C_DtaLock();
    C_DtaLock(const C_DtaLock &) = delete;
    C_DtaLock &operator=(const C_DtaLock &) = delete;
    void Unlock();

private:
    bool m_locked = true;
};

// Counts the archives and their references; reports leaks when the DLL unloads.
struct S_DtaLeakCounter {
    int references = 0;
    int objects = 0;
    bool report = false;   // dtaDumpMemoryLeaks
    ~S_DtaLeakCounter();   // 0x100096ee
};

// State of FQL recording and playback.
struct S_DtaFql {
    static constexpr uint32_t BLOCK_SIZE = 0x20000;         // uncompressed block, 8-byte header
    static constexpr uint32_t BLOCK_HEADER_SIZE = 8;
    static constexpr uint32_t COMPRESSED_BUFFER_SIZE = 0x20028;

    // playback (dtaFQLBegin)
    HANDLE readFile = nullptr;
    std::vector<uint8_t> readBuffer;        // the current block, decompressed
    int readSize = 0;
    int readPosition = 0;
    std::vector<uint8_t> compressedBuffer;  // the current block as stored
    char fileName[MAX_PATH] = {};           // reported to the error callback
    // recording (dtaCreateFQL)
    HANDLE writeFile = nullptr;
    std::vector<uint8_t> writeBuffer;
    uint32_t writePosition = BLOCK_HEADER_SIZE;
    DWORD writeTotal = 0;                   // bytes written to the file
    // Closed by dtaFQLEnd / dtaCloseFQL but never opened in this build.
    HANDLE unusedReadFile = nullptr;
    HANDLE unusedWriteFile = nullptr;

    bool Active() const { return readFile != nullptr || writeFile != nullptr; }
};

extern std::vector<S_DtaOpenFile> g_openFiles;        // 0x1004374c, indexed by handle
extern std::vector<S_DtaArchiveTable> g_archiveTables;// 0x10043780
extern std::vector<S_DtaSearchSlot> g_searchOrder;    // 0x100437a0
extern std::vector<S_DtaFileLog> g_fileLogs;          // 0x100438b4
extern std::vector<int> g_fqlExtensionFilter;         // 0x100478c8
extern std::vector<int> g_fqlHandles;                 // 0x10043790, open files being recorded
extern C_CriticalSection g_lock;                      // 0x10043768
extern S_DtaLeakCounter g_leaks;                      // 0x1004375c
extern dtaErrorCallback g_errorCallback;              // 0x100478d8
extern bool g_preferArchives;                         // 0x100478dc
extern S_DtaFql g_fql;                                // 0x100478e0..0x1004790b, 0x100437b0

// Helpers -------------------------------------------------------------------------------

// dta_crypt.cpp
void DecryptBuffer(void *data, uint32_t size, uint64_t key);                 // 0x10009bf3
void EncryptBuffer(void *data, uint32_t size, uint64_t key);                 // 0x10009d24
uint16_t Checksum16(const void *data, uint32_t size, uint16_t seed);         // 0x10009e97
constexpr uint16_t CHECKSUM_SEED = 0xFF;

// dta_lzss.cpp. The decoders take the room at `dst` (an addition of the port: the original
// trusted the data); they return the decoded size.
uint32_t LzssDecompress(const uint8_t *src, uint8_t *dst, uint32_t srcSize,
                        uint32_t dstCapacity);                               // 0x1000ea20
uint32_t LzssCompress(const uint8_t *src, uint8_t *dst, uint32_t size);      // 0x1000ecd0

// dta_wav.cpp
uint32_t WavDecompress(const uint8_t *src, uint8_t *dst, uint32_t srcSize,
                       const uint8_t *wavHeader, uint32_t dstCapacity);      // 0x100097f7

// dta_open.cpp
int OpenFromArchives(const char *fileName);                                  // 0x1000c110
int OpenFromDisk(const char *fileName);                                      // 0x1000dea0
// Puts an open file in the first free slot (or a new one); returns its handle.
int StoreOpenFile(S_DtaOpenFile file);
// Index in g_archiveTables of the table of an archive file (searched from the end), or -1.
int FindArchiveTable(HANDLE file);
void UpperCase(char *text);
void UpperCase(std::string &text);
// Packs the extension of a name (up to the last 3 characters after the last '.') into an int.
int PackExtension(const char *name);
// Calls the error callback for an error in an archived file.
void ReportArchiveError(HANDLE archiveFile, int error);

// dta_fql.cpp
bool FqlRead(void *data, uint32_t size);                                     // 0x10002535
bool FqlWrite(const void *data, uint32_t size);                              // 0x10002129
bool FqlIsExtensionFiltered(const char *fileName);                           // 0x1000e920
void FqlRecordOpen(int handle, const char *fileName);                        // 0x1000e880

// dta_filelog.cpp
void FileLogRecord(const char *fileName);                                    // 0x1000e3d0

// MSVC's rand() (the DLL had its own copy of the C runtime): per thread, seeded with 1.
int DtaRand();
