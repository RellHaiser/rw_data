// FQL files: the archive data read during a load, recorded in order into one file
// (dtaCreateFQL .. dtaCloseFQL) and played back from it (dtaFQLBegin .. dtaFQLEnd), so a
// later load reads one file sequentially instead of seeking through the archives.
//
// File: u32 file size, u16 checksum of that u32, then blocks. A block is a u32 stored
// size and LZSS chunks (u32 size + stream) that decompress to up to 128 KB:
//   u32 used size (including this 8-byte header), u32 checksum (computed with it zeroed),
//   then records: u32 size + data (a record may continue in the next blocks).
// Only ISD1 archives are recorded: the file headers, names, block tables and WAV headers
// read by OpenFromArchives, and the data read by dtaRead.
#include "dta_internal.h"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace {

constexpr uint32_t CHUNK_SIZE = 0x8000;
constexpr uint32_t BLOCK_PAYLOAD = S_DtaFql::BLOCK_SIZE - S_DtaFql::BLOCK_HEADER_SIZE;

// LZSS output of one chunk (0x1003b748). LzssCompress may write a few bytes past the
// chunk size before it falls back to storing; the original's buffer was 0x8004 bytes.
uint8_t g_compressedChunk[CHUNK_SIZE + 16];

uint32_t Load32(const uint8_t *p)
{
    uint32_t value;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

void Store32(uint8_t *p, uint32_t value)
{
    std::memcpy(p, &value, sizeof(value));
}

void ReportFqlError(const char *fileName, int error)
{
    if (g_errorCallback)
        g_errorCallback(nullptr, fileName, error);
}

// Compresses the recording buffer into the file as one block. Returns the result of the
// last write.
bool FqlFlushBlock()   // 0x10001e7e
{
    uint8_t *block = g_fql.writeBuffer.data();
    const uint32_t used = g_fql.writePosition;
    Store32(block, used);
    Store32(block + 4, 0);
    Store32(block + 4, Checksum16(block, used, CHECKSUM_SEED));

    const HANDLE file = g_fql.writeFile;
    DWORD written;
    const DWORD start = SetFilePointer(file, 0, nullptr, FILE_CURRENT);
    uint32_t total = 0;
    bool ok = WriteFile(file, &total, sizeof(total), &written, nullptr) != FALSE;   // patched below

    auto writeChunk = [&](uint32_t offset, uint32_t size) {
        const uint32_t packed = LzssCompress(block + offset, g_compressedChunk, size);
        WriteFile(file, &packed, sizeof(packed), &written, nullptr);
        ok = WriteFile(file, g_compressedChunk, packed, &written, nullptr) != FALSE;
        total += 4 + packed;
    };
    const uint32_t chunks = used / CHUNK_SIZE;
    const uint32_t rest = used - chunks * CHUNK_SIZE;
    uint32_t offset = 0;
    for (uint32_t i = 0; i < chunks; ++i, offset += CHUNK_SIZE)
        writeChunk(offset, CHUNK_SIZE);
    if (rest != 0)
        writeChunk(offset, rest);

    SetFilePointer(file, static_cast<LONG>(start), nullptr, FILE_BEGIN);
    ok = WriteFile(file, &total, sizeof(total), &written, nullptr) != FALSE;
    SetFilePointer(file, 0, nullptr, FILE_END);
    g_fql.writeTotal += 4 + total;
    g_fql.writePosition = S_DtaFql::BLOCK_HEADER_SIZE;
    return ok;
}

// Reads and decompresses the next block. Errors are reported but the block is used anyway.
bool FqlReadBlock()   // 0x100022e3
{
    bool ok = true;
    const HANDLE file = g_fql.readFile;
    uint32_t stored = 0;
    DWORD read = 0;
    if (!ReadFile(file, &stored, sizeof(stored), &read, nullptr)) {
        ok = false;
        ReportFqlError(g_fql.fileName, DTA_ERROR_READ);
    }
    if (read != sizeof(stored)) {
        ok = false;
        ReportFqlError(g_fql.fileName, DTA_ERROR_SIZE);
    }
    // (The original read `stored` bytes whatever the size of the buffer.)
    const uint32_t wanted = std::min<uint32_t>(stored, S_DtaFql::COMPRESSED_BUFFER_SIZE);
    uint8_t *compressed = g_fql.compressedBuffer.data();
    read = 0;
    if (!ReadFile(file, compressed, wanted, &read, nullptr)) {
        ok = false;
        ReportFqlError(g_fql.fileName, DTA_ERROR_READ);
    }
    if (read != stored) {
        ok = false;
        ReportFqlError(g_fql.fileName, DTA_ERROR_SIZE);
    }

    uint8_t *block = g_fql.readBuffer.data();
    uint32_t out = 0;
    for (uint32_t in = 0; in < wanted;) {
        // (Bounds checks on corrupt data are additions of the port.)
        if (in + 4 > wanted || out > S_DtaFql::BLOCK_SIZE)
            break;
        const uint32_t length = Load32(compressed + in);
        in += 4;
        if (length == 0 || in + length > wanted)
            break;
        const uint32_t room = static_cast<uint32_t>(g_fql.readBuffer.size()) - out;
        if (compressed[in] == 1) {
            out += LzssDecompress(compressed + in, block + out, length, room);
        } else {
            const uint32_t size = std::min(length - 1, room);
            std::memcpy(block + out, compressed + in + 1, size);
            out += size;
        }
        in += length;
    }

    g_fql.readSize = static_cast<int>(Load32(block));
    const uint32_t checksum = Load32(block + 4);
    Store32(block + 4, 0);
    const uint32_t used = std::min<uint32_t>(static_cast<uint32_t>(g_fql.readSize), S_DtaFql::BLOCK_SIZE);
    // (The original called the callback without checking it for null.)
    if (checksum != Checksum16(block, used, CHECKSUM_SEED))
        ReportFqlError(g_fql.fileName, DTA_ERROR_CHECKSUM);
    g_fql.readPosition = static_cast<int>(S_DtaFql::BLOCK_HEADER_SIZE);
    return ok;
}

void FreeReadBuffers()
{
    g_fql.readBuffer.clear();
    g_fql.readBuffer.shrink_to_fit();
    g_fql.compressedBuffer.clear();
    g_fql.compressedBuffer.shrink_to_fit();
}

// Never referenced in the original (0x100026d0): an earlier dtaFQLBegin that kept going
// after a failed read.
[[maybe_unused]] void LegacyFqlOpen(const char *fileName)
{
    if (fileName == nullptr || g_fql.readFile != nullptr)
        return;
    std::strncpy(g_fql.fileName, fileName, sizeof(g_fql.fileName) - 1);
    g_fql.readPosition = 0;
    g_fql.readSize = 0;
    const HANDLE file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        ReportFqlError(fileName, DTA_ERROR_OPEN);
        return;
    }
    g_fql.readFile = file;
    g_fql.readBuffer.assign(S_DtaFql::BLOCK_SIZE + 0x10000, 0);
    g_fql.compressedBuffer.assign(S_DtaFql::COMPRESSED_BUFFER_SIZE, 0);

    // Every check runs, even after the file has been dropped.
    auto drop = [&](int error) {
        ReportFqlError(fileName, error);
        if (g_fql.readFile != nullptr)
            CloseHandle(g_fql.readFile);
        g_fql.readFile = nullptr;
        FreeReadBuffers();
    };
    const DWORD fileSize = SetFilePointer(file, 0, nullptr, FILE_END);
    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    uint32_t total = 0;
    uint16_t checksum = 0;
    DWORD read = 0;
    if (!ReadFile(g_fql.readFile, &total, sizeof(total), &read, nullptr))
        drop(DTA_ERROR_READ);
    if (read != sizeof(total))
        drop(DTA_ERROR_SIZE);
    read = 0;
    if (!ReadFile(g_fql.readFile, &checksum, sizeof(checksum), &read, nullptr))
        drop(DTA_ERROR_READ);
    if (read != sizeof(checksum))
        drop(DTA_ERROR_SIZE);
    if (g_errorCallback) {
        if (checksum != Checksum16(&total, sizeof(total), CHECKSUM_SEED))
            ReportFqlError(fileName, DTA_ERROR_CHECKSUM);
        if (total != fileSize)
            ReportFqlError(fileName, DTA_ERROR_SIZE);
    }
}

// Never referenced in the original (0x10002ba9): the same as dtaFQLEnd.
[[maybe_unused]] void LegacyFqlClose()
{
    dtaFQLEnd();
}

} // namespace

bool FqlWrite(const void *data, uint32_t size)   // 0x10002129
{
    const uint8_t *bytes = static_cast<const uint8_t *>(data);
    uint8_t *block = g_fql.writeBuffer.data();
    bool ok = true;
    // The record's size never straddles two blocks.
    if (S_DtaFql::BLOCK_SIZE - g_fql.writePosition < 4)
        ok = FqlFlushBlock();
    Store32(block + g_fql.writePosition, size);
    g_fql.writePosition += 4;

    const uint32_t room = S_DtaFql::BLOCK_SIZE - g_fql.writePosition;
    if (size <= room) {
        std::memcpy(block + g_fql.writePosition, bytes, size);
        g_fql.writePosition += size;
        return ok;
    }

    std::memcpy(block + g_fql.writePosition, bytes, room);
    g_fql.writePosition += room;
    ok = FqlFlushBlock();
    uint32_t done = room;
    uint32_t left = size - room;
    for (uint32_t full = left / BLOCK_PAYLOAD; full != 0; --full) {
        std::memcpy(block + g_fql.writePosition, bytes + done, BLOCK_PAYLOAD);
        done += BLOCK_PAYLOAD;
        g_fql.writePosition += BLOCK_PAYLOAD;
        ok = FqlFlushBlock();
    }
    left %= BLOCK_PAYLOAD;
    if (left != 0) {
        std::memcpy(block + g_fql.writePosition, bytes + done, left);
        g_fql.writePosition += left;
    }
    return ok;
}

bool FqlRead(void *data, uint32_t size)   // 0x10002535
{
    uint8_t *bytes = static_cast<uint8_t *>(data);
    bool ok = true;
    if (g_fql.readSize - g_fql.readPosition < 1)
        ok = FqlReadBlock();
    const uint32_t recorded = Load32(g_fql.readBuffer.data() + g_fql.readPosition);
    g_fql.readPosition += 4;
    // The playback must ask for exactly what was recorded ("temp==buff_size", rw_data.cpp line 306).
    assert(recorded == size && "temp==buff_size");
    (void)recorded;

    uint32_t available = static_cast<uint32_t>(g_fql.readSize - g_fql.readPosition);
    if (size <= available) {
        std::memcpy(bytes, g_fql.readBuffer.data() + g_fql.readPosition, size);
        g_fql.readPosition += static_cast<int>(size);
        return ok;
    }

    std::memcpy(bytes, g_fql.readBuffer.data() + g_fql.readPosition, available);
    uint32_t done = available;
    uint32_t left = size - available;
    while (left != 0) {
        ok = FqlReadBlock();
        available = static_cast<uint32_t>(g_fql.readSize - g_fql.readPosition);
        if (available < left) {
            std::memcpy(bytes + done, g_fql.readBuffer.data() + g_fql.readPosition, available);
            done += available;
            left -= available;
        } else {
            std::memcpy(bytes + done, g_fql.readBuffer.data() + g_fql.readPosition, left);
            g_fql.readPosition += static_cast<int>(left);
            left = 0;
        }
    }
    return ok;
}

bool FqlIsExtensionFiltered(const char *fileName)   // 0x1000e920
{
    const int extension = PackExtension(fileName);
    return std::find(g_fqlExtensionFilter.begin(), g_fqlExtensionFilter.end(), extension) !=
           g_fqlExtensionFilter.end();
}

// Marks an open file as recorded / played back (`fileName` is upper case).
void FqlRecordOpen(int handle, const char *fileName)   // 0x1000e880
{
    if (FqlIsExtensionFiltered(fileName))
        return;
    if (std::find(g_fqlHandles.begin(), g_fqlHandles.end(), handle) == g_fqlHandles.end())
        g_fqlHandles.push_back(handle);
}

extern "C" {

// Unlike the other functions, the original does not take the lock here.
RW_DATA_API bool RW_DATA_CALL dtaFQLBegin(const char *fileName)   // 0x10002c96
{
    if (fileName == nullptr || g_fql.readFile != nullptr)
        return false;
    // (The original strcpy'd the name into a 260-byte buffer.)
    std::strncpy(g_fql.fileName, fileName, sizeof(g_fql.fileName) - 1);
    g_fql.fileName[sizeof(g_fql.fileName) - 1] = '\0';
    g_fql.readPosition = 0;
    g_fql.readSize = 0;

    const HANDLE file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        ReportFqlError(fileName, DTA_ERROR_OPEN);
        return false;
    }
    g_fql.readFile = file;
    // Slack after the block: LzssDecompress of a corrupt chunk may run past 128 KB.
    g_fql.readBuffer.assign(S_DtaFql::BLOCK_SIZE + 0x10000, 0);
    g_fql.compressedBuffer.assign(S_DtaFql::COMPRESSED_BUFFER_SIZE, 0);

    // The error callbacks below were not checked for null in the original.
    auto fail = [&](int error) {
        ReportFqlError(fileName, error);
        CloseHandle(file);
        g_fql.readFile = nullptr;
        FreeReadBuffers();
        return false;
    };
    const DWORD fileSize = SetFilePointer(file, 0, nullptr, FILE_END);
    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    uint32_t total;
    DWORD read;
    if (!ReadFile(file, &total, sizeof(total), &read, nullptr))
        return fail(DTA_ERROR_READ);
    if (read != sizeof(total))
        return fail(DTA_ERROR_SIZE);
    uint16_t checksum;
    if (!ReadFile(file, &checksum, sizeof(checksum), &read, nullptr))
        return fail(DTA_ERROR_READ);
    if (read != sizeof(checksum))
        return fail(DTA_ERROR_SIZE);
    if (g_errorCallback) {
        if (checksum != Checksum16(&total, sizeof(total), CHECKSUM_SEED))
            ReportFqlError(fileName, DTA_ERROR_CHECKSUM);
        if (total != fileSize)
            ReportFqlError(fileName, DTA_ERROR_SIZE);
    }
    return true;
}

RW_DATA_API void RW_DATA_CALL dtaFQLEnd()   // 0x10003186
{
    if (g_fql.readFile != nullptr)
        CloseHandle(g_fql.readFile);
    g_fql.readFile = nullptr;
    if (g_fql.unusedReadFile != nullptr)
        CloseHandle(g_fql.unusedReadFile);
    g_fql.unusedReadFile = nullptr;
    g_fqlHandles.clear();
    FreeReadBuffers();
    g_fql.readPosition = 0;
    g_fql.readSize = 0;
}

RW_DATA_API bool RW_DATA_CALL dtaCreateFQL(const char *fileName)   // 0x10009234
{
    C_DtaLock lock;
    if (g_fql.writeFile != nullptr)
        return false;
    g_fql.writeTotal = 0;
    g_fql.writePosition = S_DtaFql::BLOCK_HEADER_SIZE;
    const HANDLE file = CreateFileA(fileName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    g_fql.writeFile = file;
    // Two bytes of slack: LzssCompress reads past the end of the data it compresses.
    g_fql.writeBuffer.assign(S_DtaFql::BLOCK_SIZE + 2, 0);
    // Room for the header (the size and its checksum), written by dtaCloseFQL.
    WriteFile(file, g_fql.writeBuffer.data(), 6, &g_fql.writeTotal, nullptr);
    return true;
}

RW_DATA_API void RW_DATA_CALL dtaCloseFQL()   // 0x10009356
{
    C_DtaLock lock;
    if (g_fql.writeFile == nullptr)
        return;
    if (g_fql.writePosition != S_DtaFql::BLOCK_HEADER_SIZE)
        FqlFlushBlock();
    DWORD written;
    SetFilePointer(g_fql.writeFile, 0, nullptr, FILE_BEGIN);
    WriteFile(g_fql.writeFile, &g_fql.writeTotal, sizeof(g_fql.writeTotal), &written, nullptr);
    const uint16_t checksum = Checksum16(&g_fql.writeTotal, sizeof(g_fql.writeTotal), CHECKSUM_SEED);
    WriteFile(g_fql.writeFile, &checksum, sizeof(checksum), &written, nullptr);
    CloseHandle(g_fql.writeFile);
    g_fql.writeFile = nullptr;
    if (g_fql.unusedWriteFile != nullptr)
        CloseHandle(g_fql.unusedWriteFile);
    g_fql.unusedWriteFile = nullptr;
    g_fqlHandles.clear();
    g_fql.writeBuffer.clear();
    g_fql.writeBuffer.shrink_to_fit();
    g_fql.writePosition = S_DtaFql::BLOCK_HEADER_SIZE;
}

RW_DATA_API bool RW_DATA_CALL dtaAddFQLExtensionFilter(const char *ext)   // 0x100094c0
{
    C_DtaLock lock;
    if (ext == nullptr)
        return false;
    const size_t length = std::strlen(ext);
    if (static_cast<int>(length) < 1 || static_cast<int>(length) > 3)
        return false;
    char upper[4];
    std::strcpy(upper, ext);
    UpperCase(upper);
    int packed = 0;
    std::memcpy(&packed, upper, length);
    if (std::find(g_fqlExtensionFilter.begin(), g_fqlExtensionFilter.end(), packed) ==
        g_fqlExtensionFilter.end()) {
        g_fqlExtensionFilter.push_back(packed);
    }
    return true;
}

RW_DATA_API void RW_DATA_CALL dtaClearFQLExtensionFilter()   // 0x1000960b
{
    C_DtaLock lock;
    g_fqlExtensionFilter.clear();
}

RW_DATA_API void RW_DATA_CALL dtaSetDebugFQLExt(int)   // 0x1000922d
{
}

} // extern "C"
