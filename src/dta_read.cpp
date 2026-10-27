// Reading and seeking: dtaRead, dtaSeek, dtaGetTime.
#include "dta_internal.h"

#include <algorithm>
#include <cstring>
#include <memory>

namespace {

// A stored block is at most 0xFFFF bytes plus the type byte. (The original decoded into a
// 0x8008-byte stack buffer, too small for the largest blocks a 16-bit size allows.)
constexpr uint32_t RAW_BLOCK_SIZE = 0x10000 + 8 + DTA_DECODE_PAD;

// The original read a block's stored size into its 0x8008-byte stack buffer. Larger ISD0 blocks
// (and empty ones, which left a stale type byte) make dtaRead fail with -1; for ISD1 a block past
// the table or of 0x8008 bytes or more fails as a ReadFile error (6).
constexpr uint32_t RETAIL_BLOCK_LIMIT = 0x8008;

// What dtaRead copies out of the open file at the start (the original kept these in
// locals); the remaining fields are read from the slot again, as the error callback may
// open more files and move the slots.
struct S_ReadContext {
    int handle;
    HANDLE file;
    uint32_t size;
    uint32_t dataOffset;
    uint32_t blockCount;
    uint64_t key;
    bool tables;                 // ISD1: block sizes, checksums and types are in tables
    bool encrypted;
    uint8_t *decoded;            // the file's 32 KB buffer
    const uint16_t *sizes;
    const uint16_t *checksums;
    const uint8_t *types;
    uint32_t tableCount;

    S_DtaOpenFile &Slot() const { return g_openFiles[handle]; }

    // (The original read one entry past the tables when reading up to the end of a file.)
    uint32_t SizeOf(uint32_t block) const { return block < tableCount ? sizes[block] : 0; }
    uint8_t TypeOf(uint32_t block) const { return block < tableCount ? types[block] : 0; }

    // Offset of a block from dataOffset: the sum of the sizes before it.
    uint32_t OffsetOf(uint32_t block) const
    {
        uint32_t offset = 0;
        for (uint32_t i = block; i-- > 0;)
            offset += SizeOf(i);
        return offset;
    }
};

// Scratch buffer for one stored block, allocated on first use.
class C_RawBlock {
public:
    uint8_t *Get()
    {
        if (!m_data)
            m_data.reset(new uint8_t[RAW_BLOCK_SIZE]);
        return m_data.get();
    }

private:
    std::unique_ptr<uint8_t[]> m_data;
};

bool Seek(HANDLE file, uint32_t offset)
{
    return SetFilePointer(file, static_cast<LONG>(offset), nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER ||
           GetLastError() == NO_ERROR;
}

// ISD0: reads the u32 in front of a block (stored size | size of the previous block << 16).
bool ReadBlockHeader(HANDLE file, S_DtaCursor &cursor)
{
    uint32_t value;
    DWORD read;
    if (!ReadFile(file, &value, sizeof(value), &read, nullptr) || read != sizeof(value))
        return false;
    cursor.previousBlockSize = value >> 16;
    cursor.blockSize = value & 0xFFFF;
    return true;
}

// Reads the stored block at the current file position into `raw` (raw[0] = the type),
// checks and decrypts it. For ISD1 the type comes from the table and `blockSize` grows by
// it. On failure leaves the lock and reports the error (some callers first invalidate the
// buffer, as the original did).
bool ReadBlock(const S_ReadContext &ctx, uint8_t *raw, uint32_t &blockSize, uint32_t block,
               bool invalidateOnError, C_DtaLock &lock)
{
    uint8_t *data = ctx.tables ? raw + 1 : raw;
    if (ctx.tables ? block >= ctx.tableCount || blockSize >= RETAIL_BLOCK_LIMIT
                   : blockSize == 0 || blockSize > RETAIL_BLOCK_LIMIT) {
        if (invalidateOnError)
            ctx.Slot().bufferValid = false;
        lock.Unlock();
        if (ctx.tables)
            ReportArchiveError(ctx.file, DTA_ERROR_READ);
        return false;
    }
    DWORD read = 0;
    if (!ReadFile(ctx.file, data, blockSize, &read, nullptr)) {
        if (invalidateOnError)
            ctx.Slot().bufferValid = false;
        lock.Unlock();
        if (ctx.tables)
            ReportArchiveError(ctx.file, DTA_ERROR_READ);
        return false;
    }
    if (read != blockSize) {
        if (invalidateOnError)
            ctx.Slot().bufferValid = false;
        lock.Unlock();
        ReportArchiveError(ctx.file, DTA_ERROR_SIZE);
        return false;
    }
    if (ctx.tables && g_errorCallback && block < ctx.tableCount &&
        ctx.checksums[block] != Checksum16(data, blockSize, CHECKSUM_SEED)) {
        ReportArchiveError(ctx.file, DTA_ERROR_CHECKSUM);
    }
    if (ctx.encrypted)
        EncryptBuffer(data, blockSize, ctx.key);   // the cipher is its own inverse
    if (ctx.tables) {
        raw[0] = ctx.TypeOf(block);
        ++blockSize;
    }
    // The original's decoders read past the block (stale stack bytes); zeros here.
    std::memset(raw + blockSize, 0, DTA_DECODE_PAD);
    return true;
}

// Decodes a stored block (raw[0] = type) into `dst`, which has room for `capacity` bytes (a valid
// block decodes to at most 32 KB); returns the decoded size, or -1. Damaged blocks decode as in the
// original, which never compared the result with the expected size; a stored block larger than the
// room fails.
int DecodeBlock(const S_ReadContext &ctx, uint8_t *raw, uint32_t blockSize, uint32_t block,
                uint8_t *dst, uint32_t capacity)
{
    if (raw[0] == 1)
        return static_cast<int>(std::min(LzssDecompressRetail(raw, blockSize, dst, 0, capacity), capacity));
    if (raw[0] < 8) {
        if (blockSize - 1 > capacity)
            return -1;
        std::memcpy(dst, raw + 1, blockSize - 1);
        return static_cast<int>(blockSize - 1);
    }
    // Unless the whole block is encrypted, only the first block's RIFF header is.
    if (block == 0 && !ctx.encrypted)
        DecryptBuffer(raw + 1, DTA_WAV_HEADER_SIZE, ctx.key);
    const std::vector<uint8_t> &header = ctx.Slot().wavHeader;
    if (header.empty())   // (the original crashed on the missing header)
        return static_cast<int>(WavDecompress(raw, dst, blockSize, nullptr, capacity));
    return static_cast<int>(WavDecompressRetail(raw, blockSize, header.data(), dst, capacity));
}

// A file in an archive. Returns the bytes read or -1.
int ReadArchived(const S_ReadContext &ctx, S_DtaCursor &c, uint8_t *dst, uint32_t count, C_DtaLock &lock)
{
    C_RawBlock raw;

    // Move to the block of the position.
    const uint32_t target = c.position >> 15;
    if (c.block != target) {
        if (ctx.tables) {
            c.blockSize = ctx.SizeOf(target);
            c.blockOffset = ctx.OffsetOf(target);
            c.block = target;
        } else if (c.block < target) {
            while (c.block != target) {
                c.blockOffset += 4 + c.blockSize;
                ++c.block;
                if (!Seek(ctx.file, ctx.dataOffset + c.blockOffset) || !ReadBlockHeader(ctx.file, c))
                    return -1;
            }
        } else if (target < c.block >> 1) {
            // Nearer to the start: walk forward from the first block.
            if (!Seek(ctx.file, ctx.dataOffset))
                return -1;
            c.block = 0;
            c.blockOffset = 0;
            if (!ReadBlockHeader(ctx.file, c))
                return -1;
            while (c.block != target) {
                c.blockOffset += 4 + c.blockSize;
                ++c.block;
                if (!Seek(ctx.file, ctx.dataOffset + c.blockOffset) || !ReadBlockHeader(ctx.file, c))
                    return -1;
            }
        } else {
            // Walk back through the sizes of the previous blocks.
            while (c.block != target) {
                c.blockOffset -= c.previousBlockSize + 4;
                --c.block;
                if (!Seek(ctx.file, ctx.dataOffset + c.blockOffset) || !ReadBlockHeader(ctx.file, c))
                    return -1;
            }
        }
        c.blockPosition = c.position - c.block * DTA_BLOCK_SIZE;
        ctx.Slot().bufferValid = false;
    }

    // Decode the block.
    if (!ctx.Slot().bufferValid) {
        if (!Seek(ctx.file, ctx.dataOffset + c.blockOffset + (ctx.tables ? 0 : 4)))
            return -1;
        uint8_t *block = raw.Get();
        if (!ReadBlock(ctx, block, c.blockSize, c.block, false, lock))
            return -1;
        const int decoded = DecodeBlock(ctx, block, c.blockSize, c.block, ctx.decoded, DTA_BLOCK_SIZE);
        if (decoded < 0)
            return -1;
        c.bufferSize = static_cast<uint32_t>(decoded);
        ctx.Slot().bufferValid = true;
    }

    // (Only damaged data leaves the position past the decoded bytes; the original then
    // copied from past the buffer.)
    const uint32_t available = c.bufferSize > c.blockPosition ? c.bufferSize - c.blockPosition : 0;
    if (count <= available) {
        std::memcpy(dst, ctx.decoded + c.blockPosition, count);
        c.position += count;
        c.blockPosition += count;
        // At the end of the block, step to the next one.
        if (c.blockPosition == c.bufferSize && c.block + 1 < ctx.blockCount) {
            if (!ctx.tables) {
                c.blockOffset += c.blockSize + 4;
                ++c.block;
                if (!Seek(ctx.file, ctx.dataOffset + c.blockOffset) || !ReadBlockHeader(ctx.file, c))
                    return -1;
            } else {
                ++c.block;
                c.blockOffset = ctx.OffsetOf(c.block);
                c.blockSize = ctx.SizeOf(c.block);
            }
            ctx.Slot().bufferValid = false;
            c.blockPosition = 0;
        }
        return static_cast<int>(count);
    }

    // The rest of this block ...
    std::memcpy(dst, ctx.decoded + c.blockPosition, available);
    c.position += available;
    c.blockPosition = 0;
    uint32_t done = available;
    const uint32_t remaining = count - available;
    if (!ctx.tables)
        c.blockOffset += c.blockSize + 4;
    else
        c.blockOffset = ctx.OffsetOf(c.block + 1);
    if (!Seek(ctx.file, ctx.dataOffset + c.blockOffset))
        return -1;

    // ... whole blocks, decoded straight into the caller's buffer ...
    const uint32_t wholeBlocks = remaining >> 15;
    const uint32_t tail = remaining - wholeBlocks * DTA_BLOCK_SIZE;
    for (uint32_t i = 0; i < wholeBlocks; ++i) {
        ++c.block;
        if (!ctx.tables) {
            if (!ReadBlockHeader(ctx.file, c)) {
                ctx.Slot().bufferValid = false;
                return -1;
            }
        } else {
            c.blockSize = ctx.SizeOf(c.block);
        }
        uint8_t *block = raw.Get();
        if (!ReadBlock(ctx, block, c.blockSize, c.block, true, lock))
            return -1;
        const int decoded = DecodeBlock(ctx, block, c.blockSize, c.block, dst + done, count - done);
        if (decoded < 0) {
            ctx.Slot().bufferValid = false;
            return -1;
        }
        c.bufferSize = static_cast<uint32_t>(decoded);
        done += c.bufferSize;
        c.position += c.bufferSize;
        if (!ctx.tables)
            c.blockOffset += 4 + c.blockSize;
        else
            c.blockOffset = ctx.OffsetOf(c.block + 1);
    }

    // ... and the start of the next block through the file's buffer.
    ++c.block;
    if (!ctx.tables) {
        if (!ReadBlockHeader(ctx.file, c)) {
            ctx.Slot().bufferValid = false;
            return -1;
        }
    } else {
        c.blockOffset = ctx.OffsetOf(c.block);
        c.blockSize = ctx.SizeOf(c.block);
    }
    if (tail == 0) {
        ctx.Slot().bufferValid = false;
        return static_cast<int>(done);
    }
    uint8_t *block = raw.Get();
    if (!ReadBlock(ctx, block, c.blockSize, c.block, true, lock))
        return -1;
    const int decoded = DecodeBlock(ctx, block, c.blockSize, c.block, ctx.decoded, DTA_BLOCK_SIZE);
    if (decoded < 0) {
        ctx.Slot().bufferValid = false;
        return -1;
    }
    c.bufferSize = static_cast<uint32_t>(decoded);
    std::memcpy(dst + done, ctx.decoded + c.blockPosition, tail);
    c.position += tail;
    c.blockPosition += tail;
    return static_cast<int>(done + tail);
}

// A file on disk, read through its 32 KB buffer. Returns the bytes read or -1.
int ReadDisk(const S_ReadContext &ctx, S_DtaCursor &c, uint8_t *dst, uint32_t count)
{
    DWORD read;
    if (!ctx.Slot().bufferValid || c.position < c.blockOffset || c.blockOffset + c.bufferSize <= c.position) {
        c.blockOffset = c.position & ~(DTA_BLOCK_SIZE - 1);
        if (!Seek(ctx.file, c.blockOffset))
            return -1;
        c.bufferSize = std::min(ctx.size - c.blockOffset, DTA_BLOCK_SIZE);
        if (!ReadFile(ctx.file, ctx.decoded, c.bufferSize, &read, nullptr) || read != c.bufferSize)
            return -1;
        ctx.Slot().bufferValid = true;
        c.blockPosition = c.position - c.blockOffset;
    }

    const uint32_t available = c.bufferSize > c.blockPosition ? c.bufferSize - c.blockPosition : 0;
    if (count <= available) {
        std::memcpy(dst, ctx.decoded + c.blockPosition, count);
        c.position += count;
        c.blockPosition += count;
        if (c.blockPosition == c.bufferSize && c.position < ctx.size) {
            c.blockOffset += c.bufferSize;
            ctx.Slot().bufferValid = false;
        }
        return static_cast<int>(count);
    }

    std::memcpy(dst, ctx.decoded + c.blockPosition, available);
    c.position += available;
    c.blockPosition = 0;
    uint32_t done = available;
    const uint32_t remaining = count - available;
    ctx.Slot().bufferValid = false;
    c.blockOffset += c.bufferSize;
    if (!Seek(ctx.file, c.blockOffset))
        return -1;
    c.bufferSize = std::min(ctx.size - c.blockOffset, DTA_BLOCK_SIZE);
    if (remaining < c.bufferSize) {
        // Refill the buffer and copy from it.
        if (!ReadFile(ctx.file, ctx.decoded, c.bufferSize, &read, nullptr) || read != c.bufferSize)
            return -1;
        std::memcpy(dst + done, ctx.decoded, remaining);
        done += remaining;
        c.position += remaining;
        c.blockPosition += remaining;
        ctx.Slot().bufferValid = true;
    } else {
        // Read the rest straight into the caller's buffer.
        if (!ReadFile(ctx.file, dst + done, remaining, &read, nullptr) || read != remaining)
            return -1;
        done += remaining;
        c.position += remaining;
    }
    return static_cast<int>(done);
}

} // namespace

extern "C" {

RW_DATA_API int RW_DATA_CALL dtaRead(int handle, void *buffer, int size)   // 0x1000513b
{
    C_DtaLock lock;
    if (buffer == nullptr || static_cast<uint32_t>(handle) >= g_openFiles.size())
        return -1;
    S_DtaOpenFile &file = g_openFiles[handle];
    if (file.IsFree() || (file.flags & DTA_FILE_WRITE))
        return -1;

    const S_ReadContext ctx = {
        handle,
        file.file,
        file.size,
        file.dataOffset,
        file.blockCount,
        file.key,
        file.blockTables,
        file.blocksEncrypted,
        file.buffer.data(),
        file.blockSizes.data(),
        file.blockChecksums.data(),
        file.blockTypes.data(),
        static_cast<uint32_t>(file.blockSizes.size()),
    };
    const uint32_t flags = file.flags;
    S_DtaCursor cursor = file.cursor;

    // Reads of ISD1 files opened while recording / playing back go through the FQL file.
    bool recorded = false;
    if (ctx.tables && g_fql.Active())
        recorded = std::find(g_fqlHandles.begin(), g_fqlHandles.end(), handle) != g_fqlHandles.end();

    // dtaSeek accepts one byte past the end. The original then computed the remaining size
    // as 0xFFFFFFFF and copied `size` bytes from past its buffers; the port reads nothing.
    if (cursor.position > ctx.size)
        return 0;
    uint32_t count = static_cast<uint32_t>(size);
    if (ctx.size - cursor.position < count)
        count = ctx.size - cursor.position;

    uint8_t *dst = static_cast<uint8_t *>(buffer);
    int result;
    if ((flags & DTA_FILE_DISK) == 0 && recorded && g_fql.readFile != nullptr) {
        FqlRead(dst, count);
        result = static_cast<int>(count);
        cursor.blockOffset = 0;
        cursor.position += count;
        cursor.blockPosition = 0;
        cursor.block = 0;
        cursor.blockSize = 0;
        cursor.previousBlockSize = 0;
        cursor.bufferSize = 0;
    } else if ((flags & DTA_FILE_DISK) == 0) {
        result = ReadArchived(ctx, cursor, dst, count, lock);
        if (result < 0)
            return -1;
        if (recorded && g_fql.writeFile != nullptr)
            FqlWrite(dst, static_cast<uint32_t>(result));
    } else {
        result = ReadDisk(ctx, cursor, dst, count);
        if (result < 0)
            return -1;
    }
    g_openFiles[handle].cursor = cursor;
    return result;
}

RW_DATA_API int RW_DATA_CALL dtaSeek(int handle, int position, int origin)   // 0x100079b0
{
    C_DtaLock lock;
    if (static_cast<uint32_t>(handle) >= g_openFiles.size())
        return -1;
    S_DtaOpenFile &file = g_openFiles[handle];
    if (file.IsFree())
        return -1;
    S_DtaCursor &cursor = file.cursor;

    // Files being read: only the position moves; dtaRead finds the block.
    if ((file.flags & DTA_FILE_WRITE) == 0) {
        switch (origin) {
        case 0:
            if (position < 0 || file.size < static_cast<uint32_t>(position))
                return -1;
            cursor.position = static_cast<uint32_t>(position);
            cursor.blockPosition = cursor.position % DTA_BLOCK_SIZE;
            return position;
        case 1: {
            const uint32_t target = cursor.position + static_cast<uint32_t>(position);
            if (file.size < target || static_cast<int>(target) < 0)
                return -1;
            cursor.position = target;
            cursor.blockPosition = cursor.position % DTA_BLOCK_SIZE;
            return static_cast<int>(cursor.position);
        }
        case 2:
            // (The test is position < 2, so one byte past the end is accepted.)
            if (position < 2 && static_cast<int>(file.size + static_cast<uint32_t>(position)) >= 0) {
                cursor.position = file.size + static_cast<uint32_t>(position);
                cursor.blockPosition = cursor.position % DTA_BLOCK_SIZE;
                return static_cast<int>(cursor.position);
            }
            return -1;
        default:
            return -1;
        }
    }

    // Files being written: the file pointer. The original's switch has no breaks, so a
    // failed seek is retried with the next origins.
    switch (origin) {
    case 0:
        cursor.position = SetFilePointer(file.file, position, nullptr, FILE_BEGIN);
        if (cursor.position != INVALID_SET_FILE_POINTER) {
            cursor.blockPosition = cursor.position % DTA_BLOCK_SIZE;
            return static_cast<int>(cursor.position);
        }
        [[fallthrough]];
    case 1:
        cursor.position = SetFilePointer(file.file, position, nullptr, FILE_CURRENT);
        if (cursor.position != INVALID_SET_FILE_POINTER) {
            cursor.blockPosition = cursor.position % DTA_BLOCK_SIZE;
            return static_cast<int>(cursor.position);
        }
        [[fallthrough]];
    case 2:
        cursor.position = SetFilePointer(file.file, position, nullptr, FILE_END);
        if (cursor.position != INVALID_SET_FILE_POINTER) {
            cursor.blockPosition = cursor.position % DTA_BLOCK_SIZE;
            return static_cast<int>(cursor.position);
        }
        break;
    default:
        break;
    }
    return -1;
}

RW_DATA_API bool RW_DATA_CALL dtaGetTime(int handle, _FILETIME *time, bool containerTime)   // 0x100088d5
{
    C_DtaLock lock;
    if (static_cast<uint32_t>(handle) >= g_openFiles.size())
        return false;
    const S_DtaOpenFile &file = g_openFiles[handle];
    if (file.IsFree())
        return false;
    if ((file.flags & DTA_FILE_DISK) == 0 && !containerTime) {
        *time = file.time;
        return true;
    }
    FILETIME creation;
    FILETIME access;
    return GetFileTime(file.file, &creation, &access, time) != FALSE;
}

} // extern "C"
