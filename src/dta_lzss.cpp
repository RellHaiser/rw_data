// LZSS codec of the archive blocks and FQL files.
//
// Stream: byte 0 = 0 (stored: the data follows) or 1 (compressed). A compressed stream is
// a sequence of groups of 16 items, each group preceded by a big-endian 16-bit flag word
// (most significant bit first; the first one is at bytes 1..2):
//   flag 0: a literal byte
//   flag 1: two bytes DDDD DDDD DDDD LLLL: copy L + 3 bytes from D bytes back (D != 0), or
//           D == 0: four bytes 00 0H LL BB: H:LL + 16 copies of byte BB
#include "dta_internal.h"

#include <algorithm>
#include <cstring>

namespace {

constexpr uint32_t WINDOW_SIZE = 0x1000;
constexpr uint16_t MAX_MATCH = 0x12;
constexpr uint16_t MAX_RUN = 0xFFF;
constexpr uint16_t MIN_RUN = 0x10;

// Last position at which each 3-byte hash was seen (0x100438c8).
int g_hashTable[0x1000];

// Looks for an earlier occurrence of the bytes at `pos` through the hash table and records
// `pos` in it. On success `length` (3..18) and `matchPos` describe the match; otherwise
// `length` is left unchanged when the hash slot was empty or too far away.
bool FindMatch(const uint8_t *data, uint32_t pos, uint32_t size, uint16_t &length,
               int &matchPos)   // 0x1000f030
{
    // Reads up to two bytes past the end of the data, like the original.
    const int mixed = ((((data[pos] << 4) ^ data[pos + 1]) << 4) ^ data[pos + 2]);
    const int hash = static_cast<int>(static_cast<uint32_t>(mixed) * 0x9E5Fu) >> 4 & 0xFFF;
    bool found = false;
    const int candidate = g_hashTable[hash];
    if (candidate != -1 && pos - static_cast<uint32_t>(candidate) < WINDOW_SIZE) {
        matchPos = candidate;
        length = 0;
        while (length < MAX_MATCH && data[pos + length] == data[matchPos + length] &&
               pos + length < size) {
            ++length;
        }
        found = length > 2;
    }
    g_hashTable[hash] = static_cast<int>(pos);
    return found;
}

} // namespace

uint32_t LzssDecompress(const uint8_t *src, uint8_t *dst, uint32_t srcSize, uint32_t dstCapacity)   // 0x1000ea20
{
    // Valid streams decode exactly as in the original. On anything else (a damaged block,
    // or bytes past the end of a file) the original wrote past `dst`, read before it and
    // past `src`; here the output stops at `dstCapacity`, a reference before the start of
    // the output reads zeros and a token cut off by the end of the input ends the stream.
    if (srcSize == 0)
        return 0;
    if (src[0] == 0) {
        const uint32_t size = std::min(srcSize - 1, dstCapacity);
        std::memcpy(dst, src + 1, size);
        return size;
    }
    if (srcSize < 3)
        return 0;

    uint32_t out = 0;
    uint32_t in = 3;
    uint16_t flags = static_cast<uint16_t>(src[1] << 8 | src[2]);
    uint8_t flagsLeft = 16;
    while (in < srcSize) {
        if (flagsLeft == 0) {
            if (in + 2 > srcSize)
                break;
            flags = static_cast<uint16_t>(src[in] << 8 | src[in + 1]);
            flagsLeft = 16;
            in += 2;
            if (in >= srcSize)
                break;
        }
        if ((flags & 0x8000) == 0) {
            if (out >= dstCapacity)
                return out;
            dst[out++] = src[in++];
        } else {
            if (in + 2 > srcSize)
                break;
            const uint32_t distance = src[in] * 16u + (src[in + 1] >> 4);
            if (distance == 0) {
                if (in + 4 > srcSize)
                    break;
                const uint32_t count = (src[in + 1] << 8) + 0xF + src[in + 2] + 1u;
                const uint32_t n = std::min(count, dstCapacity - out);
                std::memset(dst + out, src[in + 3], n);
                in += 4;
                out += n;
                if (n != count)
                    return out;
            } else {
                const uint32_t length = (src[in + 1] & 0xFu) + 3;
                const uint32_t n = std::min(length, dstCapacity - out);
                for (uint32_t i = 0; i < n; ++i) {   // byte by byte: the copy may overlap
                    const uint32_t at = out + i;
                    dst[at] = at >= distance ? dst[at - distance] : 0;
                }
                in += 2;
                out += n;
                if (n != length)
                    return out;
            }
        }
        flags = static_cast<uint16_t>(flags << 1);
        --flagsLeft;
    }
    return out;
}

// Falls back to a stored stream when compressing does not pay. `dst` needs `size` + 6 bytes.
uint32_t LzssCompress(const uint8_t *src, uint8_t *dst, uint32_t size)   // 0x1000ecd0
{
    std::memset(g_hashTable, 0xFF, sizeof(g_hashTable));
    dst[0] = 1;
    uint32_t in = 0;
    uint32_t out = 3;
    uint32_t flagsPos = 1;
    uint16_t flagCount = 0;
    uint16_t flags = 0;
    int matchPos = 0;
    while (in < size && out <= size) {
        if (flagCount > 15) {
            dst[flagsPos] = static_cast<uint8_t>(flags >> 8);
            dst[flagsPos + 1] = static_cast<uint8_t>(flags);
            flagsPos = out;
            flagCount = 0;
            out += 2;
        }

        // Reads one byte past the end of the data, like the original.
        uint16_t length = 1;
        while (src[in] == src[in + length] && length < MAX_RUN && in + length < size)
            ++length;

        if (length < MIN_RUN) {
            if (!FindMatch(src, in, size, length, matchPos)) {
                dst[out++] = src[in++];
                flags = static_cast<uint16_t>(flags << 1);
            } else {
                const uint16_t code = static_cast<uint16_t>(
                    static_cast<uint16_t>(in - matchPos) * 16 - 3 + length);
                dst[out] = static_cast<uint8_t>(code >> 8);
                dst[out + 1] = static_cast<uint8_t>(code);
                out += 2;
                in += length;
                flags = static_cast<uint16_t>(flags * 2 + 1);
            }
        } else {
            const uint16_t count = static_cast<uint16_t>(length - MIN_RUN);
            dst[out] = 0;
            dst[out + 1] = static_cast<uint8_t>(count >> 8);
            dst[out + 2] = static_cast<uint8_t>(count);
            dst[out + 3] = src[in];
            out += 4;
            in += length;
            flags = static_cast<uint16_t>(flags * 2 + 1);
        }
        ++flagCount;
    }
    flags = static_cast<uint16_t>(static_cast<uint32_t>(flags) << ((16 - flagCount) & 0x1F));
    dst[flagsPos] = static_cast<uint8_t>(flags >> 8);
    dst[flagsPos + 1] = static_cast<uint8_t>(flags);

    if (size < out) {
        std::memcpy(dst + 1, src, size);
        dst[0] = 0;
        out = size + 1;
    }
    return out;
}
