// The archives' cipher and checksum.
#include "dta_internal.h"

// The cipher XORs every byte with the byte of the 64-bit key (little endian) at the same
// position modulo 8. The original works on 8-byte words from the end of the buffer
// (writing them as ~(~word ^ key)) and then on the remaining bytes; the result is the same.
void DecryptBuffer(void *data, uint32_t size, uint64_t key)   // 0x10009bf3
{
    uint8_t *bytes = static_cast<uint8_t *>(data);
    for (uint32_t i = 0; i < size; ++i)
        bytes[i] ^= static_cast<uint8_t>(key >> ((i & 7) * 8));
}

// The cipher is its own inverse; dtaRead uses this name to decrypt whole blocks.
void EncryptBuffer(void *data, uint32_t size, uint64_t key)   // 0x10009d24
{
    DecryptBuffer(data, size, key);
}

uint16_t Checksum16(const void *data, uint32_t size, uint16_t seed)   // 0x10009e97
{
    const uint8_t *bytes = static_cast<const uint8_t *>(data);
    uint16_t sum = seed;
    for (uint32_t i = 0; i < size; ++i) {
        sum = static_cast<uint16_t>(sum + bytes[i]);
        sum ^= static_cast<uint8_t>(~bytes[i]);
    }
    return sum;
}
