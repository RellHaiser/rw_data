// Decoder of compressed WAV blocks: 16-bit PCM stored as one byte per sample, the delta
// to the previous sample of the channel (bit 7 = sign, bits 0..6 = index in a quadratic
// table). The first sample of every channel is stored as is.
#include "dta_internal.h"

#include <cstring>

namespace {

// Delta tables (0x10036d70), selected by the block type: 8 (and any other unlisted type)
// = table 0, 0x0C = 1, 0x10 = 2, 0x14 = 3, 0x18 = 4, 0x1C = 5, 0x20 = 6.
const int16_t g_wavDeltas[7][128] = {
    {
        0, 1, 2, 4, 8, 12, 18, 24, 32, 41, 50, 61,
        73, 85, 99, 114, 130, 146, 164, 183, 203, 223, 245, 268,
        292, 317, 343, 370, 398, 427, 457, 488, 520, 553, 587, 622,
        658, 695, 733, 772, 812, 853, 895, 939, 983, 1028, 1074, 1121,
        1170, 1219, 1269, 1321, 1373, 1426, 1481, 1536, 1592, 1650, 1708, 1768,
        1828, 1889, 1952, 2015, 2080, 2145, 2212, 2279, 2348, 2418, 2488, 2560,
        2632, 2706, 2781, 2856, 2933, 3011, 3090, 3169, 3250, 3332, 3415, 3498,
        3583, 3669, 3756, 3844, 3933, 4023, 4114, 4205, 4298, 4392, 4487, 4583,
        4680, 4778, 4877, 4977, 5079, 5181, 5284, 5388, 5493, 5599, 5706, 5815,
        5924, 6034, 6145, 6257, 6371, 6485, 6600, 6717, 6834, 6952, 7072, 7192,
        7313, 7436, 7559, 7684, 7809, 7936, 8063, 8192,
    },
    {
        0, 1, 3, 6, 12, 19, 27, 37, 48, 61, 76, 92,
        109, 128, 149, 171, 195, 220, 246, 275, 304, 335, 368, 403,
        438, 476, 515, 555, 597, 640, 685, 732, 780, 829, 880, 933,
        987, 1042, 1100, 1158, 1218, 1280, 1343, 1408, 1474, 1542, 1612, 1682,
        1755, 1829, 1904, 1981, 2060, 2140, 2221, 2304, 2389, 2475, 2562, 2652,
        2742, 2834, 2928, 3023, 3120, 3218, 3318, 3419, 3522, 3627, 3733, 3840,
        3949, 4059, 4171, 4285, 4400, 4517, 4635, 4754, 4875, 4998, 5122, 5248,
        5375, 5504, 5634, 5766, 5899, 6034, 6171, 6308, 6448, 6589, 6731, 6875,
        7021, 7168, 7316, 7466, 7618, 7771, 7926, 8082, 8240, 8399, 8560, 8722,
        8886, 9051, 9218, 9386, 9556, 9728, 9901, 10075, 10251, 10429, 10608, 10788,
        10970, 11154, 11339, 11526, 11714, 11904, 12095, 12288,
    },
    {
        0, 2, 4, 9, 16, 25, 36, 49, 65, 82, 101, 122,
        146, 171, 199, 228, 260, 293, 329, 366, 406, 447, 491, 537,
        585, 634, 686, 740, 796, 854, 914, 976, 1040, 1106, 1174, 1244,
        1316, 1390, 1466, 1545, 1625, 1707, 1791, 1878, 1966, 2057, 2149, 2243,
        2340, 2438, 2539, 2642, 2746, 2853, 2962, 3072, 3185, 3300, 3417, 3536,
        3656, 3779, 3904, 4031, 4160, 4291, 4424, 4559, 4697, 4836, 4977, 5120,
        5265, 5413, 5562, 5713, 5867, 6022, 6180, 6339, 6501, 6664, 6830, 6997,
        7167, 7339, 7512, 7688, 7866, 8046, 8228, 8411, 8597, 8785, 8975, 9167,
        9361, 9557, 9755, 9955, 10158, 10362, 10568, 10776, 10987, 11199, 11413, 11630,
        11848, 12068, 12291, 12515, 12742, 12970, 13201, 13434, 13668, 13905, 14144, 14384,
        14627, 14872, 15119, 15368, 15619, 15872, 16127, 16384,
    },
    {
        0, 2, 5, 11, 20, 31, 45, 62, 81, 102, 126, 153,
        182, 214, 248, 285, 325, 366, 411, 458, 507, 559, 614, 671,
        731, 793, 858, 925, 995, 1067, 1142, 1220, 1300, 1382, 1467, 1555,
        1645, 1738, 1833, 1931, 2031, 2134, 2239, 2347, 2458, 2571, 2686, 2804,
        2925, 3048, 3174, 3302, 3433, 3566, 3702, 3841, 3981, 4125, 4271, 4420,
        4571, 4724, 4880, 5039, 5200, 5364, 5531, 5699, 5871, 6045, 6221, 6400,
        6582, 6766, 6953, 7142, 7334, 7528, 7725, 7924, 8126, 8330, 8537, 8747,
        8959, 9174, 9391, 9610, 9833, 10057, 10285, 10514, 10747, 10982, 11219, 11459,
        11702, 11947, 12194, 12444, 12697, 12952, 13210, 13470, 13733, 13999, 14267, 14537,
        14810, 15086, 15364, 15644, 15927, 16213, 16501, 16792, 17085, 17381, 17680, 17981,
        18284, 18590, 18899, 19210, 19523, 19840, 20158, 20480,
    },
    {
        0, 2, 6, 13, 24, 38, 54, 74, 97, 123, 152, 184,
        219, 257, 298, 342, 390, 440, 493, 550, 609, 671, 737, 806,
        877, 952, 1030, 1110, 1194, 1281, 1371, 1464, 1560, 1659, 1761, 1866,
        1974, 2085, 2200, 2317, 2437, 2561, 2687, 2817, 2949, 3085, 3224, 3365,
        3510, 3658, 3809, 3963, 4120, 4280, 4443, 4609, 4778, 4950, 5125, 5304,
        5485, 5669, 5857, 6047, 6241, 6437, 6637, 6839, 7045, 7254, 7466, 7681,
        7898, 8119, 8343, 8570, 8800, 9034, 9270, 9509, 9751, 9997, 10245, 10496,
        10751, 11008, 11269, 11532, 11799, 12069, 12342, 12617, 12896, 13178, 13463, 13751,
        14042, 14336, 14633, 14933, 15237, 15543, 15852, 16165, 16480, 16798, 17120, 17445,
        17772, 18103, 18436, 18773, 19113, 19456, 19802, 20151, 20503, 20858, 21216, 21577,
        21941, 22308, 22678, 23052, 23428, 23808, 24190, 24576,
    },
    {
        0, 2, 7, 15, 28, 44, 63, 87, 113, 143, 177, 215,
        255, 300, 348, 399, 455, 513, 575, 641, 711, 783, 860, 940,
        1023, 1111, 1201, 1295, 1393, 1495, 1599, 1708, 1820, 1935, 2054, 2177,
        2303, 2433, 2566, 2703, 2844, 2988, 3135, 3286, 3441, 3599, 3761, 3926,
        4095, 4268, 4444, 4623, 4806, 4993, 5183, 5377, 5574, 5775, 5980, 6188,
        6399, 6614, 6833, 7055, 7281, 7510, 7743, 7979, 8219, 8463, 8710, 8961,
        9215, 9473, 9734, 9999, 10267, 10539, 10815, 11094, 11377, 11663, 11953, 12246,
        12543, 12843, 13147, 13455, 13766, 14080, 14399, 14720, 15046, 15375, 15707, 16043,
        16382, 16726, 17072, 17422, 17776, 18133, 18494, 18859, 19227, 19598, 19973, 20352,
        20734, 21120, 21509, 21902, 22299, 22699, 23102, 23509, 23920, 24334, 24752, 25173,
        25598, 26026, 26458, 26894, 27333, 27776, 28222, 28672,
    },
    {
        0, 2, 8, 18, 32, 50, 73, 99, 130, 164, 203, 245,
        292, 343, 398, 457, 520, 587, 658, 733, 812, 895, 983, 1074,
        1170, 1269, 1373, 1481, 1592, 1708, 1828, 1952, 2080, 2212, 2348, 2488,
        2632, 2781, 2933, 3089, 3250, 3415, 3583, 3756, 3933, 4113, 4298, 4487,
        4680, 4877, 5078, 5284, 5493, 5706, 5924, 6145, 6370, 6600, 6834, 7071,
        7313, 7559, 7809, 8063, 8321, 8583, 8849, 9119, 9393, 9672, 9954, 10241,
        10531, 10826, 11124, 11427, 11734, 12045, 12359, 12678, 13001, 13329, 13660, 13995,
        14334, 14678, 15025, 15376, 15732, 16091, 16455, 16823, 17195, 17570, 17950, 18334,
        18722, 19114, 19511, 19911, 20315, 20723, 21136, 21552, 21973, 22397, 22826, 23259,
        23696, 24136, 24581, 25030, 25483, 25940, 26402, 26867, 27336, 27809, 28287, 28768,
        29254, 29744, 30237, 30735, 31237, 31743, 32253, 32767,
    },
};

int DeltaTable(uint8_t blockType)
{
    switch (blockType) {
    case 0x0C: return 1;
    case 0x10: return 2;
    case 0x14: return 3;
    case 0x18: return 4;
    case 0x1C: return 5;
    case 0x20: return 6;
    default: return 0;
    }
}

uint32_t Read32(const uint8_t *p)
{
    uint32_t value;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

uint16_t Read16(const uint8_t *p)
{
    uint16_t value;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

int16_t ReadSample(const uint8_t *p)
{
    int16_t value;
    std::memcpy(&value, p, sizeof(value));
    return value;
}

void WriteSample(uint8_t *p, int16_t value)
{
    std::memcpy(p, &value, sizeof(value));
}

int16_t Delta(const int16_t *table, uint8_t code)
{
    const int16_t delta = table[code & 0x7F];
    return (code & 0x80) ? static_cast<int16_t>(-delta) : delta;
}

} // namespace

// `src` starts with the block type byte; the first block of a file then repeats the
// file's RIFF header (`wavHeader`), which is copied to the output. Returns the decoded size.
// The output stops at `dstCapacity` (only damaged data gets there; the original went on).
uint32_t WavDecompress(const uint8_t *src, uint8_t *dst, uint32_t srcSize, const uint8_t *wavHeader,
                       uint32_t dstCapacity)   // 0x100097f7
{
    const int16_t *table = g_wavDeltas[DeltaTable(src[0])];
    uint32_t out = 0;
    uint32_t in = 1;

    // The original read the header unconditionally (a null header crashed it).
    if (wavHeader == nullptr) {
        if (in < srcSize)
            out += LzssDecompress(src + in, dst + out, srcSize - in, dstCapacity - out);
        return out;
    }

    // "RIFF", "fmt " and "data" at the same places as in the file's header.
    if (Read32(src + 1) == Read32(wavHeader) && Read32(src + 0xD) == Read32(wavHeader + 0xC) &&
        Read32(src + 0x25) == Read32(wavHeader + 0x24) && dstCapacity >= DTA_WAV_HEADER_SIZE) {
        std::memcpy(dst, src + 1, DTA_WAV_HEADER_SIZE);
        out += DTA_WAV_HEADER_SIZE;
        in += DTA_WAV_HEADER_SIZE;
    }
    if (in >= srcSize)
        return out;

    const uint16_t channels = Read16(wavHeader + 0x16);
    const uint16_t blockAlign = Read16(wavHeader + 0x20);
    // The original divided by a zero channel count too.
    if (channels == 0 || blockAlign / channels != 2) {
        out += LzssDecompress(src + in, dst + out, srcSize - in, dstCapacity - out);
        return out;
    }

    // Like the original, a sample pair at the end of the data may use the byte after it.
    if (channels == 2) {
        if (dstCapacity - out < 4)
            return out;
        for (int i = 0; i < 4; ++i)
            dst[out++] = src[in++];
        if (in < srcSize) {
            int16_t left = ReadSample(dst + out - 4);
            int16_t right = ReadSample(dst + out - 2);
            do {
                if (dstCapacity - out < 4)
                    return out;
                uint8_t *sample = dst + out;
                out += 4;
                left = static_cast<int16_t>(left + Delta(table, src[in]));
                WriteSample(sample, left);
                right = static_cast<int16_t>(right + Delta(table, src[in + 1]));
                in += 2;
                WriteSample(sample + 2, right);
            } while (in < srcSize);
        }
    } else {
        if (dstCapacity - out < 2)
            return out;
        for (int i = 0; i < 2; ++i)
            dst[out++] = src[in++];
        if (in < srcSize) {
            int16_t value = ReadSample(dst + out - 2);
            do {
                if (dstCapacity - out < 2)
                    return out;
                uint8_t *sample = dst + out;
                out += 2;
                value = static_cast<int16_t>(value + Delta(table, src[in]));
                ++in;
                WriteSample(sample, value);
            } while (in < srcSize);
        }
    }
    return out;
}
