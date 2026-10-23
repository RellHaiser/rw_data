// Opening and closing files: the archive lookup, disk files, dtaOpen / dtaClose.
#include "dta_archive.h"

#include <algorithm>
#include <cstring>

namespace {

// OpenEntry results besides a handle.
constexpr int ENTRY_NO_MATCH = -2;   // another file with the same hash: try the next entry
constexpr int ENTRY_ERROR = -1;      // stop the lookup

// First index of the entries with this hash in an archive's (sorted) table, or -1.
int ArchiveFindEntry(int table, uint32_t hash)   // 0x1000e0f0
{
    const std::vector<S_DtaFileEntry> &entries = g_archiveTables[table].entries;
    const int count = static_cast<int>(entries.size());
    if (count < 1)
        return -1;

    // The original compares the hashes through their signed difference.
    auto compare = [&](int index) { return static_cast<int>(hash - entries[index].hash); };
    int low = 0;
    int high = count - 1;
    int middle = count / 2;
    for (;;) {
        const int difference = compare(middle);
        if (difference == 0)
            break;
        if (difference > 0)
            low = middle + 1;
        else
            high = middle - 1;
        if (high < low)
            return -1;
        middle = (high - low) / 2 + low;
    }
    while (middle >= 1 && entries[middle - 1].hash == hash)
        --middle;
    return middle;
}

// Reports an error of the archive in a search slot (or of the FQL file during playback).
void ReportSlotError(int slot, int error)
{
    if (g_errorCallback == nullptr)
        return;
    if (g_fql.readFile == nullptr) {
        C_DtaRead *archive = g_searchOrder[slot].archive;
        g_errorCallback(archive, archive->GetName(), error);
    } else {
        g_errorCallback(nullptr, g_fql.fileName, error);
    }
}

// Reads from the archive, or from the FQL file during playback when the file is recorded.
// `read` receives the byte count; false when ReadFile fails.
bool ReadArchiveData(HANDLE file, void *data, DWORD size, DWORD &read, bool recorded)
{
    if (recorded && g_fql.readFile != nullptr) {
        read = size;
        FqlRead(data, size);
        return true;
    }
    return ReadFile(file, data, size, &read, nullptr) != FALSE;
}

void RecordArchiveData(const void *data, DWORD size, bool recorded)
{
    if (recorded && g_fql.writeFile != nullptr)
        FqlWrite(data, size);
}

// Opens the file of one table entry if its full name matches.
int OpenEntry(int slot, int table, const S_DtaFileEntry &entry, const std::string &upperName,
              bool recorded)
{
    // The archive is copied: the error callback could mount more archives.
    const HANDLE file = g_archiveTables[table].file;
    const uint64_t key = g_archiveTables[table].key;
    const int version = g_archiveTables[table].version;

    // The table holds the last 16 characters of the name.
    const uint16_t nameLength = static_cast<uint16_t>(entry.hash >> 16);
    const size_t tailOffset = nameLength > 16 ? nameLength - 16u : 0u;
    if (std::strncmp(entry.nameTail, upperName.c_str() + tailOffset, 16) != 0)
        return ENTRY_NO_MATCH;

    if (SetFilePointer(file, static_cast<LONG>(entry.headerOffset), nullptr, FILE_BEGIN) ==
            INVALID_SET_FILE_POINTER &&
        GetLastError() != NO_ERROR) {
        return ENTRY_ERROR;
    }

    // Header. ISD0 archives are never played back from an FQL file.
    S_DtaFileHeader header = {};
    uint16_t nameField = 0;
    uint16_t tablesChecksum = 0;
    DWORD read = 0;
    if (version == 0) {
        if (!ReadFile(file, &header, sizeof(header), &read, nullptr) || read != sizeof(header))
            return ENTRY_ERROR;
        DecryptBuffer(&header, sizeof(header), key);
        nameField = header.v0.nameLength;
    } else if (version == 1) {
        if (!ReadArchiveData(file, &header, sizeof(header), read, recorded)) {
            ReportSlotError(slot, DTA_ERROR_READ);
            return ENTRY_ERROR;
        }
        if (read != sizeof(header)) {
            ReportSlotError(slot, DTA_ERROR_SIZE);
            return ENTRY_ERROR;
        }
        RecordArchiveData(&header, sizeof(header), recorded);
        DecryptBuffer(&header, sizeof(header), key);
        nameField = header.v1.nameLength;
        tablesChecksum = header.v1.tablesChecksum;
        if (g_errorCallback) {
            const uint32_t stored = header.v1.headerChecksum;
            header.v1.headerChecksum = 0;
            if (stored != Checksum16(&header, sizeof(header), CHECKSUM_SEED))
                ReportSlotError(slot, DTA_ERROR_CHECKSUM);
        }
    }

    // Full name. The original read it into a 264-byte stack buffer whatever its length.
    const DWORD nameSize = nameField & 0x7FFFu;
    std::vector<char> name(nameSize + 1u);
    if (version == 1) {
        if (!ReadArchiveData(file, name.data(), nameSize, read, recorded)) {
            ReportSlotError(slot, DTA_ERROR_READ);
            return ENTRY_ERROR;
        }
        RecordArchiveData(name.data(), read, recorded);
    } else if (!ReadFile(file, name.data(), nameSize, &read, nullptr)) {
        return ENTRY_ERROR;
    }
    if (read != nameSize) {
        // (The original called the callback here without checking it for null.)
        ReportSlotError(slot, DTA_ERROR_SIZE);
        return ENTRY_ERROR;
    }
    DecryptBuffer(name.data(), nameSize, key);
    uint16_t checksum = 0;
    if (version != 0 && g_errorCallback)
        checksum = Checksum16(name.data(), nameSize, CHECKSUM_SEED);
    name[read] = '\0';
    UpperCase(name.data());
    if (std::strcmp(upperName.c_str(), name.data()) != 0)
        return ENTRY_NO_MATCH;

    S_DtaOpenFile open;
    open.file = file;
    open.flags = 0;
    open.time = header.time;
    open.size = header.size;
    open.dataOffset = entry.dataOffset;
    open.blockCount = header.blockCount;
    open.cursor.bufferSize = std::min(open.size, DTA_BLOCK_SIZE);
    open.key = key;
    open.blocksEncrypted = (nameField & DTA_NAME_ENCRYPTED_BLOCKS) != 0;

    if (version == 0) {
        // The first block's header: its stored size in the low 16 bits.
        uint32_t blockHeader;
        if (!ReadFile(file, &blockHeader, sizeof(blockHeader), &read, nullptr) ||
            read != sizeof(blockHeader)) {
            return ENTRY_ERROR;
        }
        open.cursor.blockSize = blockHeader & 0xFFFF;
    } else if (version == 1) {
        // Block tables: u32 per block (size | checksum << 16), then a type byte per block.
        const uint32_t blockCount = open.blockCount;
        std::vector<uint32_t> sizes(blockCount);
        const DWORD sizesBytes = blockCount * 4;
        if (!ReadArchiveData(file, sizes.data(), sizesBytes, read, recorded)) {
            ReportSlotError(slot, DTA_ERROR_READ);
            return ENTRY_ERROR;
        }
        RecordArchiveData(sizes.data(), read, recorded);
        if (read != sizesBytes) {
            ReportSlotError(slot, DTA_ERROR_SIZE);   // (unchecked callback in the original)
            return ENTRY_ERROR;
        }
        if (g_errorCallback)
            checksum = Checksum16(sizes.data(), sizesBytes, checksum);
        open.blockTables = true;
        open.blockSizes.resize(blockCount);
        open.blockChecksums.resize(blockCount);
        for (uint32_t i = 0; i < blockCount; ++i) {
            open.blockSizes[i] = static_cast<uint16_t>(sizes[i]);
            open.blockChecksums[i] = static_cast<uint16_t>(sizes[i] >> 16);
        }
        // (The original read the first size of an empty table too.)
        open.cursor.blockSize = blockCount ? open.blockSizes[0] : 0;

        open.blockTypes.resize(blockCount);
        if (!ReadArchiveData(file, open.blockTypes.data(), blockCount, read, recorded)) {
            ReportSlotError(slot, DTA_ERROR_READ);
            return ENTRY_ERROR;
        }
        RecordArchiveData(open.blockTypes.data(), read, recorded);
        if (read != blockCount) {
            ReportSlotError(slot, DTA_ERROR_SIZE);   // (unchecked callback in the original)
            return ENTRY_ERROR;
        }
        if (g_errorCallback && tablesChecksum != Checksum16(open.blockTypes.data(), blockCount, checksum))
            ReportSlotError(slot, DTA_ERROR_CHECKSUM);
        DecryptBuffer(open.blockTypes.data(), blockCount, key);
    }

    // Type of the first block; compressed WAV files keep their RIFF header.
    uint8_t block[1 + DTA_WAV_HEADER_SIZE];
    if (version == 0) {
        if (!ReadFile(file, block, 1, &read, nullptr) || read != 1)
            return ENTRY_ERROR;
        if (open.blocksEncrypted)
            DecryptBuffer(block, 1, key);
    } else {
        block[0] = open.blockTypes.empty() ? 0 : open.blockTypes[0];
    }
    if (block[0] > 7) {
        if (!ReadArchiveData(file, block + 1, DTA_WAV_HEADER_SIZE, read, recorded)) {
            ReportSlotError(slot, DTA_ERROR_READ);
            return ENTRY_ERROR;
        }
        RecordArchiveData(block + 1, read, recorded);
        if (read != DTA_WAV_HEADER_SIZE) {
            ReportSlotError(slot, DTA_ERROR_SIZE);   // (unchecked callback in the original)
            return ENTRY_ERROR;
        }
        if (version == 0 && open.blocksEncrypted)
            DecryptBuffer(block, sizeof(block), key);   // encrypted together with the type byte
        else
            DecryptBuffer(block + 1, DTA_WAV_HEADER_SIZE, key);
        open.wavHeader.assign(block + 1, block + 1 + DTA_WAV_HEADER_SIZE);
    }

    open.buffer.resize(DTA_BLOCK_SIZE);
    return StoreOpenFile(std::move(open));
}

} // namespace

void UpperCase(char *text)
{
    // _strupr of the C locale.
    for (; *text; ++text) {
        if (*text >= 'a' && *text <= 'z')
            *text = static_cast<char>(*text - ('a' - 'A'));
    }
}

void UpperCase(std::string &text)
{
    UpperCase(&text[0]);
}

int PackExtension(const char *name)
{
    const size_t length = std::strlen(name);
    // (The original read the byte before an empty name.)
    if (length == 0)
        return 0;
    // Start of the extension: after the last '.' among the last 3 characters, else the
    // last 3 characters.
    size_t start;
    size_t end = length;
    for (;;) {
        start = end - 1;
        if (static_cast<int>(length - start) > 2 || static_cast<int>(start) < 1)
            break;
        const char before = name[end - 2];
        end = start;
        if (before == '.')
            break;
    }
    int packed = 0;
    std::memcpy(&packed, name + start, length - start);
    return packed;
}

int FindArchiveTable(HANDLE file)
{
    int table = static_cast<int>(g_archiveTables.size());
    do {
        if (table-- == 0)
            break;
    } while (g_archiveTables[table].file != file);
    return table;
}

int StoreOpenFile(S_DtaOpenFile file)
{
    const size_t count = g_openFiles.size();
    for (size_t handle = 0; handle < count; ++handle) {
        if (g_openFiles[handle].IsFree()) {
            g_openFiles[handle] = std::move(file);
            return static_cast<int>(handle);
        }
    }
    g_openFiles.push_back(std::move(file));
    return static_cast<int>(g_openFiles.size()) - 1;
}

void ReportArchiveError(HANDLE archiveFile, int error)
{
    if (g_errorCallback == nullptr)
        return;
    int slot = static_cast<int>(g_searchOrder.size());
    do {
        if (slot-- == 0)
            return;
    } while (g_archiveTables[g_searchOrder[slot].table].file != archiveFile);
    ReportSlotError(slot, error);
}

int OpenFromArchives(const char *fileName)   // 0x1000c110
{
    // The original copied the name into a 264-byte buffer.
    std::string upperName = fileName;
    UpperCase(upperName);
    const uint32_t length = static_cast<uint32_t>(upperName.size());
    uint16_t sum = 0;
    for (uint32_t i = length; i-- > 0;)
        sum = static_cast<uint16_t>(sum + static_cast<uint8_t>(upperName[i]));
    const uint32_t hash = length << 16 | sum;

    bool recorded = false;
    if (g_fql.Active())
        recorded = !FqlIsExtensionFiltered(upperName.c_str());

    const uint32_t slotCount = static_cast<uint32_t>(g_searchOrder.size());
    for (uint32_t slot = 0; slot < slotCount; ++slot) {
        const int table = g_searchOrder[slot].table;
        const uint32_t entryCount = static_cast<uint32_t>(g_archiveTables[table].entries.size());
        const int first = ArchiveFindEntry(table, hash);
        if (first == -1)
            continue;
        for (uint32_t index = static_cast<uint32_t>(first); index < entryCount; ++index) {
            const S_DtaFileEntry entry = g_archiveTables[table].entries[index];
            if (entry.hash != hash)
                break;
            const int handle = OpenEntry(static_cast<int>(slot), table, entry, upperName, recorded);
            if (handle == ENTRY_NO_MATCH)
                continue;
            return handle;   // a handle or an error (-1)
        }
    }
    return -1;
}

int OpenFromDisk(const char *fileName)   // 0x1000dea0
{
    const HANDLE file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    const DWORD size = SetFilePointer(file, 0, nullptr, FILE_END);
    if (size == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        CloseHandle(file);   // (the original leaked the handle)
        return -1;
    }

    S_DtaOpenFile open;
    open.file = file;
    open.flags = DTA_FILE_DISK;
    open.size = size;
    open.blockCount = 1;
    open.cursor.bufferSize = std::min<uint32_t>(size, DTA_BLOCK_SIZE);
    open.buffer.resize(DTA_BLOCK_SIZE);
    return StoreOpenFile(std::move(open));
}

extern "C" {

RW_DATA_API int RW_DATA_CALL dtaOpen(const char *fileName, bool archivesFirst)   // 0x10004b8c
{
    C_DtaLock lock;
    int handle;
    if (!archivesFirst && !g_preferArchives) {
        handle = OpenFromDisk(fileName);
        if (handle == -1)
            handle = OpenFromArchives(fileName);
    } else {
        handle = OpenFromArchives(fileName);
        if (handle == -1)
            handle = OpenFromDisk(fileName);
    }

    if (handle >= 0) {
        std::string upperName = fileName;
        UpperCase(upperName);
        if (g_fql.Active())
            FqlRecordOpen(handle, upperName.c_str());
        FileLogRecord(upperName.c_str());
    }
    return handle;
}

RW_DATA_API bool RW_DATA_CALL dtaClose(int handle)   // 0x10004cc4
{
    C_DtaLock lock;
    if (static_cast<uint32_t>(handle) >= g_openFiles.size())
        return false;

    S_DtaOpenFile &file = g_openFiles[handle];
    if (file.IsFree())
        return true;

    if (g_fql.Active()) {
        for (size_t i = g_fqlHandles.size(); i-- > 0;) {
            if (g_fqlHandles[i] == handle) {
                g_fqlHandles[i] = g_fqlHandles.back();
                g_fqlHandles.pop_back();
            }
        }
    }

    if (file.flags & DTA_FILE_DISK) {
        if (!CloseHandle(file.file))
            return false;
        if (file.flags & DTA_FILE_TEMP) {
            if ((file.flags & DTA_FILE_WRITE_ERROR) == 0) {
                // Replace the target ("<name>.tmp" without ".tmp") by the temporary file.
                const std::string target = file.tempFileName.substr(0, file.tempFileName.size() - 4);
                if (!DeleteFileA(target.c_str())) {
                    const DWORD attributes = GetFileAttributesA(target.c_str());
                    if (attributes != INVALID_FILE_ATTRIBUTES) {
                        SetFileAttributesA(target.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
                        DeleteFileA(target.c_str());
                    }
                }
                MoveFileA(file.tempFileName.c_str(), target.c_str());
            } else {
                DeleteFileA(file.tempFileName.c_str());
            }
        }
    }
    file = S_DtaOpenFile();
    return true;
}

RW_DATA_API bool RW_DATA_CALL dtaDelete(const char *fileName)   // 0x10005113
{
    return DeleteFileA(fileName) != FALSE;
}

RW_DATA_API void *RW_DATA_CALL dtaGetPackDirectAccess(const char *fileName, int *offset)   // 0x100049f1
{
    C_DtaLock lock;
    HANDLE result = INVALID_HANDLE_VALUE;
    int handle = -1;
    if (fileName != nullptr && offset != nullptr) {
        // Look the file up without recording it.
        const HANDLE fqlRead = g_fql.readFile;
        const HANDLE fqlWrite = g_fql.writeFile;
        g_fql.readFile = nullptr;
        g_fql.writeFile = nullptr;
        handle = OpenFromArchives(fileName);
        g_fql.readFile = fqlRead;
        g_fql.writeFile = fqlWrite;

        if (handle < 0) {
            result = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_RANDOM_ACCESS | FILE_ATTRIBUTE_NORMAL, nullptr);
            *offset = 0;
        } else {
            *offset = static_cast<int>(g_openFiles[handle].dataOffset);
            const int table = FindArchiveTable(g_openFiles[handle].file);
            if (table >= 0) {
                result = CreateFileA(g_archiveTables[table].fileName.c_str(), GENERIC_READ,
                                     FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                     FILE_FLAG_RANDOM_ACCESS | FILE_ATTRIBUTE_NORMAL, nullptr);
            }
        }
    }
    lock.Unlock();
    // Quirk kept from the original: the test is != 0, so a lookup that got handle 0 leaves
    // that file open.
    if (handle != 0)
        dtaClose(handle);
    return result;
}

} // extern "C"
