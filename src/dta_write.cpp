// Writing files: dtaOpenWrite, dtaWrite, dtaFlush, and dtaBin2Text.
#include "dta_internal.h"

#include <cstring>

extern "C" {

RW_DATA_API int RW_DATA_CALL dtaOpenWrite(const char *fileName, int flags)   // 0x10008062
{
    C_DtaLock lock;
    const DWORD attributes = (flags & DTA_WRITE_HIDDEN) ? FILE_ATTRIBUTE_HIDDEN : FILE_ATTRIBUTE_NORMAL;
    const DWORD disposition = (flags & DTA_WRITE_CREATE_ALWAYS) ? CREATE_ALWAYS : OPEN_ALWAYS;

    // With DTA_WRITE_TEMP_FILE the data goes to "<name>.tmp", which starts as a copy of the
    // file unless it is recreated. (The original built the name in a 512-byte buffer.)
    std::string tempName;
    const char *path = fileName;
    if (flags & DTA_WRITE_TEMP_FILE) {
        tempName = std::string(fileName) + ".tmp";
        if (disposition == CREATE_ALWAYS)
            DeleteFileA(tempName.c_str());
        else
            CopyFileA(fileName, tempName.c_str(), FALSE);
        path = tempName.c_str();
    }

    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, nullptr, disposition, attributes, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if ((flags & DTA_WRITE_CLEAR_READONLY) == 0)
            return -1;
        const DWORD current = GetFileAttributesA(path);
        if (current == INVALID_FILE_ATTRIBUTES)
            return -1;
        SetFileAttributesA(path, current & ~FILE_ATTRIBUTE_READONLY);
        file = CreateFileA(path, GENERIC_WRITE, 0, nullptr, disposition, attributes, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return -1;
    }

    S_DtaOpenFile open;
    open.file = file;
    open.flags = DTA_FILE_WRITE | DTA_FILE_DISK;
    if (flags & DTA_WRITE_TEMP_FILE) {
        open.flags |= DTA_FILE_TEMP;
        open.tempFileName = tempName;
    }
    open.blockCount = 1;
    open.cursor.bufferSize = DTA_BLOCK_SIZE;
    open.buffer.resize(DTA_BLOCK_SIZE);   // allocated by the original too, though unused
    return StoreOpenFile(std::move(open));
}

RW_DATA_API int RW_DATA_CALL dtaWrite(int handle, const void *buffer, int size)   // 0x100085bb
{
    C_DtaLock lock;
    if (static_cast<uint32_t>(handle) >= g_openFiles.size())
        return -1;
    S_DtaOpenFile &file = g_openFiles[handle];
    if (file.IsFree())
        return -1;
    if ((file.flags & DTA_FILE_WRITE) == 0 || (file.flags & DTA_FILE_DISK) == 0 || buffer == nullptr)
        return -1;

    DWORD written;
    if (!WriteFile(file.file, buffer, static_cast<DWORD>(size), &written, nullptr) ||
        written != static_cast<DWORD>(size)) {
        // A failed write keeps the temporary file from replacing the target.
        if (file.flags & DTA_FILE_TEMP)
            file.flags |= DTA_FILE_WRITE_ERROR;
        return -1;
    }
    return size;
}

RW_DATA_API bool RW_DATA_CALL dtaFlush(int handle)   // 0x100087be
{
    C_DtaLock lock;
    if (static_cast<uint32_t>(handle) >= g_openFiles.size())
        return false;
    const S_DtaOpenFile &file = g_openFiles[handle];
    if (file.IsFree())
        return false;
    if ((file.flags & DTA_FILE_WRITE) == 0 || (file.flags & DTA_FILE_DISK) == 0)
        return false;
    return FlushFileBuffers(file.file) != FALSE;
}

RW_DATA_API int RW_DATA_CALL dtaBin2Text(char *buffer, int size)   // 0x10007f37
{
    // (A negative size made the original run over the whole address space.)
    if (buffer == nullptr || size <= 0)
        return 0;

    C_DtaLock lock;
    // Positions of the '\r' characters, from the end; the last character is not checked.
    std::vector<int> positions;
    for (uint32_t i = static_cast<uint32_t>(size) - 1; i-- > 0;) {
        if (buffer[i] == '\r')
            positions.push_back(static_cast<int>(i));
    }
    for (const int position : positions) {
        std::memmove(buffer + position, buffer + position + 1, size - (position + 1));
        --size;
    }
    return size;
}

} // extern "C"
