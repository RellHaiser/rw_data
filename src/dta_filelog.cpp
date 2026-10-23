// File logs: text files listing the names opened with dtaOpen, filtered by directory
// prefixes and extensions.
#include "dta_internal.h"

#include <algorithm>
#include <cstring>

namespace {

// Packs an extension argument (1..3 characters) the way PackExtension packs a name's.
bool PackExtensionArgument(const char *ext, int &packed)
{
    if (ext == nullptr)
        return false;
    const size_t length = std::strlen(ext);
    if (static_cast<int>(length) < 1 || static_cast<int>(length) > 3)
        return false;
    char upper[4];
    std::strcpy(upper, ext);
    UpperCase(upper);
    packed = 0;
    std::memcpy(&packed, upper, length);
    return true;
}

bool IsOpenLog(int log)
{
    return static_cast<uint32_t>(log) < g_fileLogs.size() && g_fileLogs[log].handle >= 0;
}

void WriteLogLine(const S_DtaFileLog &log, const char *fileName)
{
    // (The original built the line in a 516-byte buffer.)
    const std::string line = log.pathBefore + fileName;
    dtaWrite(log.handle, line.c_str(), static_cast<int>(line.size()));
    dtaWrite(log.handle, "\r\n", 2);
}

} // namespace

// `fileName` is upper case.
void FileLogRecord(const char *fileName)   // 0x1000e3d0
{
    // The last log with a directory the name starts with ...
    const int nameLength = static_cast<int>(std::strlen(fileName));
    int log = static_cast<int>(g_fileLogs.size());
    int dir = -1;
    do {
        if (log-- == 0)
            break;
        const std::vector<std::string> &dirs = g_fileLogs[log].dirs;
        dir = static_cast<int>(dirs.size());
        while (dir-- > 0) {
            const int dirLength = static_cast<int>(dirs[dir].size());
            if (nameLength >= dirLength && std::strncmp(dirs[dir].c_str(), fileName, dirLength) == 0)
                break;
        }
    } while (dir < 0);
    if (log >= 0) {
        WriteLogLine(g_fileLogs[log], fileName);
        return;
    }

    // ... else the last one with its extension.
    const int extension = PackExtension(fileName);
    log = static_cast<int>(g_fileLogs.size());
    int index = -1;
    do {
        if (log-- == 0)
            break;
        const std::vector<int> &extensions = g_fileLogs[log].extensions;
        index = static_cast<int>(extensions.size());
        while (index-- > 0 && extensions[index] != extension) {
        }
    } while (index < 0);
    if (log >= 0)
        WriteLogLine(g_fileLogs[log], fileName);
}

extern "C" {

RW_DATA_API int RW_DATA_CALL dtaOpenFileLog(const char *fileName, int flags)   // 0x10008a0c
{
    C_DtaLock lock;
    S_DtaFileLog log;
    log.handle = dtaOpenWrite(fileName, flags);
    if (log.handle < 0)
        return -1;

    // Quirk kept from the original: the search from the end stops at the first log that is
    // still open (the test is inverted), so opening a second log takes over the last open
    // log's slot (and its filters) and leaves the old file open. Closed slots are not reused.
    int slot = static_cast<int>(g_fileLogs.size());
    do {
        if (slot-- == 0)
            break;
    } while (g_fileLogs[slot].handle == -1);
    if (slot < 0) {
        g_fileLogs.push_back(log);
        return static_cast<int>(g_fileLogs.size()) - 1;
    }
    g_fileLogs[slot].handle = log.handle;
    return slot;
}

RW_DATA_API bool RW_DATA_CALL dtaCloseFileLog(int log)   // 0x10009096
{
    C_DtaLock lock;
    if (!IsOpenLog(log))
        return false;
    S_DtaFileLog &entry = g_fileLogs[log];
    dtaClose(entry.handle);
    entry.handle = -1;
    entry.extensions.clear();
    entry.dirs.clear();
    // (The original freed the prefix without clearing the pointer; setting a new prefix
    // on the closed log then freed it again.)
    entry.pathBefore.clear();
    return true;
}

RW_DATA_API bool RW_DATA_CALL dtaAddDir(int log, const char *dir)   // 0x10008e34
{
    C_DtaLock lock;
    if (!IsOpenLog(log) || dir == nullptr)
        return false;

    std::string upper = dir;
    UpperCase(upper);
    // Directories that are a prefix of the new one, or that it is a prefix of, are replaced.
    std::vector<std::string> &dirs = g_fileLogs[log].dirs;
    for (size_t i = dirs.size(); i-- > 0;) {
        const size_t length = std::min(dirs[i].size(), upper.size());
        if (std::strncmp(dirs[i].c_str(), upper.c_str(), length) == 0)
            dirs.erase(dirs.begin() + static_cast<std::ptrdiff_t>(i));
    }
    dirs.push_back(upper);
    return true;
}

RW_DATA_API bool RW_DATA_CALL dtaAddExtension(int log, const char *ext)   // 0x10008c67
{
    C_DtaLock lock;
    int packed;
    if (!IsOpenLog(log) || !PackExtensionArgument(ext, packed))
        return false;
    std::vector<int> &extensions = g_fileLogs[log].extensions;
    if (std::find(extensions.begin(), extensions.end(), packed) == extensions.end())
        extensions.push_back(packed);
    return true;
}

RW_DATA_API bool RW_DATA_CALL dtaSetPathBeforeLogItems(int log, const char *path)   // 0x10008b37
{
    C_DtaLock lock;
    if (static_cast<uint32_t>(log) >= g_fileLogs.size())
        return false;
    std::string &prefix = g_fileLogs[log].pathBefore;
    prefix.clear();
    if (path != nullptr) {
        prefix = path;
        UpperCase(prefix);
    }
    return true;
}

} // extern "C"
