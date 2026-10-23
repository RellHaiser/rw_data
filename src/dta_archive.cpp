// Mounted archives: C_DtaRead and dtaCreate.
#include "dta_archive.h"

#include <cstring>
#include <new>

namespace {

// Index in g_searchOrder of an archive, or -1.
int FindSearchSlot(const C_DtaRead *archive)
{
    int slot = static_cast<int>(g_searchOrder.size());
    do {
        if (slot-- == 0)
            break;
    } while (g_searchOrder[slot].archive != archive);
    return slot;
}

uint64_t MakeKey(uint32_t low, uint32_t high)
{
    return static_cast<uint64_t>(high) << 32 | low;
}

} // namespace

C_DtaRead::C_DtaRead(const char *fileName, bool &ok)
{
    ok = false;
    // A random mask built from four rand() values.
    for (int i = 0; i < 4; ++i)
        m_keyMask = (m_keyMask << 16) | static_cast<uint16_t>(DtaRand());

    m_file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_FLAG_RANDOM_ACCESS | FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_file == INVALID_HANDLE_VALUE) {
        if (g_errorCallback)
            g_errorCallback(nullptr, fileName, DTA_ERROR_OPEN);
        return;
    }

    uint32_t magic;
    DWORD read;
    if (!ReadFile(m_file, &magic, sizeof(magic), &read, nullptr)) {
        if (g_errorCallback)
            g_errorCallback(nullptr, fileName, DTA_ERROR_READ);
        return;
    }
    if (read != sizeof(magic)) {
        if (g_errorCallback)
            g_errorCallback(nullptr, fileName, DTA_ERROR_SIZE);
        return;
    }

    m_version = -1;
    if (magic == DTA_MAGIC_ISD0)
        m_version = 0;
    else if (magic == DTA_MAGIC_ISD1)
        m_version = 1;
    if (m_version < 0) {
        if (g_errorCallback)
            g_errorCallback(nullptr, fileName, DTA_ERROR_FORMAT);
        return;
    }

    // The original stored the name in a char[260] with strcpy.
    S_DtaArchiveTable table;
    table.file = m_file;
    table.fileName = fileName;
    table.version = m_version;
    g_archiveTables.push_back(std::move(table));
    g_searchOrder.push_back({this, static_cast<int>(g_archiveTables.size()) - 1});
    AddRef();
    m_keyMask = ~m_keyMask;
    m_fileName = fileName;
    ++g_leaks.objects;
    ok = true;
}

// Runs inside Release, under the lock.
C_DtaRead::~C_DtaRead()
{
    if (m_file != INVALID_HANDLE_VALUE)
        CloseHandle(m_file);

    const int table = FindArchiveTable(m_file);
    if (table >= 0) {
        g_archiveTables[table].entries.clear();
        g_archiveTables.erase(g_archiveTables.begin() + table);
    }
    // When the table was not found every index is decremented, like the original did.
    for (int slot = static_cast<int>(g_searchOrder.size()); slot-- > 0;) {
        if (g_searchOrder[slot].archive == this)
            g_searchOrder.erase(g_searchOrder.begin() + slot);
        else if (table < g_searchOrder[slot].table)
            --g_searchOrder[slot].table;
    }
    // Files still open in the archive become free slots.
    for (int handle = static_cast<int>(g_openFiles.size()); handle-- > 0;) {
        if (g_openFiles[handle].file == m_file)
            g_openFiles[handle] = S_DtaOpenFile();
    }
    --g_leaks.objects;
}

// MSVC's scalar deleting destructor, kept for the layout of the virtual table.
void *C_DtaRead::DeletingDestructor(unsigned flags)
{
    this->~C_DtaRead();
    if (flags & 1)
        ::operator delete(this);
    return this;
}

int C_DtaRead::AddRef()
{
    {
        C_DtaLock lock;
        ++g_leaks.references;
    }
    return static_cast<int>(++m_refCount);
}

// The count is unsigned: releasing an archive that was never referenced (a failed
// dtaCreate) wraps it around and leaks the object, as in the original.
int C_DtaRead::Release()
{
    C_DtaLock lock;
    --g_leaks.references;
    --m_refCount;
    const int remaining = static_cast<int>(m_refCount);
    if (m_refCount < 1)
        DeletingDestructor(1);
    return remaining;
}

// The game applies its key in two steps: XorKey(key ^ r) with a random r, then
// XorKey(GetKey() ^ key). The first call only stores the masked value; the second one
// recovers the key ((key ^ r ^ mask) ^ key ^ (mask ^ key ^ r) = key) and loads the table.
bool C_DtaRead::XorKey(uint32_t low, uint32_t high)
{
    C_DtaLock lock;
    const uint64_t value = MakeKey(low, high);
    if (m_key == 0) {
        m_key = value ^ m_keyMask;
        m_keyMask ^= value;
        return true;
    }
    const uint64_t key = value ^ m_keyMask;
    m_keyMask = 0;
    return LoadFileTable(key, lock);
}

uint64_t C_DtaRead::GetKey()
{
    return m_key;
}

bool C_DtaRead::SetKey(uint32_t low, uint32_t high)
{
    C_DtaLock lock;
    return LoadFileTable(MakeKey(low, high), lock);
}

bool C_DtaRead::LoadFileTable(uint64_t key, C_DtaLock &lock)
{
    if (SetFilePointer(m_file, 4, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        GetLastError() != NO_ERROR) {
        return false;
    }

    uint32_t tableOffset = 0;
    uint32_t tableSize = 0;
    uint32_t tableChecksum = 0;
    DWORD read;
    if (m_version == 0) {
        uint32_t header[4];
        if (!ReadFile(m_file, header, sizeof(header), &read, nullptr) || read != sizeof(header))
            return false;
        DecryptBuffer(header, sizeof(header), key);
        tableOffset = header[1];
        tableSize = header[2];
    } else if (m_version == 1) {
        const DWORD fileSize = SetFilePointer(m_file, 0, nullptr, FILE_END);
        if (g_errorCallback && fileSize < 0x18)
            ReportError(DTA_ERROR_SIZE);
        SetFilePointer(m_file, 0, nullptr, FILE_BEGIN);

        // magic, then 20 encrypted bytes: ?, table offset, table size, table checksum,
        // and the checksum of all 24 bytes (decrypted, with this field zeroed).
        uint8_t header[0x18];
        if (!ReadFile(m_file, header, sizeof(header), &read, nullptr)) {
            lock.Unlock();
            ReportError(DTA_ERROR_READ);
            return false;
        }
        if (read != sizeof(header)) {
            lock.Unlock();
            ReportError(DTA_ERROR_SIZE);
            return false;
        }
        uint32_t fields[5];
        std::memcpy(fields, header + 4, sizeof(fields));
        DecryptBuffer(fields, sizeof(fields), key);
        const uint32_t headerChecksum = fields[4];
        fields[4] = 0;
        std::memcpy(header + 4, fields, sizeof(fields));
        if (g_errorCallback && headerChecksum != Checksum16(header, sizeof(header), CHECKSUM_SEED))
            ReportError(DTA_ERROR_CHECKSUM);
        tableOffset = fields[1];
        tableSize = fields[2];
        tableChecksum = fields[3];
        if (g_errorCallback && fileSize != tableSize + tableOffset)
            ReportError(DTA_ERROR_SIZE);
    }

    const int table = FindArchiveTable(m_file);
    if (table < 0)
        return false;
    S_DtaArchiveTable &archive = g_archiveTables[table];
    archive.key = key;
    archive.entries.resize(tableSize / sizeof(S_DtaFileEntry), S_DtaFileEntry{});

    // The original read `tableSize` bytes straight into the entries, past their end when
    // the size is not a multiple of an entry; this reads into a buffer of the full size
    // that starts with the current entries (what a short read leaves in place).
    std::vector<uint8_t> raw(tableSize);
    if (!archive.entries.empty())
        std::memcpy(raw.data(), archive.entries.data(), archive.entries.size() * sizeof(S_DtaFileEntry));
    SetFilePointer(m_file, tableOffset, nullptr, FILE_BEGIN);
    read = 0;
    if (!ReadFile(m_file, raw.data(), tableSize, &read, nullptr) && g_errorCallback)
        ReportError(DTA_ERROR_READ);
    if (read != tableSize && g_errorCallback)
        ReportError(DTA_ERROR_SIZE);
    if (m_version != 0 && g_errorCallback &&
        tableChecksum != Checksum16(raw.data(), tableSize, CHECKSUM_SEED)) {
        ReportError(DTA_ERROR_CHECKSUM);
    }
    DecryptBuffer(raw.data(), tableSize, key);
    if (!archive.entries.empty())
        std::memcpy(archive.entries.data(), raw.data(), archive.entries.size() * sizeof(S_DtaFileEntry));
    return true;
}

void C_DtaRead::ReportError(int error)
{
    if (g_errorCallback)
        g_errorCallback(this, m_fileName.c_str(), error);
}

bool C_DtaRead::SetPreferArchives(bool prefer)
{
    C_DtaLock lock;
    const bool previous = g_preferArchives;
    g_preferArchives = prefer;
    return previous;
}

int C_DtaRead::SetPriority(int priority)
{
    C_DtaLock lock;
    if (priority < 0)
        priority = 0;
    else if (static_cast<uint32_t>(priority) > g_searchOrder.size() - 1)
        priority = static_cast<int>(g_searchOrder.size()) - 1;

    const int slot = FindSearchSlot(this);
    // The original also moved a slot when the archive was not in the search order (-1),
    // reading and erasing outside the vector.
    if (slot >= 0 && slot != priority) {
        const S_DtaSearchSlot entry = g_searchOrder[slot];
        g_searchOrder.erase(g_searchOrder.begin() + slot);
        g_searchOrder.insert(g_searchOrder.begin() + priority, entry);
    }
    return priority;
}

int C_DtaRead::GetPriority()
{
    C_DtaLock lock;
    return FindSearchSlot(this);
}

const char *C_DtaRead::GetName()
{
    return m_fileName.c_str();
}

extern "C" RW_DATA_API C_DtaArchive *RW_DATA_CALL dtaCreate(const char *fileName)   // 0x10003269
{
    C_DtaLock lock;
    bool ok = false;
    C_DtaRead *archive = new (std::nothrow) C_DtaRead(fileName, ok);
    lock.Unlock();
    if (archive == nullptr || !ok) {
        if (archive != nullptr)
            archive->Release();
        return nullptr;
    }
    return archive;
}
