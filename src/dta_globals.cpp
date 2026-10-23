// Global state of the DLL. The definitions keep the order of the original's static
// initialisers (0x10001b40..0x10001e23), so they are destroyed in the same order when the
// DLL unloads: the leak report first, then the lock, then the tables.
#include "dta_internal.h"

#include <cstdio>
#include <cstring>

std::vector<S_DtaOpenFile> g_openFiles;
std::vector<S_DtaArchiveTable> g_archiveTables;
std::vector<S_DtaSearchSlot> g_searchOrder;
std::vector<S_DtaFileLog> g_fileLogs;
std::vector<int> g_fqlExtensionFilter;
std::vector<int> g_fqlHandles;
C_CriticalSection g_lock;
S_DtaLeakCounter g_leaks;

dtaErrorCallback g_errorCallback = nullptr;
bool g_preferArchives = false;
S_DtaFql g_fql;

C_DtaLock::C_DtaLock()
{
    g_lock.Enter();
}

C_DtaLock::~C_DtaLock()
{
    Unlock();
}

void C_DtaLock::Unlock()
{
    if (m_locked) {
        m_locked = false;
        g_lock.Leave();
    }
}

S_DtaLeakCounter::~S_DtaLeakCounter()
{
    if (!report)
        return;

    char message[512];
    char line[124];
    message[0] = '\0';
    if (references != 0) {
        std::snprintf(line, sizeof(line), "Not released:  %d  reference(s) of Dta_read.\n", references);
        std::strcat(message, line);
    }
    if (objects != 0) {
        std::snprintf(line, sizeof(line), "Not released:  %d  Dta_read(s).\n", objects);
        std::strcat(message, line);
    }
    if (std::strlen(message) != 0)
        MessageBoxA(nullptr, message, "Dta_read error message", MB_OK);
}

int DtaRand()
{
    // The multi-threaded C runtime keeps the seed per thread, starting at 1.
    thread_local uint32_t seed = 1;
    seed = seed * 214013u + 2531011u;
    return static_cast<int>((seed >> 16) & 0x7FFF);
}

extern "C" {

RW_DATA_API dtaErrorCallback RW_DATA_CALL dtaSetCallbackERR(dtaErrorCallback callback)  // 0x10009e3e
{
    C_DtaLock lock;
    const dtaErrorCallback previous = g_errorCallback;
    g_errorCallback = callback;
    return previous;
}

RW_DATA_API void RW_DATA_CALL dtaDumpMemoryLeaks(bool enable)  // 0x100096b0
{
    g_leaks.report = enable;
}

} // extern "C"
