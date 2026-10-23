// rw_data.dll — Illusion Softworks' virtual file system for Hidden & Dangerous 2.
//
// Every game file goes through these functions: a name is looked up in the mounted .dta
// archives and on disk (in an order chosen per call), and the returned handle reads the
// file transparently (archive data is encrypted, split in 32 KB blocks and compressed).
// The DLL also writes files (optionally through a temporary file renamed on close), keeps
// "file logs" of the names that were opened, and can record the archive reads of a load
// into one sequential FQL file and play them back later.
//
// This header is the public interface of the source port. The functions are exported
// __stdcall with their decorated names (_dtaOpen@8, ...) and the ordinals of the original.
#pragma once

#include <cstdint>

#ifndef RW_DATA_API
#ifdef RW_DATA_BUILD
#define RW_DATA_API
#else
#define RW_DATA_API __declspec(dllimport)
#endif
#endif

#ifndef RW_DATA_CALL
#define RW_DATA_CALL __stdcall
#endif

#ifdef _MSC_VER
#define RW_DATA_THISCALL
#else
#define RW_DATA_THISCALL __attribute__((thiscall))
#endif

struct _FILETIME;

// A mounted .dta archive, returned by dtaCreate. The layout of the virtual table is the one
// of the original MSVC 6 class, so objects can be shared with code built by other compilers:
// slot 0 is MSVC's scalar deleting destructor (call Release instead), all methods __thiscall.
class C_DtaArchive {
public:
    virtual void *RW_DATA_THISCALL DeletingDestructor(unsigned flags) = 0;  // slot 0x00
    // Reference counting; Release destroys the archive when the count reaches zero.
    virtual int RW_DATA_THISCALL AddRef() = 0;                              // slot 0x04
    virtual int RW_DATA_THISCALL Release() = 0;                             // slot 0x08
    // Applies a 64-bit key in two XOR steps (see C_DtaRead::XorKey). The second call
    // decrypts the archive's file table.
    virtual bool RW_DATA_THISCALL XorKey(uint32_t low, uint32_t high) = 0;  // slot 0x0C
    virtual uint64_t RW_DATA_THISCALL GetKey() = 0;                         // slot 0x10
    // Decrypts the file table with a plain key.
    virtual bool RW_DATA_THISCALL SetKey(uint32_t low, uint32_t high) = 0;  // slot 0x14
    // Global switch: dtaOpen looks in the archives before the disk. Returns the old value.
    virtual bool RW_DATA_THISCALL SetPreferArchives(bool prefer) = 0;       // slot 0x18
    // Position in the archive search order (0 = searched first); returns the new position.
    virtual int RW_DATA_THISCALL SetPriority(int priority) = 0;             // slot 0x1C
    virtual int RW_DATA_THISCALL GetPriority() = 0;                         // slot 0x20
    virtual const char *RW_DATA_THISCALL GetName() = 0;                     // slot 0x24

protected:
    ~C_DtaArchive() = default;
};

// Error codes passed to the error callback.
enum E_DtaError {
    DTA_ERROR_OPEN = 1,      // the file could not be opened
    DTA_ERROR_SIZE = 2,      // a read returned fewer bytes than expected / size mismatch
    DTA_ERROR_CHECKSUM = 3,  // a checksum of an ISD1 archive (or FQL file) does not match
    DTA_ERROR_FORMAT = 4,    // not a .dta archive (the magic is neither ISD0 nor ISD1)
    DTA_ERROR_MEMORY = 5,    // out of memory
    DTA_ERROR_READ = 6,      // ReadFile failed
};

// Called for archive errors. `archive` is null for errors that happen while an archive is
// being opened and for errors of the FQL file (then `fileName` is the FQL file's name).
typedef void(__cdecl *dtaErrorCallback)(C_DtaArchive *archive, const char *fileName, int error);

// dtaOpenWrite flags.
enum {
    DTA_WRITE_HIDDEN = 0x1,           // create the file with FILE_ATTRIBUTE_HIDDEN
    DTA_WRITE_TEMP_FILE = 0x100,      // write "<name>.tmp"; dtaClose renames it over <name>
    DTA_WRITE_CREATE_ALWAYS = 0x10000,// truncate (CREATE_ALWAYS) instead of OPEN_ALWAYS
    DTA_WRITE_CLEAR_READONLY = 0x100000, // on failure, clear the read-only attribute and retry
};

constexpr int DTA_INVALID_HANDLE = -1;

extern "C" {

// Archives ------------------------------------------------------------------------------

// Mounts an archive and appends it to the search order; null when the file is missing
// or is not an archive. The archive is unusable until its key is set (XorKey / SetKey).
RW_DATA_API C_DtaArchive *RW_DATA_CALL dtaCreate(const char *fileName);
// Opens the .dta containing `fileName` for direct access and stores the offset of the
// file's data in it; for a file that is not in an archive, opens the file itself (offset 0).
RW_DATA_API void *RW_DATA_CALL dtaGetPackDirectAccess(const char *fileName, int *offset);
// Installs the error callback; returns the previous one.
RW_DATA_API dtaErrorCallback RW_DATA_CALL dtaSetCallbackERR(dtaErrorCallback callback);
// Enables the "Not released ..." message box shown when the DLL unloads with archives alive.
RW_DATA_API void RW_DATA_CALL dtaDumpMemoryLeaks(bool enable);

// Files ---------------------------------------------------------------------------------

// Opens a file for reading; -1 on failure. The disk is searched before the archives
// unless `archivesFirst` (or C_DtaArchive::SetPreferArchives) is set.
RW_DATA_API int RW_DATA_CALL dtaOpen(const char *fileName, bool archivesFirst);
// Opens a file on disk for writing (DTA_WRITE_* flags); -1 on failure.
RW_DATA_API int RW_DATA_CALL dtaOpenWrite(const char *fileName, int flags);
RW_DATA_API int RW_DATA_CALL dtaRead(int handle, void *buffer, int size);
RW_DATA_API int RW_DATA_CALL dtaWrite(int handle, const void *buffer, int size);
// origin: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END. Returns the new position or -1.
RW_DATA_API int RW_DATA_CALL dtaSeek(int handle, int position, int origin);
RW_DATA_API bool RW_DATA_CALL dtaClose(int handle);
RW_DATA_API bool RW_DATA_CALL dtaFlush(int handle);
// Last-write time: of the archived file itself, or (`containerTime`, and for disk files)
// of the file on disk.
RW_DATA_API bool RW_DATA_CALL dtaGetTime(int handle, _FILETIME *time, bool containerTime);
RW_DATA_API bool RW_DATA_CALL dtaDelete(const char *fileName);
// Removes the '\r' characters of a buffer in place (except a trailing one); returns the
// new size.
RW_DATA_API int RW_DATA_CALL dtaBin2Text(char *buffer, int size);

// File logs: text files listing the names opened with dtaOpen ---------------------------

// Opens a log (dtaOpenWrite flags); returns the log's index or -1.
RW_DATA_API int RW_DATA_CALL dtaOpenFileLog(const char *fileName, int flags);
RW_DATA_API bool RW_DATA_CALL dtaCloseFileLog(int log);
// A log lists the names starting with one of its directories ...
RW_DATA_API bool RW_DATA_CALL dtaAddDir(int log, const char *dir);
// ... or with one of its extensions (at most 3 characters).
RW_DATA_API bool RW_DATA_CALL dtaAddExtension(int log, const char *ext);
// Prefix written before every name of the log.
RW_DATA_API bool RW_DATA_CALL dtaSetPathBeforeLogItems(int log, const char *path);

// FQL: record the archive reads of a load into one file and play them back --------------

// Starts recording into a new FQL file.
RW_DATA_API bool RW_DATA_CALL dtaCreateFQL(const char *fileName);
// Finishes the recording.
RW_DATA_API void RW_DATA_CALL dtaCloseFQL();
// Starts playing back an FQL file: archive reads come from it instead of the archives.
RW_DATA_API bool RW_DATA_CALL dtaFQLBegin(const char *fileName);
RW_DATA_API void RW_DATA_CALL dtaFQLEnd();
// Files with these extensions are not recorded.
RW_DATA_API bool RW_DATA_CALL dtaAddFQLExtensionFilter(const char *ext);
RW_DATA_API void RW_DATA_CALL dtaClearFQLExtensionFilter();
// Does nothing in this build.
RW_DATA_API void RW_DATA_CALL dtaSetDebugFQLExt(int value);

} // extern "C"
