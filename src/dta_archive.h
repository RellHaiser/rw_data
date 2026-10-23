// The archive object behind C_DtaArchive ("Dta_read" in the original, vtable 0x1003301c).
#pragma once

#include "dta_internal.h"

class C_DtaRead final : public C_DtaArchive {
public:
    // Opens the archive and reads its magic; on success registers its table and appends
    // it to the search order (with one reference) and sets `ok`.
    C_DtaRead(const char *fileName, bool &ok);                                  // 0x1000333f
    ~C_DtaRead();                                                               // 0x1000433b

    void *RW_DATA_THISCALL DeletingDestructor(unsigned flags) override;         // 0x1000c000
    int RW_DATA_THISCALL AddRef() override;                                     // 0x100046a8
    int RW_DATA_THISCALL Release() override;                                    // 0x1000470d
    bool RW_DATA_THISCALL XorKey(uint32_t low, uint32_t high) override;         // 0x10003763
    uint64_t RW_DATA_THISCALL GetKey() override;                                // 0x10003d84
    bool RW_DATA_THISCALL SetKey(uint32_t low, uint32_t high) override;         // 0x10003d9f
    bool RW_DATA_THISCALL SetPreferArchives(bool prefer) override;              // 0x100047db
    int RW_DATA_THISCALL SetPriority(int priority) override;                    // 0x10004840
    int RW_DATA_THISCALL GetPriority() override;                                // 0x10004955
    const char *RW_DATA_THISCALL GetName() override;                            // 0x100047c3

private:
    // Reads and decrypts the file table (the common part of XorKey and SetKey). Leaves
    // the lock on every path.
    bool LoadFileTable(uint64_t key, C_DtaLock &lock);
    void ReportError(int error);

    // The key is kept XOR-masked with a random value (inverted once the archive is open).
    uint64_t m_keyMask = 0;
    uint64_t m_key = 0;
    uint32_t m_refCount = 0;
    HANDLE m_file = INVALID_HANDLE_VALUE;
    int m_version = -1;           // 0 = ISD0, 1 = ISD1
    std::string m_fileName;
};
