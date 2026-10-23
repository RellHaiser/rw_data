# How rw_data.dll works

`rw_data.dll` is the data-file layer of Hidden & Dangerous 2 (Illusion Softworks, 2003–2004).
The game, the LS3D engine (`LS3DF.dll`, `LS3DRF.dll`) and the dedicated server read and write
their data files through it. This document describes what each function does and the formats
and algorithms behind them. It is based on the original binary (an MSVC 6 debug build of
`D:\hd2project\_src\rw_data\rw_data.cpp`) and on the source port in this folder, which was
checked against the original on all of the game's archives (see `README.md`).

Addresses (`0x1000xxxx`) are those of the original DLL; the C++ names are those of the port.

## Contents

1. [Overview](#1-overview)
2. [Concepts](#2-concepts): handles, archives and the search order, the key, locking, errors
3. [Archive format](#3-archive-format)
4. [Algorithms](#4-algorithms): name hash, cipher, checksum, LZSS, WAV, reading blocks
5. [Function reference](#5-function-reference)
   - [Archives](#51-archives)
   - [Opening and closing files](#52-opening-and-closing-files)
   - [Reading and seeking](#53-reading-and-seeking)
   - [Writing](#54-writing)
   - [Error reporting and diagnostics](#55-error-reporting-and-diagnostics)
   - [File logs](#56-file-logs)
   - [FQL recording and playback](#57-fql-recording-and-playback)
6. [The archive object (`C_DtaArchive`)](#6-the-archive-object-c_dtaarchive)
7. [Internal functions](#7-internal-functions)
8. [Behaviour worth knowing](#8-behaviour-worth-knowing)

---

## 1. Overview

The DLL is a small virtual file system:

- **Archives.** `dtaCreate` mounts a `.dta` archive and appends it to a search order. An
  archive holds many files, each encrypted with the archive's 64-bit key, split into 32 KB
  blocks and compressed (LZSS, or a lossy DPCM scheme for 16-bit WAV sound).
- **Files.** `dtaOpen` looks a name up on disk and in the archives, in an order chosen by the
  caller, and returns a small integer handle. `dtaRead` / `dtaSeek` then work the same way
  for a plain disk file and an archived one; decryption and decompression are transparent.
- **Writing.** `dtaOpenWrite` / `dtaWrite` write plain disk files, optionally through a
  `<name>.tmp` file that replaces the target only when it is closed without errors.
- **File logs.** Text files that list the names opened with `dtaOpen`, filtered by directory
  or extension (for example to find out which files a level needs).
- **FQL files.** A recording of the archive reads made during a level load, compressed into
  one sequential file; a later load can play it back instead of seeking through the
  archives.

All 26 exports are `extern "C" __stdcall` and exported only under their decorated names
(`_dtaOpen@8` and so on), with ordinals 1–26 in alphabetical order.

| Group | Functions |
|---|---|
| Archives | `dtaCreate`, `dtaGetPackDirectAccess` |
| Files | `dtaOpen`, `dtaRead`, `dtaSeek`, `dtaClose`, `dtaGetTime`, `dtaDelete`, `dtaBin2Text` |
| Writing | `dtaOpenWrite`, `dtaWrite`, `dtaFlush` |
| Errors / diagnostics | `dtaSetCallbackERR`, `dtaDumpMemoryLeaks` |
| File logs | `dtaOpenFileLog`, `dtaCloseFileLog`, `dtaAddDir`, `dtaAddExtension`, `dtaSetPathBeforeLogItems` |
| FQL | `dtaCreateFQL`, `dtaCloseFQL`, `dtaFQLBegin`, `dtaFQLEnd`, `dtaAddFQLExtensionFilter`, `dtaClearFQLExtensionFilter`, `dtaSetDebugFQLExt` |

---

## 2. Concepts

### 2.1 Handles

A handle is an index into the DLL's table of open files (`g_openFiles`, 0x1004374c, 0x60
bytes per entry in the original). Opening a file takes the **lowest free slot**, or appends
a new one; closing frees the slot. -1 (`DTA_INVALID_HANDLE`) means failure.

Each open file has a 32 KB buffer. For an archived file the slot shares the archive's
Windows file handle (every read seeks first, so many files of one archive can be open at
once); a disk file has its own. A slot records the file's size, its position, which block
is in the buffer, and for archived files the key, the block tables and the WAV header.

Flags of a slot: 0x1 file on disk, 0x2 opened for writing, 0x4 written through a `.tmp`
file, 0x80 a write failed. Read functions refuse write handles and vice versa.

### 2.2 Archives and the search order

`dtaCreate` adds the archive to a **search order** (`g_searchOrder`, 0x100437a0): a list of
(archive, file table) pairs. `dtaOpen` searches it from the front, so archives mounted first
win. The game mounts its archives in this order (`MountDataArchives`, game 0x006dba30):

`PatchX03`, `PatchX02`, `PatchX01`, `SabreSquadron`, `Lang<language>` (or `LangEnglish` if
that is missing), `Patch`, `Models`, `Missions`, `Maps`, `Sounds`, `Scripts`, `Others`,
`Maps_C`, `Maps_U` (all `.dta`)

so patches override the base game. `C_DtaArchive::SetPriority` moves an archive within the
order.

Whether the disk or the archives are searched first is chosen per `dtaOpen` call
(`archivesFirst`) or globally (`C_DtaArchive::SetPreferArchives`): by default a loose file on
disk overrides the archived one.

### 2.3 The key

Every archive has a 64-bit XOR key (the game's keys are in `MountDataArchives`, see
`C++/src/game/app.cpp`). An archive cannot be read until its key is set, either directly with
`SetKey`, or the way the game does it, in two `XorKey` steps that never pass the key itself:

```
archive->XorKey(key ^ r)                 // r: a random value
archive->XorKey(archive->GetKey() ^ key)
```

Internally the archive keeps a random mask `m` (built from four `rand()` calls when it is
created, then inverted). The first `XorKey(v)` stores `GetKey() = v ^ m` and sets `m ^= v`,
so `m == GetKey()`. The second call computes `(GetKey() ^ key) ^ m = key` and loads the file
table with it. See [XorKey](#xorkey-0x10003763).

### 2.4 Locking

One critical section (`g_lock`, 0x10043768) serialises every function, so the DLL can be
called from several threads. It is recursive:
functions call each other while holding it (`FileLogRecord` calls `dtaWrite`, the error
callback may call back into the DLL). The exceptions that take no lock are `dtaFQLBegin`,
`dtaFQLEnd`, `dtaDelete`, `dtaDumpMemoryLeaks`, `GetKey` and `GetName`.

### 2.5 Errors

Functions report failure through their return value (-1 or `false`). In addition, problems
with archive *data* are passed to an optional callback installed with `dtaSetCallbackERR`:

```cpp
void __cdecl callback(C_DtaArchive *archive, const char *fileName, int error);
```

| Code | Name | Meaning |
|---:|---|---|
| 1 | `DTA_ERROR_OPEN` | the archive or FQL file could not be opened |
| 2 | `DTA_ERROR_SIZE` | a read returned fewer bytes than expected, or a size does not add up |
| 3 | `DTA_ERROR_CHECKSUM` | a checksum of an ISD1 archive (or of an FQL file) does not match |
| 4 | `DTA_ERROR_FORMAT` | the file is not an archive (bad magic) |
| 5 | `DTA_ERROR_MEMORY` | out of memory (FQL buffers) |
| 6 | `DTA_ERROR_READ` | `ReadFile` failed |

`archive` is null when the error happens before the archive object exists (opening an
archive) and for FQL errors; `fileName` is then the archive's or the FQL file's name.
Otherwise it is the archive in which the file was found and its name. A checksum error is
only reported; the data is used anyway.

---

## 3. Archive format

All integers are little endian. Encrypted pieces are decrypted **each from its own start**:
byte *i* of a piece is XORed with byte *i* mod 8 of the key, whatever its position in the
archive (see [cipher](#42-cipher)).

### 3.1 Archive header

Two versions exist, told apart by the magic at offset 0:

**ISD0** (`Maps`, `Maps_U`, `missions`, `models`, `Scripts`, `Sounds`):

| Offset | Size | Contents |
|---:|---:|---|
| 0 | 4 | `"ISD0"` |
| 4 | 16 | encrypted: u32 ?, u32 **table offset**, u32 **table size**, u32 ? |

**ISD1** (`SabreSquadron`, `Patch`, `PatchX01`, `LangEnglish`) adds checksums:

| Offset | Size | Contents |
|---:|---:|---|
| 0 | 4 | `"ISD1"` |
| 4 | 20 | encrypted: u32 ?, u32 **table offset**, u32 **table size**, u32 **table checksum**, u32 **header checksum** |

The header checksum is `Checksum16` of the 24 bytes (magic + the decrypted fields, with the
header checksum field zeroed). The table checksum is `Checksum16` of the table as stored
(encrypted). An ISD1 archive must end exactly at table offset + table size.

### 3.2 File table

The table is an array of 0x1C-byte entries, encrypted as one piece, **sorted by hash**:

| Offset | Size | Contents |
|---:|---:|---|
| 0x00 | 4 | hash of the upper-case name: `length << 16 \| (16-bit sum of its bytes)` |
| 0x04 | 4 | offset of the file's header |
| 0x08 | 4 | offset of the file's first block (`dataOffset`) |
| 0x0C | 16 | the last 16 characters of the upper-case name (padded with zero bytes if shorter) |

Names are paths with backslashes, stored upper case (`MAPS\FOO.4DS`); lookups upper-case
the requested name, so they are case-insensitive.

### 3.3 File header and name

At the entry's header offset: a 0x20-byte header, then the name, each encrypted separately.

| Offset | ISD0 | ISD1 |
|---:|---|---|
| 0x00 | u32 ? | u32 ? |
| 0x04 | u32 ? | u32 ? |
| 0x08 | FILETIME (the file's time) | FILETIME |
| 0x10 | u32 decoded size | u32 decoded size |
| 0x14 | u32 block count | u32 block count |
| 0x18 | u16 name length + flag | u32 header checksum (of this header, decrypted, with this field zeroed) |
| 0x1C | — | u16 name length + flag |
| 0x1E | — | u16 checksum of the name and the block tables |

The name length's bit 15 (`0x8000`) says that **whole blocks are encrypted**; without it only
the RIFF header of WAV files is. The name itself (length & 0x7FFF bytes) follows the header.

### 3.4 Blocks

A file is split into blocks that decode to 32 KB each (the last one to the rest). Block *n*
covers bytes `n * 0x8000 .. n * 0x8000 + 0x7FFF` of the file. The first byte of a stored
block is its **type**:

| Type | Encoding |
|---|---|
| 1 | LZSS ([4.4](#44-lzss)) |
| 0, 2–7 | stored: the bytes after the type are the data |
| 8 and up | compressed 16-bit WAV ([4.5](#45-compressed-wav)); the type selects the delta table |

**ISD0** blocks are chained. At `dataOffset`, then after every block:

```
u32   low 16 bits: stored size of this block (type byte included)
      high 16 bits: stored size of the previous block
bytes the stored block
```

The previous block's size lets a reader walk backwards without the table that ISD0 lacks.

**ISD1** puts the tables in front, after the name:

```
u32[blockCount]   low 16 bits: stored size of the block (without the type byte)
                  high 16 bits: checksum of the stored (encrypted) block
u8[blockCount]    the block types (encrypted)
bytes             the blocks, back to back, without their type byte
```

The header's checksum at 0x1E is `Checksum16` chained over the decrypted name, the size
table as stored, and the encrypted type table.

### 3.5 Compressed WAV files

A file whose first block has a type of 8 or more is a compressed WAV. Its 0x2C-byte RIFF
header follows the block tables (ISD1) or the first block's type byte (ISD0), and is kept by
the open file. The first block then repeats the header in front of the samples (the decoder
recognises it by comparing the `"RIFF"`, `"fmt "` and `"data"` fields).

---

## 4. Algorithms

### 4.1 Name hash and lookup

```
upper = toupper(name)                     (ASCII only)
hash  = strlen(upper) << 16 | (sum of the bytes of upper) & 0xFFFF
```

For each archive in the search order, `ArchiveFindEntry` (0x1000e0f0) binary-searches the
sorted table for the hash and steps back to the first entry with it. Each entry with that
hash is then checked: its 16-character name tail against the end of the requested name,
then the full name read from its header. The first full match is opened. An I/O error while
checking a candidate ends the whole lookup with -1 (it does not go on to other archives).

### 4.2 Cipher

`DecryptBuffer` (0x10009bf3) and `EncryptBuffer` (0x10009d24) are the same operation:

```
data[i] ^= key[i % 8]        key = the 64-bit key as 8 little-endian bytes
```

The original works on 8-byte words from the end of the buffer, written as `~(~word ^ key)`,
then on the remaining bytes; the result is a plain XOR.

### 4.3 Checksum

`Checksum16` (0x10009e97), seeded with 0xFF everywhere:

```
for each byte b:
    sum = (sum + b) & 0xFFFF
    sum ^= ~b & 0xFF
```

### 4.4 LZSS

A stream starts with a byte: 0 = stored (the data follows), 1 = compressed. A compressed
stream is a sequence of groups of 16 items, each group preceded by a big-endian 16-bit flag
word read from its most significant bit (the first flag word is at bytes 1–2, the first
item at byte 3):

| Flag | Item |
|---|---|
| 0 | one literal byte |
| 1 | two bytes `DDDDDDDD DDDDLLLL`: copy *L* + 3 bytes (3–18) from *D* bytes back (*D* = 1–4095) |
| 1, *D* = 0 | four bytes `00 0H LL BB`: *HLL* + 16 copies of byte *BB* (16–4111) |

Copies are done byte by byte, so they may overlap their source (a run of a repeated
pattern).

The compressor (`LzssCompress`, 0x1000ecd0) is used only for FQL files. At each position it
first measures a run of equal bytes; a run of 16 or more is emitted as a run token. Otherwise
it looks up a 4096-entry table (`LzssFindMatch`, 0x1000f030) that holds, for the hash of the
next three bytes (`((b0 << 4 ^ b1) << 4 ^ b2) * 0x9E5F >> 4 & 0xFFF`), the last position
where that hash was seen; a match of 3 or more bytes within 4096 bytes is emitted, else a
literal. If the output grows larger than the input, it falls back to a stored stream.

### 4.5 Compressed WAV

`WavDecompress` (0x100097f7) decodes blocks of type 8 and up. If the file's header says the
samples are 16-bit (block align / channels = 2), the block is DPCM:

- the first sample of each channel is stored as is (2 bytes mono, 4 bytes stereo);
- every following sample is one byte: bit 7 = sign, bits 0–6 = index into a delta table; the
  delta is added to the previous sample of the same channel (16-bit wrap-around). Stereo
  bytes alternate left / right.

The block type selects one of seven 128-entry tables (`g_wavDeltas`, 0x10036d70): 0x0C → 1,
0x10 → 2, 0x14 → 3, 0x18 → 4, 0x1C → 5, 0x20 → 6, anything else → 0. The tables grow
quadratically from 0 to 8192, 12288, …, 32767 (table *t* ends at 8192 + 4096·*t*), so small
differences are coded precisely and large ones coarsely. This is lossy.

For other sample formats an LZSS stream follows the (optional) header copy instead.

### 4.6 Reading an archived file

`dtaRead` keeps, per open file, the current block, its offset, its stored size and how much
of the decoded block has been consumed. A read:

1. finds the block of the current position (`position >> 15`). ISD1 computes the block's
   offset by summing the size table. ISD0 has to walk the chain: forward through the block
   headers, backward through the "previous size" fields, or forward again from the first
   block when the target is nearer the start;
2. if that block is not in the buffer, reads it, checks its checksum (ISD1), decrypts it if
   the file's blocks are encrypted, and decodes it into the 32 KB buffer (a WAV file's first
   block has its embedded RIFF header decrypted first, unless the whole block was);
3. copies from the buffer. A read that runs past the block copies the rest of it, decodes
   the following whole blocks **straight into the caller's buffer**, and decodes the block
   with the remainder into the file's buffer.

Moving to another block (a seek, or reaching the end of one) marks the buffer invalid; it is
only filled on the next read.

### 4.7 Reading a disk file

Disk files use the same 32 KB buffer as a plain read cache aligned to 32 KB. A read that
extends past the buffer copies its rest, then refills the buffer if the remainder is
smaller than a buffer, or reads the remainder straight into the caller's buffer otherwise.

---

## 5. Function reference

Every function is `__stdcall`. "Handle" means a value returned by `dtaOpen` or
`dtaOpenWrite`.

### 5.1 Archives

#### `C_DtaArchive *dtaCreate(const char *fileName)` (0x10003269)

Mounts an archive. Opens the file (shared for reading, random access), reads the magic and
creates the archive object. On success the archive's (still empty) file table is registered,
the archive is appended to the end of the search order with one reference, and the object is
returned. The table is only read when the key is set ([`XorKey`](#xorkey-0x10003763) /
[`SetKey`](#setkey-0x10003d9f)).

Returns null if the file cannot be opened (error 1), cannot be read (6 / 2) or is not an
archive (4); the error callback is called with a null archive.

Unmount an archive with `Release()`.

#### `void *dtaGetPackDirectAccess(const char *fileName, int *offset)` (0x100049f1)

Gives direct access to an archived file's stored data, presumably for code that reads it
with its own I/O. Looks the name up in the archives only (without
recording it in an FQL file); if found, opens **a new Windows handle to the archive** (read
only, random access) and stores the offset of the file's first block in `*offset` (for ISD0
that is the first block header). If the name is not in any archive, it opens the file
itself and sets `*offset` to 0.

Returns the Windows `HANDLE`, which the caller closes with `CloseHandle`, or
`INVALID_HANDLE_VALUE` if nothing was found or an argument is null. The data at the offset is
still encrypted and compressed.

### 5.2 Opening and closing files

#### `int dtaOpen(const char *fileName, bool archivesFirst)` (0x10004b8c)

Opens a file for reading. Searches the disk first and then the archives, or the reverse when
`archivesFirst` is true or `SetPreferArchives(true)` was called. On disk the name is passed
to `CreateFileA` as is (relative to the current directory); in the archives it is looked up
as described in [4.1](#41-name-hash-and-lookup).

When a file was found, its upper-case name is passed to the file logs
([5.6](#56-file-logs)), and while FQL recording or playback is active it is marked for FQL
unless its extension is filtered ([5.7](#57-fql-recording-and-playback)).

Opening an archived file reads its header, its name, its block tables (ISD1) or the start of
its first block (ISD0: the block header and the type byte), and for WAV files the RIFF
header; the data is only read by `dtaRead`. Returns the handle, or -1.

#### `bool dtaClose(int handle)` (0x10004cc4)

Closes a handle and frees its slot. A disk file's Windows handle is closed (an archive's is
not). For a file written through a temporary file (`DTA_WRITE_TEMP_FILE`):

- if no write failed, the target is deleted (clearing its read-only attribute if needed) and
  `<name>.tmp` is renamed to it;
- if a write failed, `<name>.tmp` is deleted and the target is left unchanged.

Returns false for an invalid handle or if `CloseHandle` fails; true otherwise, including for
a slot that is already closed.

#### `bool dtaDelete(const char *fileName)` (0x10005113)

`DeleteFileA`. Works on disk files only. Returns whether it succeeded.

### 5.3 Reading and seeking

#### `int dtaRead(int handle, void *buffer, int size)` (0x1000513b)

Reads up to `size` bytes from the current position and advances it. The count is limited to
the bytes left in the file, so a read at the end returns 0. Archived files are read as
described in [4.6](#46-reading-an-archived-file), disk files as in
[4.7](#47-reading-a-disk-file).

For an ISD1 file marked for FQL, the data comes from the FQL file during playback, and is
recorded into it during recording.

Returns the number of bytes read, or -1 for a null buffer, an invalid handle, a write
handle, or an I/O error. A block that reads short is also reported to the error callback
(error 2), and for ISD1 archives so is a failed read (6) or a wrong block checksum (3, the
read still succeeds).

#### `int dtaSeek(int handle, int position, int origin)` (0x100079b0)

`origin`: 0 = from the start, 1 = from the current position, 2 = from the end. Returns the
new position, or -1.

- **Read handles** only move the logical position: from the start the target must be in
  `0 .. size`; from the current position the result must be in `0 .. size`; from the end the
  offset must be less than 2 and the result not negative, so `dtaSeek(h, 1, 2)` is accepted
  and puts the position one byte past the end. Nothing is read until the next `dtaRead`.
- **Write handles** move the Windows file pointer (`SetFilePointer`). If the seek fails, the
  next origins are tried in turn with the same offset (origin 0 retries as 1, then 2), a quirk
  of the original's `switch` without `break`s.

#### `bool dtaGetTime(int handle, FILETIME *time, bool containerTime)` (0x100088d5)

For an archived file, returns the time stored in the archive, or with `containerTime` the
last-write time of the `.dta` file. For a disk file, returns its last-write time. Returns
false for an invalid handle or if `GetFileTime` fails.

#### `int dtaBin2Text(char *buffer, int size)` (0x10007f37)

Removes the `'\r'` characters of a buffer in place, turning CR-LF text into LF text. The
last character is never removed. Returns the new size (0 for a null buffer or a size of 0).
Unrelated to handles.

### 5.4 Writing

#### `int dtaOpenWrite(const char *fileName, int flags)` (0x10008062)

Opens a disk file for writing (exclusive access) and returns a handle, or -1. Flags:

| Flag | Value | Effect |
|---|---|---|
| `DTA_WRITE_HIDDEN` | 0x1 | create the file hidden |
| `DTA_WRITE_TEMP_FILE` | 0x100 | write `<name>.tmp`; `dtaClose` replaces `<name>` with it |
| `DTA_WRITE_CREATE_ALWAYS` | 0x10000 | truncate the file; without it the file is opened as is and written over from the start |
| `DTA_WRITE_CLEAR_READONLY` | 0x100000 | if the file cannot be opened, clear its read-only attribute and try again |

With `DTA_WRITE_TEMP_FILE`, the temporary file starts as a copy of the target (or is deleted
first when the file is created anew), so the rest of the file survives a partial rewrite.
The game writes its saves and configuration with flags 0x10000.

#### `int dtaWrite(int handle, const void *buffer, int size)` (0x100085bb)

Writes `size` bytes at the current position. Returns `size`, or -1 for an invalid handle, a
read handle, a null buffer or a failed / short write. A failed write of a temporary file
marks it so that `dtaClose` discards it.

#### `bool dtaFlush(int handle)` (0x100087be)

`FlushFileBuffers` for a write handle. Returns false for other handles.

### 5.5 Error reporting and diagnostics

#### `dtaErrorCallback dtaSetCallbackERR(dtaErrorCallback callback)` (0x10009e3e)

Installs the error callback ([2.5](#25-errors)); null removes it. Returns the previous one.
Some checks only run when a callback is installed (the archive checksums and the archive
size checks), so without one they cost nothing.

#### `void dtaDumpMemoryLeaks(bool enable)` (0x100096b0)

When enabled, the DLL shows a message box when it is unloaded if archives were not released:
"Not released: N reference(s) of Dta_read." and "Not released: N Dta_read(s).". It counts
`AddRef` / `Release` calls and live archive objects.

### 5.6 File logs

A file log is a text file that receives one line for every name opened with `dtaOpen` that
matches its filters:

```
<path before log items><NAME IN UPPER CASE>\r\n
```

A name goes to **one** log: the last log that has a directory the name starts with, or, if
none, the last log that has the name's extension. Logs without filters receive nothing.

#### `int dtaOpenFileLog(const char *fileName, int flags)` (0x10008a0c)

Creates a log, writing it through `dtaOpenWrite(fileName, flags)`. Returns the log's index
(not a file handle), or -1.

Quirk: when a log is still open, the new log does not get a slot of its own: it takes over
the last open log's slot (and its filters), and the old log's file stays open. Closed slots
are not reused, so a log opened after closing the previous one gets a new index.

#### `bool dtaCloseFileLog(int log)` (0x10009096)

Closes the log's file and clears its filters and prefix. Returns false for an invalid or
closed log.

#### `bool dtaAddDir(int log, const char *dir)` (0x10008e34)

Adds a directory filter (upper-cased; a name matches when it starts with it). Directories
of the log that are a prefix of the new one, or that it is a prefix of, are replaced by it.
Returns false for an invalid or closed log or a null directory.

#### `bool dtaAddExtension(int log, const char *ext)` (0x10008c67)

Adds an extension filter of 1 to 3 characters without the dot (`"tga"`). A name's extension
is the 1 to 3 characters after a dot among its last 4 characters, otherwise its last 3
characters. Returns false for an invalid or closed log or a bad extension.

#### `bool dtaSetPathBeforeLogItems(int log, const char *path)` (0x10008b37)

Sets the prefix written before every name of the log (upper-cased); null removes it.
Returns false for an invalid log index.

### 5.7 FQL recording and playback

Loading a level opens hundreds of archived files and seeks around the archives. FQL turns
that into one sequential read: a load is **recorded**, and later loads **play back** the
recording.

While FQL is active, `dtaOpen` marks each opened file unless its extension is filtered. For
files of ISD1 archives, every read of the lookup (file header, name, block tables, WAV
header) and every `dtaRead` is copied into the FQL file in order while recording, and taken
from it instead of the archive while playing back. ISD0 archives are not recorded, except
the RIFF header of their WAV files, read by the lookup. The archives must still be mounted
during playback: the file tables come from them.

Playback must repeat the recording's sequence exactly: every read asks for the size that was
recorded (the original checks this with an assertion, `temp==buff_size`).

#### FQL file format

```
u32   total size of the file
u16   Checksum16 of that u32
then blocks:
  u32   stored size of the block (the chunks that follow)
  chunks, each:
    u32   chunk size
    bytes an LZSS stream (4.4) decoding to up to 32 KB
```

A block's chunks decode to up to 128 KB:

```
u32   bytes used in the block, including this 8-byte header
u32   Checksum16 of the used bytes, computed with this field zeroed
records, each:
  u32   size of the data
  bytes data (it may continue in the following blocks; the size field never straddles two)
```

#### `bool dtaCreateFQL(const char *fileName)` (0x10009234)

Starts recording into a new FQL file. Returns false if recording is already active or the
file cannot be created.

#### `void dtaCloseFQL()` (0x10009356)

Writes the last block, the file size and its checksum, stops recording and forgets which
files are marked.

#### `bool dtaFQLBegin(const char *fileName)` (0x10002c96)

Starts playing back an FQL file. Checks its size and checksum (reported to the error
callback, not fatal). Returns false if playback is already active or the file cannot be
opened or read. Takes no lock.

#### `void dtaFQLEnd()` (0x10003186)

Stops playback and forgets which files are marked. Takes no lock.

#### `bool dtaAddFQLExtensionFilter(const char *ext)` (0x100094c0)

Excludes an extension (1 to 3 characters, as for file logs) from FQL recording and
playback. Returns false for a bad extension.

#### `void dtaClearFQLExtensionFilter()` (0x1000960b)

Removes all FQL extension filters.

#### `void dtaSetDebugFQLExt(int)` (0x1000922d)

Does nothing in this build.

---

## 6. The archive object (`C_DtaArchive`)

`dtaCreate` returns an object with this virtual table (the original class is called
`Dta_read`; all methods are `__thiscall`):

| Offset | Method | Address |
|---:|---|---|
| 0x00 | `void *DeletingDestructor(unsigned flags)` (MSVC's scalar deleting destructor; use `Release`) | 0x1000c000 |
| 0x04 | `int AddRef()` | 0x100046a8 |
| 0x08 | `int Release()` | 0x1000470d |
| 0x0C | `bool XorKey(uint32_t low, uint32_t high)` | 0x10003763 |
| 0x10 | `uint64_t GetKey()` | 0x10003d84 |
| 0x14 | `bool SetKey(uint32_t low, uint32_t high)` | 0x10003d9f |
| 0x18 | `bool SetPreferArchives(bool prefer)` | 0x100047db |
| 0x1C | `int SetPriority(int priority)` | 0x10004840 |
| 0x20 | `int GetPriority()` | 0x10004955 |
| 0x24 | `const char *GetName()` | 0x100047c3 |

#### `AddRef` (0x100046a8), `Release` (0x1000470d)

Reference counting; both return the new count. When `Release` brings it to 0 the archive is
destroyed: its Windows handle is closed, its table and its place in the search order are
removed, and **files still open from it are closed**. An archive whose `dtaCreate` failed
never had a reference; releasing it wraps the count around and leaks it.

#### `XorKey` (0x10003763)

The two-step key of [2.3](#23-the-key). The first call (while `GetKey()` is still 0) only
stores the masked value and returns true. Every later call recovers a key from the mask and
loads the file table with it, like `SetKey`.

#### `GetKey` (0x10003d84)

Returns the masked value stored by the first `XorKey` (0 before it). Not the key.

#### `SetKey` (0x10003d9f)

Loads the file table with a plain key: reads and decrypts the archive header ([3.1](#31-archive-header)),
reads the table, checks it (ISD1, with a callback installed), decrypts it and stores the key
for the archive's files. Returns false if the header cannot be read; errors in the table are
only reported. A wrong key gives a garbage table, in which no name is found.

#### `SetPreferArchives` (0x100047db)

Sets the global "archives before disk" switch for `dtaOpen` (it is not per archive). Returns
the previous value.

#### `SetPriority` (0x10004840), `GetPriority` (0x10004955)

The archive's index in the search order (0 = searched first). `SetPriority` clamps the
index to the order's size and moves the archive there; it returns the index used.
`GetPriority` returns -1 for an archive that is not in the order.

#### `GetName` (0x100047c3)

The file name passed to `dtaCreate`.

---

## 7. Internal functions

The other functions of the original, with their port names:

| Address | Function | Purpose |
|---|---|---|
| 0x1000c110 | `OpenFromArchives` | name lookup in the search order ([4.1](#41-name-hash-and-lookup)) and opening of the archived file |
| 0x1000dea0 | `OpenFromDisk` | opening of a disk file for reading |
| 0x1000e0f0 | `ArchiveFindEntry` | binary search of a file table by hash |
| 0x1000333f / 0x1000433b | `C_DtaRead` constructor / destructor | mounting / unmounting an archive |
| 0x1000ea20 | `LzssDecompress` | LZSS decoder ([4.4](#44-lzss)) |
| 0x1000ecd0 / 0x1000f030 | `LzssCompress` / `FindMatch` | LZSS encoder and its match finder |
| 0x100097f7 | `WavDecompress` | WAV DPCM decoder ([4.5](#45-compressed-wav)) |
| 0x10009bf3 / 0x10009d24 | `DecryptBuffer` / `EncryptBuffer` | the cipher ([4.2](#42-cipher)) |
| 0x10009e97 | `Checksum16` | the checksum ([4.3](#43-checksum)) |
| 0x1000e3d0 | `FileLogRecord` | writes an opened name to the matching file log |
| 0x1000e880 | `FqlRecordOpen` | marks an opened file for FQL |
| 0x1000e920 | `FqlIsExtensionFiltered` | FQL extension filter test |
| 0x10002129 / 0x10001e7e | `FqlWrite` / `FqlFlushBlock` | appends a record to the FQL buffer / compresses and writes a full block |
| 0x10002535 / 0x100022e3 | `FqlRead` / `FqlReadBlock` | takes a record from the FQL file / reads and decompresses the next block |
| 0x100026d0, 0x10002ba9 | `LegacyFqlOpen`, `LegacyFqlClose` | unreferenced older versions of `dtaFQLBegin` / `dtaFQLEnd` |
| 0x1000964b / 0x1000967f | `C_CriticalSection` | the lock |
| 0x100096bf / 0x100096ee | `S_DtaLeakCounter` | the counters of `dtaDumpMemoryLeaks` |

The remaining 245 functions of the DLL's own code are `std::vector` code generated by the
compiler (213) and the static initialisers of the globals (32). The DLL also contains its
own copy of the C runtime (from 0x10014e80).

---

## 8. Behaviour worth knowing

- **Disk before archives** by default: a loose file overrides the archived one. Patch
  archives override earlier-mounted archives only because they are mounted first.
- **Names are case-insensitive** in the archives (they are upper-cased), but passed as is to
  Windows for disk files (also case-insensitive there). Paths use backslashes.
- **One byte past the end**: `dtaSeek(h, 1, 2)` is accepted. In the original, reading there
  copies bytes from past the DLL's buffers; the port returns 0.
- **Releasing an archive closes its open files**; their handles become invalid.
- **Handles are reused** lowest-first, so a closed handle number soon refers to another file.
- **`dtaGetPackDirectAccess` leaks handle 0**: it closes its temporary handle with a `!= 0`
  test, so when the lookup got handle 0 that file stays open.
- **Without an error callback** no archive checksum is computed and some size checks are
  skipped.
- **Each open file costs a 32 KB buffer**, and a read that crosses blocks decodes whole
  blocks directly into the caller's buffer, so large reads are cheap.
- **Write handles cannot be read, read handles cannot be written**; `dtaRead` / `dtaWrite`
  return -1.
- **`DTA_WRITE_CREATE_ALWAYS` matters**: without it an existing file is not truncated, and a
  shorter rewrite leaves the old file's tail behind.
