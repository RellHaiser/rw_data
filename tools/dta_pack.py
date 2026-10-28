#!/usr/bin/env python3
"""DTA Packer: packs a folder into a Hidden & Dangerous 2 .dta archive.

Run without arguments for the window; with arguments it packs from the command line:

    python dta_pack.py                                   (window)
    python dta_pack.py MyMod PatchX02.dta --key PatchX02.dta
    python dta_pack.py MyMod Test.dta --key 0x12345678:0x9ABCDEF0 --store
    python dta_pack.py MyMod Plain.dta --key blank

Every file under the folder is stored under its path relative to the folder, with
backslashes ("Tables\\items.sav"), which is the name the game asks rw_data.dll for.

The archives are written in the ISD1 format, as read by rw_data.dll (see the rw_data
port, docs/rw_data_functions.md, section 3). All integers are little endian; "encrypted"
means XORed with the 64-bit key, byte i of each piece with key byte i % 8, each piece from
its own start.

    archive  "ISD1", then 20 encrypted bytes: file count, table offset, table size,
             Checksum16 of the table as stored, Checksum16 of these 24 bytes (decrypted,
             this field zeroed). The files follow back to back, the table ends the archive.
    file     0x20-byte header (encrypted): u32 stored size of the whole entry, u32 Windows
             attributes, FILETIME, u32 size, u32 block count, u32 Checksum16 of the header
             (decrypted, this field zeroed), u16 name length | 0x8000 (whole blocks are
             encrypted), u16 Checksum16 chained over the decrypted name, the size table and
             the stored type table. Then the name (encrypted, original case), u32 per block
             (stored size | Checksum16 of the stored block << 16, not encrypted), u8 per
             block its type (encrypted), and the blocks (encrypted).
    blocks   each decodes to 32 KB (the last one to the rest). Type 1 is an LZSS stream
             whose first byte is the type, type 0 stores the bytes as they are. An empty
             file has one empty stored block.
    table    0x1C bytes per file, sorted by hash, encrypted as one piece: hash (name length
             << 16 | 16-bit sum of the upper-case name), header offset, offset of the first
             block, the last 16 characters of the upper-case name (zero padded).

The fields the reader ignores are filled like in the game's own archives: in all 68,968
files of the retail archives the first header field is the entry's stored size, the second
holds Windows file attributes (0x20, 0x21 or 0x80), and every file has the 0x8000 flag.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import multiprocessing
import os
import queue
import struct
import sys
import threading
import time
import zlib

BLOCK_SIZE = 0x8000            # decoded size of a block
CHUNK_BLOCKS = 32              # blocks per compression job (1 MB)
MAX_NAME_LENGTH = 259          # the original rw_data.dll reads names into 264-byte buffers
MAX_ARCHIVE_SIZE = 0x7FFFFFFF  # offsets go through SetFilePointer as signed 32-bit values
CHECKSUM_SEED = 0xFF
NAME_ENCRYPTED_BLOCKS = 0x8000
FILETIME_UNIX_EPOCH = 116444736000000000   # 1970-01-01 in 100 ns units since 1601
ATTRIBUTE_MASK = 0x27          # read-only, hidden, system, archive
ATTRIBUTE_NORMAL = 0x80

# The keys of MountDataArchives (game 0x006dba30), in the order the game searches the
# archives. PatchX02, PatchX03 and Maps_C are mounted when present but are not part of the
# retail game. Every Lang<language>.dta uses the LangEnglish key.
GAME_KEYS = [
    ("PatchX03.dta", 0xA0A0A0A4, 0xA0A0A0A0, "Searched first. Not part of the retail game: free for mods."),
    ("PatchX02.dta", 0xA0A0A0A3, 0xA0A0A0A0, "Searched second. Not part of the retail game: free for mods."),
    ("PatchX01.dta", 0xA0A0A0A2, 0xA0A0A0A0, "Official patch archive (holds Tables\\items.sav)."),
    ("SabreSquadron.dta", 0xA0A0A0A1, 0xA0A0A0A0, "Sabre Squadron expansion archive."),
    ("LangEnglish.dta", 0xA0A0A0A0, 0xA0A0A0A0, "Language archive. Every Lang<language>.dta uses this key."),
    ("Patch.dta", 0x5D805270, 0x10ACB252, "Patch archive of the base game."),
    ("Models.dta", 0x5D805259, 0x10ACB252, "Base game archive."),
    ("Missions.dta", 0x7654A3F0, 0x22BCDA98, "Base game archive."),
    ("Maps.dta", 0xB438D0A5, 0xF26527FA, "Base game archive."),
    ("Sounds.dta", 0x4FE85106, 0x8D2965CA, "Base game archive."),
    ("Scripts.dta", 0x0AB4E72D, 0xCF761298, "Base game archive."),
    ("Others.dta", 0xEA85902A, 0x65F7AB23, "Base game archive."),
    ("Maps_C.dta", 0xB038D0A0, 0xE26520FA, "Searched after the base archives. Not part of the retail game."),
    ("Maps_U.dta", 0xB038D1A1, 0xF26520FA, "Base game archive, searched last."),
]


class PackError(Exception):
    """A problem with the input or the output that stops packing."""


class PackCancelled(Exception):
    pass


# Cipher and checksum -------------------------------------------------------------------

def make_key(low: int, high: int) -> int:
    return (high & 0xFFFFFFFF) << 32 | (low & 0xFFFFFFFF)


_keystreams: dict = {}


def xor_key(data: bytes, key: int) -> bytes:
    """Encrypts (or decrypts) one piece: byte i ^= key byte i % 8."""
    size = len(data)
    if size == 0 or key == 0:
        return bytes(data)
    stream = _keystreams.get(key)
    if stream is None or len(stream) < size:
        stream = key.to_bytes(8, "little") * ((max(size, BLOCK_SIZE) + 7) // 8)
        _keystreams[key] = stream
    mixed = int.from_bytes(data, "little") ^ int.from_bytes(stream[:size], "little")
    return mixed.to_bytes(size, "little")


def checksum16(data: bytes, seed: int = CHECKSUM_SEED) -> int:
    """rw_data's Checksum16."""
    s = seed
    for b in data:
        s = ((s + b) & 0xFFFF) ^ (b ^ 0xFF)
    return s


# LZSS ----------------------------------------------------------------------------------
#
# Stream: byte 0 = 1, then groups of 16 items, each group preceded by a big-endian flag
# word read from its top bit. Flag 0: a literal byte. Flag 1: DDDDDDDD DDDDLLLL copies
# L + 3 bytes from D bytes back (D = 1..4095), or with D = 0 the four bytes 00 0H LL BB
# repeat byte BB HLL + 16 times. Copies run byte by byte, so they may overlap.

WINDOW = 4095
MIN_MATCH = 3
MAX_MATCH = 18
MIN_RUN = 16
MAX_RUN = 0xFFF + MIN_RUN
CHAIN_DEPTH = 16
_RUN_PREFIX = [bytes((b,)) * MIN_RUN for b in range(256)]


def lzss_compress(data: bytes) -> bytes | None:
    """Compresses one block. Returns the stream (starting with the type byte 1), or None
    when it would not be smaller than the data stored as it is."""
    size = len(data)
    if size < 8 or len(zlib.compress(data, 1)) > size - size // 32:
        return None   # (almost) incompressible: not worth the slow search
    out = bytearray(b"\x01\x00\x00")
    flags_at = 1
    flags = 0
    items = 0
    chains: dict = {}
    pos = 0
    last_key = size - MIN_MATCH   # last position with a whole 3-byte key
    while pos < size:
        if items == 16:
            out[flags_at] = flags >> 8
            out[flags_at + 1] = flags & 0xFF
            flags_at = len(out)
            out += b"\x00\x00"
            flags = 0
            items = 0
            if len(out) > size:
                return None
        items += 1

        byte = data[pos]
        if data[pos:pos + MIN_RUN] == _RUN_PREFIX[byte]:
            end = min(size, pos + MAX_RUN)
            run = end - pos - len(data[pos:end].lstrip(_RUN_PREFIX[byte][:1]))
            count = run - MIN_RUN
            out += bytes((0, count >> 8, count & 0xFF, byte))
            flags = flags << 1 | 1
            stop = pos + run
        else:
            length = 0
            distance = 0
            if pos <= last_key:
                key = data[pos:pos + 3]
                candidates = chains.get(key)
                if candidates is not None:
                    longest = min(MAX_MATCH, size - pos)
                    target = data[pos:pos + longest]
                    oldest = pos - WINDOW
                    for at in reversed(candidates[-CHAIN_DEPTH:]):
                        if at < oldest:
                            break
                        if length and data[at + length] != target[length]:
                            continue   # cannot be longer than the best so far
                        source = data[at:at + longest]
                        if source == target:
                            length = longest
                            distance = pos - at
                            break
                        diff = int.from_bytes(source, "big") ^ int.from_bytes(target, "big")
                        common = longest - (diff.bit_length() + 7) // 8
                        if common > length:
                            length = common
                            distance = pos - at
                    candidates.append(pos)
                else:
                    chains[key] = [pos]
            if length >= MIN_MATCH:
                code = distance << 4 | (length - MIN_MATCH)
                out += bytes((code >> 8, code & 0xFF))
                flags = flags << 1 | 1
                stop = pos + length
                pos += 1   # this position is already in the chains
            else:
                out.append(byte)
                flags <<= 1
                pos += 1
                continue
        # Record the positions the item covered, so later matches can start there (of a
        # long run only its end: the other positions all have the same key).
        for at in range(max(pos, stop - MAX_MATCH), min(stop, last_key + 1)):
            key = data[at:at + 3]
            candidates = chains.get(key)
            if candidates is None:
                chains[key] = [at]
            else:
                candidates.append(at)
        pos = stop

    flags <<= 16 - items
    out[flags_at] = flags >> 8
    out[flags_at + 1] = flags & 0xFF
    if len(out) - 1 >= size:
        return None
    return bytes(out)


# Blocks (run in the worker processes) --------------------------------------------------

def encode_chunk(path: str, offset: int, length: int, key: int, compress: bool) -> list:
    """Reads `length` bytes of a file and turns them into stored blocks.
    Returns [(type, encrypted data, checksum of the encrypted data), ...].
    Raises OSError only: the worker processes send their errors back by pickling them."""
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(length)
    if len(data) != length:
        raise OSError(f"{path} changed while it was being packed")
    blocks = []
    for start in range(0, length, BLOCK_SIZE) or [0]:
        raw = data[start:start + BLOCK_SIZE]
        stream = lzss_compress(raw) if compress else None
        if stream is None:
            kind, stored = 0, raw
        else:
            kind, stored = stream[0], stream[1:]
        stored = xor_key(stored, key)
        blocks.append((kind, stored, checksum16(stored)))
    return blocks


def _encode_job(job: tuple) -> list:
    return encode_chunk(*job)


# Packing -------------------------------------------------------------------------------

def _ansi_codec() -> str:
    try:
        "".encode("mbcs")
        return "mbcs"   # the Windows ANSI code page, which the game's names use
    except LookupError:
        return "cp1252"


NAME_CODEC = _ansi_codec()


class SourceFile:
    __slots__ = ("path", "name", "upper", "size", "filetime", "attributes")

    def __init__(self, path: str, name: bytes, size: int, filetime: int, attributes: int):
        self.path = path
        self.name = name
        self.upper = name.upper()   # ASCII only, like the DLL's _strupr
        self.size = size
        self.filetime = filetime
        self.attributes = attributes

    @property
    def display_name(self) -> str:
        return self.name.decode(NAME_CODEC, "replace")

    @property
    def block_count(self) -> int:
        return max(1, (self.size + BLOCK_SIZE - 1) // BLOCK_SIZE)

    @property
    def hash(self) -> int:
        return len(self.upper) << 16 | (sum(self.upper) & 0xFFFF)


def collect_files(folder: str, exclude=()) -> list:
    """Lists the files under `folder` with their archive names; raises PackError for names
    the archive cannot hold."""
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        raise PackError(f"{folder} is not a folder")
    excluded = {os.path.normcase(os.path.abspath(p)) for p in exclude}
    files = []
    problems = []
    seen = {}

    def unreadable(error: OSError):
        problems.append(f"{os.path.relpath(error.filename, folder)}: {error.strerror}")

    for root, dirs, names in os.walk(folder, onerror=unreadable):
        dirs.sort(key=str.lower)
        for name in sorted(names, key=str.lower):
            path = os.path.join(root, name)
            if os.path.normcase(path) in excluded:
                continue
            relative = os.path.relpath(path, folder).replace("/", "\\")
            try:
                encoded = relative.encode(NAME_CODEC, "strict")
            except UnicodeEncodeError:
                problems.append(f"{relative}: the name has characters the game cannot use")
                continue
            if len(encoded) > MAX_NAME_LENGTH:
                problems.append(f"{relative}: the name is longer than {MAX_NAME_LENGTH} characters")
                continue
            try:
                info = os.stat(path)
            except OSError as error:
                problems.append(f"{relative}: {error.strerror}")
                continue
            if info.st_size > 0xFFFFFFFF:
                problems.append(f"{relative}: larger than 4 GB")
                continue
            attributes = getattr(info, "st_file_attributes", 0x20) & ATTRIBUTE_MASK or ATTRIBUTE_NORMAL
            filetime = info.st_mtime_ns // 100 + FILETIME_UNIX_EPOCH
            entry = SourceFile(path, encoded, info.st_size, filetime, attributes)
            if entry.upper in seen:
                problems.append(f"{relative}: same name as {seen[entry.upper]} (names are not case-sensitive)")
                continue
            seen[entry.upper] = relative
            files.append(entry)
    if problems:
        shown = "\n".join(problems[:15])
        more = f"\n... and {len(problems) - 15} more" if len(problems) > 15 else ""
        raise PackError(f"These files cannot be packed:\n{shown}{more}")
    return files


class _ArchiveWriter:
    """Writes the files of an ISD1 archive one after another, then the table and header."""

    def __init__(self, f, key: int):
        self.f = f
        self.key = key
        self.entries = []
        self.current = None
        f.write(b"ISD1" + bytes(20))

    def begin(self, source: SourceFile):
        self.current = source
        self.header_offset = self.f.tell()
        self.types = bytearray()
        self.sizes = []
        # Header, name and block tables are written once the blocks are known.
        self.f.write(bytes(0x20 + len(source.name) + 5 * source.block_count))

    def add_blocks(self, blocks: list):
        for kind, stored, checksum in blocks:
            self.f.write(stored)
            self.types.append(kind)
            self.sizes.append(len(stored) | checksum << 16)
        if self.f.tell() > MAX_ARCHIVE_SIZE:
            raise PackError("The archive would be larger than 2 GB, which the game cannot read. "
                            "Split the files into several archives.")

    def end(self):
        source = self.current
        count = source.block_count
        if len(self.types) != count:
            raise PackError(f"{source.path} changed while it was being packed")
        end = self.f.tell()
        name = source.name
        sizes = struct.pack(f"<{count}I", *self.sizes)
        types = xor_key(bytes(self.types), self.key)
        tables_checksum = checksum16(types, checksum16(sizes, checksum16(name)))
        header = struct.pack("<IIQIIIHH", end - self.header_offset, source.attributes,
                             source.filetime, source.size, count, 0,
                             len(name) | NAME_ENCRYPTED_BLOCKS, tables_checksum)
        header = header[:0x18] + struct.pack("<I", checksum16(header)) + header[0x1C:]
        self.f.seek(self.header_offset)
        self.f.write(xor_key(header, self.key) + xor_key(name, self.key) + sizes + types)
        self.f.seek(end)
        data_offset = self.header_offset + 0x20 + len(name) + 5 * count
        self.entries.append((source.hash, source.upper, self.header_offset, data_offset))
        self.current = None

    def finish(self):
        self.entries.sort(key=lambda e: (e[0], e[1]))
        table = b"".join(struct.pack("<III16s", h, header, data, upper[-16:])
                         for h, upper, header, data in self.entries)
        table = xor_key(table, self.key)
        table_offset = self.f.tell()
        if table_offset + len(table) > MAX_ARCHIVE_SIZE:
            raise PackError("The archive would be larger than 2 GB, which the game cannot read.")
        self.f.write(table)
        fields = [len(self.entries), table_offset, len(table), checksum16(table), 0]
        fields[4] = checksum16(b"ISD1" + struct.pack("<5I", *fields))
        self.f.seek(4)
        self.f.write(xor_key(struct.pack("<5I", *fields), self.key))
        self.f.seek(0, os.SEEK_END)


def pack_files(files: list, output: str, key: int, compress: bool = True, workers: int = 0,
               progress=None, cancel: threading.Event | None = None) -> dict:
    """Packs `files` (from collect_files) into the archive `output`.

    progress(done_bytes, total_bytes, name) is called as files are packed (from this
    thread). Setting `cancel` stops packing (PackCancelled). The archive is written to
    "<output>.part" and only replaces `output` when complete.
    """
    if not files:
        raise PackError("There are no files to pack.")
    total = sum(f.size for f in files)
    workers = workers or os.cpu_count() or 1
    if total < 2 * 1024 * 1024:
        workers = 1   # starting the processes would take longer than the work

    jobs = []   # (file index, (path, offset, length, key, compress))
    for index, source in enumerate(files):
        for offset in range(0, source.size, CHUNK_BLOCKS * BLOCK_SIZE) or [0]:
            length = min(CHUNK_BLOCKS * BLOCK_SIZE, source.size - offset)
            jobs.append((index, (source.path, offset, length, key, compress)))

    started = time.monotonic()
    temp = output + ".part"
    executor = None
    try:
        if workers > 1:
            executor = concurrent.futures.ProcessPoolExecutor(max_workers=workers)

            def results():
                # In order, with a few jobs per process queued ahead.
                pending = collections.deque()
                for index, job in jobs:
                    if len(pending) >= workers * 4:
                        done_index, length, future = pending.popleft()
                        yield done_index, length, future.result()
                    pending.append((index, job[2], executor.submit(_encode_job, job)))
                while pending:
                    done_index, length, future = pending.popleft()
                    yield done_index, length, future.result()
        else:
            def results():
                for index, job in jobs:
                    yield index, job[2], _encode_job(job)

        done = 0
        with open(temp, "wb") as f:
            writer = _ArchiveWriter(f, key)
            current = -1
            if progress:
                progress(0, total, files[0].display_name)
            for index, length, blocks in results():
                if cancel is not None and cancel.is_set():
                    raise PackCancelled()
                if index != current:
                    if current >= 0:
                        writer.end()
                    current = index
                    writer.begin(files[index])
                writer.add_blocks(blocks)
                done += length
                if progress:
                    progress(done, total, files[index].display_name)
            writer.end()
            writer.finish()
            archive_size = f.tell()
        os.replace(temp, output)
    except BaseException as error:
        if executor is not None:
            executor.shutdown(wait=True, cancel_futures=True)
            executor = None
        try:
            os.remove(temp)
        except OSError:
            pass
        if isinstance(error, concurrent.futures.process.BrokenProcessPool):
            raise PackError("The compression processes stopped. Try again with 1 process.") from error
        if isinstance(error, OSError):
            raise PackError(str(error)) from error
        raise
    finally:
        if executor is not None:
            executor.shutdown(wait=True)
    return {"files": len(files), "input_size": total, "archive_size": archive_size,
            "seconds": time.monotonic() - started}


def parse_key(text: str) -> int:
    """A game archive's name, "blank", or "LOW:HIGH" (two 32-bit hex values)."""
    text = text.strip()
    for name, low, high, _ in GAME_KEYS:
        if text.lower() in (name.lower(), name.lower()[:-4]):
            return make_key(low, high)
    if text.lower() in ("blank", "none", "0"):
        return 0
    parts = text.replace(",", ":").split(":")
    if len(parts) == 2:
        return make_key(_parse_hex32(parts[0]), _parse_hex32(parts[1]))
    raise ValueError(f"unknown key {text!r}: use an archive name, 'blank' or LOW:HIGH in hex")


def _parse_hex32(text: str) -> int:
    text = text.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text or len(text) > 8 or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise ValueError(f"{text!r} is not a 32-bit hex value")
    return int(text, 16)


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size:,} bytes"
    for unit in ("KB", "MB", "GB"):
        size /= 1024
        if size < 1024 or unit == "GB":
            return f"{size:,.1f} {unit}"


# Window --------------------------------------------------------------------------------

CUSTOM_KEY = "Custom key"
BLANK_KEY = "Blank key (no encryption)"


def _game_key(name: str):
    for entry in GAME_KEYS:
        if entry[0] == name:
            return entry
    return None


class PackerWindow:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.root = root
        root.title("DTA Packer")
        root.minsize(640, 520)

        self.source_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.key_choice = tk.StringVar(value="PatchX02.dta")
        self.low_var = tk.StringVar()
        self.high_var = tk.StringVar()
        self.key_info = tk.StringVar()
        self.compress_var = tk.BooleanVar(value=True)
        self.workers_var = tk.IntVar(value=os.cpu_count() or 1)
        self.summary_var = tk.StringVar()
        self.status_var = tk.StringVar()

        self.files = []
        self.loaded = None        # the folder whose files are listed
        self.suggested = ""       # the output name chosen by the window, not the user
        self.confirmed = ""       # an output the save dialog already asked to overwrite
        self.thread = None
        self.cancel = None
        self.messages = queue.Queue()

        frame = ttk.Frame(root, padding=12)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(7, weight=1)

        ttk.Label(frame, text="Source folder").grid(row=0, column=0, sticky="w", pady=3)
        self.source_entry = ttk.Entry(frame, textvariable=self.source_var)
        self.source_entry.grid(row=0, column=1, sticky="ew", padx=6)
        self.browse_source = ttk.Button(frame, text="Browse...", command=self.choose_source)
        self.browse_source.grid(row=0, column=2)

        ttk.Label(frame, text="Encryption key").grid(row=1, column=0, sticky="w", pady=3)
        choices = [entry[0] for entry in GAME_KEYS] + [CUSTOM_KEY, BLANK_KEY]
        self.key_box = ttk.Combobox(frame, textvariable=self.key_choice, values=choices,
                                    state="readonly", height=len(choices))
        self.key_box.grid(row=1, column=1, sticky="w", padx=6)
        key_frame = ttk.Frame(frame)
        key_frame.grid(row=2, column=1, columnspan=2, sticky="w", padx=6)
        ttk.Label(key_frame, text="Low 0x").pack(side="left")
        self.low_entry = ttk.Entry(key_frame, textvariable=self.low_var, width=10, font="TkFixedFont")
        self.low_entry.pack(side="left")
        ttk.Label(key_frame, text="   High 0x").pack(side="left")
        self.high_entry = ttk.Entry(key_frame, textvariable=self.high_var, width=10, font="TkFixedFont")
        self.high_entry.pack(side="left")
        ttk.Label(frame, textvariable=self.key_info, foreground="gray40", wraplength=480).grid(
            row=3, column=1, columnspan=2, sticky="w", padx=6, pady=(0, 6))

        ttk.Label(frame, text="Output archive").grid(row=4, column=0, sticky="w", pady=3)
        self.output_entry = ttk.Entry(frame, textvariable=self.output_var)
        self.output_entry.grid(row=4, column=1, sticky="ew", padx=6)
        self.browse_output = ttk.Button(frame, text="Browse...", command=self.choose_output)
        self.browse_output.grid(row=4, column=2)

        options = ttk.Frame(frame)
        options.grid(row=5, column=1, columnspan=2, sticky="w", padx=6, pady=6)
        self.compress_check = ttk.Checkbutton(options, text="Compress (LZSS, like the game's archives)",
                                              variable=self.compress_var)
        self.compress_check.pack(side="left")
        ttk.Label(options, text="     Processes").pack(side="left")
        self.workers_spin = ttk.Spinbox(options, from_=1, to=max(1, os.cpu_count() or 1),
                                        textvariable=self.workers_var, width=4)
        self.workers_spin.pack(side="left", padx=4)

        ttk.Label(frame, textvariable=self.summary_var).grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 2))
        list_frame = ttk.Frame(frame)
        list_frame.grid(row=7, column=0, columnspan=3, sticky="nsew")
        self.file_list = tk.Listbox(list_frame, activestyle="none", font="TkFixedFont")
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_list.yview)
        self.file_list.configure(yscrollcommand=scroll.set)
        self.file_list.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.progress = ttk.Progressbar(frame, maximum=1000)
        self.progress.grid(row=8, column=0, columnspan=3, sticky="ew", pady=(10, 2))
        ttk.Label(frame, textvariable=self.status_var).grid(row=9, column=0, columnspan=3, sticky="w")
        buttons = ttk.Frame(frame)
        buttons.grid(row=10, column=0, columnspan=3, sticky="e", pady=(8, 0))
        self.pack_button = ttk.Button(buttons, text="Pack", command=self.start_pack)
        self.pack_button.pack(side="left", padx=4)
        self.cancel_button = ttk.Button(buttons, text="Cancel", state="disabled", command=self.cancel_pack)
        self.cancel_button.pack(side="left")

        self.key_box.bind("<<ComboboxSelected>>", self.on_key_choice)
        self.source_entry.bind("<Return>", self.load_folder)
        self.source_entry.bind("<FocusOut>", self.load_folder)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.on_key_choice()
        self.load_folder()

    # Settings

    def on_key_choice(self, _=None):
        choice = self.key_choice.get()
        entry = _game_key(choice)
        if entry:
            self.low_var.set(f"{entry[1]:08X}")
            self.high_var.set(f"{entry[2]:08X}")
            self.key_info.set(entry[3])
            state = "readonly"
        elif choice == BLANK_KEY:
            self.low_var.set("00000000")
            self.high_var.set("00000000")
            self.key_info.set("The archive is not encrypted. The game only mounts the archives "
                              "listed above, each with its own key, so this needs a modified game.")
            state = "readonly"
        else:
            self.key_info.set("Two 32-bit hex values, as in the game's key table "
                              "(PatchX02.dta is Low A0A0A0A3, High A0A0A0A0).")
            state = "normal"
        self.low_entry.configure(state=state)
        self.high_entry.configure(state=state)
        self.suggest_output()

    def suggest_output(self):
        """Names the output after the chosen archive, next to the source folder, until the
        user picks a name."""
        current = self.output_var.get().strip()
        if current and current != self.suggested:
            return
        entry = _game_key(self.key_choice.get())
        if entry is None and current:
            return
        if current:
            directory = os.path.dirname(current)
        else:
            folder = self.source_var.get().strip()
            if not folder:
                return
            directory = os.path.dirname(os.path.abspath(folder))
        self.suggested = os.path.join(directory, entry[0] if entry else "Custom.dta")
        self.output_var.set(self.suggested)

    def output_path(self) -> str:
        output = self.output_var.get().strip()
        return os.path.abspath(output) if output else ""

    def current_key(self) -> int:
        try:
            return make_key(_parse_hex32(self.low_var.get()), _parse_hex32(self.high_var.get()))
        except ValueError:
            raise PackError("The key must be two 32-bit hex values (up to 8 digits each).")

    # Files

    def show_files(self, files):
        self.files = files
        self.file_list.delete(0, "end")
        total = sum(f.size for f in files)
        self.summary_var.set(f"{len(files):,} files, {_format_size(total)}, stored as:")
        for f in files:
            self.file_list.insert("end", f.display_name)

    def load_folder(self, _=None):
        """Lists the files of the source folder (again when it changed)."""
        folder = self.source_var.get().strip()
        if folder == self.loaded:
            return
        self.loaded = folder
        self.files = []
        self.file_list.delete(0, "end")
        if not folder:
            self.summary_var.set("Choose the folder whose contents go into the archive.")
            return
        self.suggest_output()
        output = self.output_path()
        try:
            self.show_files(collect_files(folder, exclude=[output, output + ".part"] if output else []))
        except PackError as error:
            self.summary_var.set("The folder cannot be packed as it is:")
            for line in str(error).splitlines()[1:] or [str(error)]:
                self.file_list.insert("end", line)

    def choose_source(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory(parent=self.root, title="Folder to pack", mustexist=True,
                                         initialdir=self.source_var.get() or None)
        if folder:
            self.source_var.set(os.path.normpath(folder))
            self.load_folder()

    def choose_output(self):
        from tkinter import filedialog
        current = self.output_var.get().strip()
        path = filedialog.asksaveasfilename(
            parent=self.root, title="Save archive as", defaultextension=".dta",
            filetypes=[("HD2 archives", "*.dta"), ("All files", "*.*")],
            initialdir=os.path.dirname(current) if current else None,
            initialfile=os.path.basename(current) if current else "")
        if path:
            self.output_var.set(os.path.normpath(path))
            self.suggested = ""
            self.confirmed = self.output_path()   # the dialog asked about replacing it

    # Packing

    def set_busy(self, busy: bool):
        for widget in (self.source_entry, self.browse_source, self.output_entry, self.browse_output,
                       self.compress_check, self.workers_spin, self.pack_button):
            widget.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if busy else "disabled")
        if busy:
            for widget in (self.key_box, self.low_entry, self.high_entry):
                widget.configure(state="disabled")
        else:
            self.key_box.configure(state="readonly")
            self.on_key_choice()

    def start_pack(self):
        from tkinter import messagebox
        try:
            folder = self.source_var.get().strip()
            output = self.output_path()
            if not folder:
                raise PackError("Choose the folder to pack.")
            if not output:
                raise PackError("Choose where to save the archive.")
            key = self.current_key()
            self.loaded = folder
            files = collect_files(folder, exclude=[output, output + ".part"])
            self.show_files(files)
            workers = int(self.workers_var.get())
        except PackError as error:
            messagebox.showerror("DTA Packer", str(error), parent=self.root)
            return
        except (ValueError, self.tk.TclError):
            messagebox.showerror("DTA Packer", "The number of processes must be a whole number.",
                                 parent=self.root)
            return
        if os.path.exists(output) and os.path.normcase(output) != os.path.normcase(self.confirmed):
            if not messagebox.askyesno("DTA Packer", f"{output} exists. Replace it?", parent=self.root):
                return

        self.cancel = threading.Event()
        self.set_busy(True)
        self.progress["value"] = 0
        self.status_var.set("Starting...")
        compress = self.compress_var.get()

        def report(done, total, name):
            self.messages.put(("progress", done, total, name))

        def work():
            try:
                result = pack_files(files, output, key, compress, workers, report, self.cancel)
                self.messages.put(("done", result, output))
            except PackCancelled:
                self.messages.put(("cancelled",))
            except PackError as error:
                self.messages.put(("error", str(error)))
            except Exception as error:
                self.messages.put(("error", f"{type(error).__name__}: {error}"))

        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()
        self.root.after(100, self.poll)

    def poll(self):
        """Shows the packing thread's progress; it cannot touch the widgets itself."""
        from tkinter import messagebox
        progress = None
        finished = None
        while True:
            try:
                message = self.messages.get_nowait()
            except queue.Empty:
                break
            if message[0] == "progress":
                progress = message
            else:
                finished = message
        if progress:
            _, done, total, name = progress
            self.progress["value"] = 1000 * done / total if total else 1000
            self.status_var.set(f"{_format_size(done)} of {_format_size(total)}   {name}")
        if finished is None:
            self.root.after(100, self.poll)
            return

        self.thread = None
        self.set_busy(False)
        if finished[0] == "done":
            result, output = finished[1], finished[2]
            self.progress["value"] = 1000
            ratio = 100 * result["archive_size"] / result["input_size"] if result["input_size"] else 100
            self.status_var.set(f"Packed {result['files']:,} files into {_format_size(result['archive_size'])} "
                                f"({ratio:.0f}%) in {result['seconds']:.1f} s.")
            messagebox.showinfo("DTA Packer", f"Created {output}\n\n{self.status_var.get()}", parent=self.root)
        elif finished[0] == "cancelled":
            self.progress["value"] = 0
            self.status_var.set("Cancelled; no archive was written.")
        else:
            self.progress["value"] = 0
            self.status_var.set("Failed; no archive was written.")
            messagebox.showerror("DTA Packer", finished[1], parent=self.root)

    def cancel_pack(self):
        if self.cancel is not None:
            self.cancel.set()
            self.status_var.set("Cancelling...")

    def on_close(self):
        from tkinter import messagebox
        if self.thread is not None and self.thread.is_alive():
            if not messagebox.askyesno("DTA Packer", "Packing is still running. Stop it and quit?",
                                       parent=self.root):
                return
            self.cancel.set()
            self.thread.join()
        self.root.destroy()


def run_gui():
    import tkinter as tk
    root = tk.Tk()
    PackerWindow(root)
    root.mainloop()


# Command line --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Packs a folder into a Hidden & Dangerous 2 .dta archive. "
                    "Without arguments, opens the window.")
    parser.add_argument("folder", help="the folder to pack; names are relative to it")
    parser.add_argument("output", help="the archive to write")
    parser.add_argument("--key", default="PatchX02.dta",
                        help="a game archive's name (PatchX02.dta, Patch.dta, ...), 'blank', "
                             "or LOW:HIGH as two 32-bit hex values (default: PatchX02.dta)")
    parser.add_argument("--store", action="store_true", help="do not compress")
    parser.add_argument("--workers", type=int, default=0, help="compression processes (default: all CPUs)")
    args = parser.parse_args(argv)
    try:
        key = parse_key(args.key)
    except ValueError as error:
        parser.error(str(error))
    output = os.path.abspath(args.output)
    try:
        files = collect_files(args.folder, exclude=[output, output + ".part"])
        last = [0.0]

        def report(done, total, name):
            now = time.monotonic()
            if now - last[0] >= 0.5 or done == total:
                last[0] = now
                print(f"\r{100 * done / total if total else 100:5.1f}%  {name[:60]:<60}", end="", flush=True)

        result = pack_files(files, output, key, not args.store, args.workers, report)
    except PackError as error:
        print(f"\nerror: {error}", file=sys.stderr)
        return 1
    print(f"\nPacked {result['files']:,} files ({_format_size(result['input_size'])}) into {output} "
          f"({_format_size(result['archive_size'])}) in {result['seconds']:.1f} s")
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1:
        sys.exit(main())
    run_gui()
