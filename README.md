# rw_data.dll — source port

Clean C++17 rewrite of `rw_data.dll`, the data-file layer of Hidden & Dangerous 2: the
virtual file system over the `.dta` archives (lookup, decryption, LZSS / WAV block
decompression), plain file writing, file logs and FQL load recordings. It builds into a
drop-in replacement DLL: same 26 exports (`_dtaOpen@8`, … decorated `__stdcall` names,
same ordinals), and the archive object keeps the MSVC 6 virtual-table layout, so the game,
`LS3DF.dll`, `LS3DRF.dll` and the dedicated server can use it unchanged.

The original is an MSVC 6 **debug** build of one source file
(`D:\hd2project\_src\rw_data\rw_data.cpp`); about 2/3 of its 317 functions are `std::vector`
instantiations, replaced here by the standard library. The statically linked debug C runtime
(0x10014e80 onwards) is not ported.

How every function works, the archive and FQL file formats and the algorithms are described
in [docs/rw_data_functions.md](docs/rw_data_functions.md).

## Packing archives

`tools/dta_pack.py` (Python 3.9+, standard library only) packs a folder into an ISD1
archive that the original DLL and the port read: every file is stored under its path
relative to the folder (`Tables\items.sav`), LZSS-compressed in 32 KB blocks on all CPU
cores, and encrypted with the key of one of the game's archives, a custom key or none.
`PatchX02.dta` and `PatchX03.dta` are mounted by the game before all its own archives but
are not part of the retail game, so they hold mods without replacing anything.

```bash
python tools/dta_pack.py
python tools/dta_pack.py MyMod PatchX02.dta --key PatchX02.dta
```

The first opens the window; the second packs from the command line (`--key` also takes
`blank` or `LOW:HIGH` in hex, `--store` turns compression off).
