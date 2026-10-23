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