# RawPDB analyzer helper

This helper uses [RawPDB](https://github.com/MolecularMatters/raw_pdb) to
memory-map native Microsoft PDBs and extract only procedure and public-function
records. It writes a bounded binary protocol to stdout; the Go backend verifies
the returned PDB identity and maps every RVA back into an executable PE
section before exposing it to the frontend.

RawPDB is fetched at the pinned revision in `CMakeLists.txt` and is distributed
under the BSD 2-Clause license reproduced in `RAW_PDB_LICENSE.txt`.

## Build on Windows

Run from the repository root in a PowerShell terminal with CMake and the MSVC
toolchain installed:

```powershell
cmake -S rawpdb-helper -B rawpdb-helper/build -A x64
cmake --build rawpdb-helper/build --config Release --parallel
```

When the backend is started from either the repository root or `backend`, it
automatically discovers:

```text
rawpdb-helper/build/bin/Release/rawpdb_analyzer.exe
```

Set `RECOMPILER_RAWPDB` to use a helper at another location. If no helper is
available, the backend logs that fact and retains the built-in Go parser as a
compatibility fallback.
