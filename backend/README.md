# Go backend

The backend accepts an x86-64 Windows PE file and an optional matching native
MSF 7.0 PDB file. It validates the input, discovers functions, caches analysis
results, provides disassembly data, and coordinates optional transformations.

When a PDB is supplied, the backend verifies its RSDS GUID and age against the
PE file.

## Start the service

Run this command from the `backend` directory:

```powershell
go run .
```

The service listens on `:8080` by default. Set `ADDR` to change the address:

```powershell
$env:ADDR = '127.0.0.1:9000'
go run .
```

At startup, the backend loads the first `.env` file found in its working
directory, its parent directory, the executable directory, or the executable
directory's parent. Process environment variables have priority. Set
`RECOMPILER_ENV_FILE` to select a specific file. Relative tool paths in `.env`
are resolved from the directory that contains that file.

The backend refuses to load `DD_API_KEY` and `DD_APP_KEY` from `.env`. Keep
those server credentials in the Datadog Agent or the Terraform process
environment.

## API

### Health

`GET /api/health` reports service availability and the configured analysis
limits.

### Analyze

`POST /api/analyze` uses `multipart/form-data` with these fields:

- `binary`: an x86-64 PE `.exe`, `.dll`, or `.sys` file
- `pdb` (optional): a matching native PDB file

Without a PDB, the backend recovers AMD64 function boundaries from the PE
exception table (`.pdata`) and assigns `sub_<virtual-address>` names. It keeps
exported names, retained COFF symbols such as `main`, and the PE entry point
when they are available.

Each file is limited to 1 GiB by default. The complete request can contain two
files plus multipart overhead. Set `RECOMPILER_MAX_UPLOAD_MIB` to select a
per-file limit from 1 through 4096 MiB. Portable PDB files from managed .NET
builds are not supported.

A successful response contains a `cacheId`. Later disassembly and
transformation requests can send this value instead of uploading the files
again. Cache entries expire after two hours of inactivity. The cache removes
the least recently used entry after 16 file pairs or when it reaches its size
limit. Set `RECOMPILER_CACHE_MIB` to select a limit from 64 through 65536 MiB.

### Disassemble

`POST /api/disassemble` accepts `cacheId`, or the original `binary` and
optional `pdb`, plus one verified `address`. It returns Intel-syntax
instructions, basic blocks, direct CFG edges, and external or indirect exits.

Set `RECOMPILER_OBJDUMP` to an installed `llvm-objdump.exe`. When a
transformation executable is configured, the backend also checks its adjacent
`llvm-tools` directory. Unknown function sizes are bounded by the next
discovered function. Each request has a 64 KiB function-size safety limit.

### Transform

`POST /api/transform` accepts `cacheId`, or the original `binary` and optional
`pdb`, with these fields:

- Up to 32 repeated, verified `address` values
- One or more allowlisted `pass` values
- Optional `nopCount` and `obfReps` values

The backend runs `remill_recompiler.exe` once for each address. It supplies the
output PE from one run as the input to the next run. The final response
contains all requested patches.

The transformation executable and its runtime files are not included in this
repository. Set `RECOMPILER_PATH` to the executable or to the directory that
contains it. When an `llvm-tools` directory is present beside the executable,
the backend finds the required LLVM tools and runtime files automatically.

You can override the discovered paths with these variables:

- `RECOMPILER_OPT`
- `RECOMPILER_LLC`
- `RECOMPILER_LLVM_LINK`
- `RECOMPILER_RUNTIME`
- `RECOMPILER_SEMANTICS`
- `RECOMPILER_SEMANTICS_INSTALL`

The allowlisted pass values are `mutate`, `opaque-predicates`, `dead-code`,
`nop-sled`, and `deobfuscate`. A request cannot mix deobfuscation with an
obfuscation pass.

The backend stages available `amd64.bc`, `amd64_avx.bc`, and
`amd64_avx512.bc` files in Remill's semantics location. This operation lets the
recompiler lift AVX and AVX-512 instructions with the correct architecture
semantics.

## RawPDB acceleration

The backend uses `rawpdb_analyzer.exe` when the helper is available. RawPDB
memory-maps the PDB and sends only procedure and public-function records
through a compact binary protocol. The backend separately verifies the PDB
identity and rejects RVAs outside executable PE sections.

Build the helper from the repository root:

```powershell
cmake -S rawpdb-helper -B rawpdb-helper/build -A x64
cmake --build rawpdb-helper/build --config Release --parallel
```

Set `RECOMPILER_RAWPDB` to override automatic discovery. If the helper is not
available, the backend uses its bounds-checked Go PDB parser.

Independent PE parsing, RawPDB extraction, and uploaded-file reads overlap
when it is safe. `RECOMPILER_ANALYSIS_JOBS` selects 1 through 16 simultaneous
analysis jobs. `RECOMPILER_ANALYSIS_WORKERS` selects 1 through 64 module
workers for the Go fallback parser. Defaults are based on `GOMAXPROCS`.

## Cache, compression, and timing

JSON responses use gzip when the client supports it. Analysis responses also
contain a `Server-Timing` header for upload, PDB indexing, and cache work.

The server permits up to one hour for large request bodies and responses. The
transformation endpoint has a 20-minute operation timeout. The Vite
development proxy does not set an analysis timeout.

## Logs

Backend logs go to the console and, on Windows, to this file by default:

```text
C:\ProgramData\recompiler\logs\backend.log
```

Set `RECOMPILER_LOG_FILE` to change the file. If the backend cannot open the
file, it reports the problem and continues with console logging.

See [`../datadog/README.md`](../datadog/README.md) for Datadog log, trace,
profile, RUM, dashboard, monitor, SLO, and Synthetic Monitoring setup.
