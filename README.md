# x86-64 PE Analysis Web Interface

This project provides a web frontend and backend for x86-64 Windows binary
analysis and transformation. It combines function discovery, symbol analysis,
disassembly, control-flow analysis, and per-function transformation controls in
one interface.

Upload a Portable Executable (PE) file to find its functions. You can also
upload a matching Program Database (PDB) file to add symbol names and module
information. The PDB file is optional. The application is designed for fast
analysis of large native PDB files.

> [!WARNING]
> This project is experimental. Do not upload a sensitive file to a server
> that you do not control.

## Project status

This repository is an experimental prototype. The PE and PDB analysis code and
the RawPDB helper are included. The external Remill-based transformation
executable and its LLVM runtime files are not included. Analysis works without
that executable, but transformations require `RECOMPILER_PATH`.

Disassembly and control-flow graphs require `llvm-objdump.exe`. Configure
`RECOMPILER_OBJDUMP` when it is not supplied beside the transformation
executable.

The API has no user authentication or rate limiting. Add the controls in the
[production deployment](#production-deployment) section before you expose it
to the internet.

## Features

- Validate x86-64 PE files before analysis.
- Analyze a PE file with or without a PDB file.
- Verify the GUID and age of a supplied PDB file.
- Find functions from PDB symbols or PE unwind data.
- Preserve names such as `main`, exported names, and the PE entry point.
- Assign a `sub_<virtual-address>` name when no symbol name exists.
- Group functions by source and category.
- Show Intel-syntax disassembly for each function.
- Show an interactive control-flow graph (CFG).
- Follow direct call and jump targets from the CFG.
- Apply allowlisted obfuscation or deobfuscation passes to selected functions.
- Transform as many as 32 functions in one request and download the resulting PE file.
- Cache analyzed uploads for later disassembly requests.
- Use RawPDB for fast native PDB analysis.
- Process RawPDB results through a compact binary protocol.
- Compress large JSON responses with gzip.
- Paginate large function lists in the browser.

## Fast analysis

The RawPDB helper memory-maps each PDB file. It reads only the streams that are
necessary for function analysis. It sends function records to the backend
through a compact binary protocol.

The backend caches each validated analysis result. Disassembly requests use
the cached result and do not upload or analyze the files again. Gzip responses
and browser pagination reduce the cost of large function lists.

## Components

| Component | Technology | Purpose |
| --- | --- | --- |
| `frontend` | SolidJS, TypeScript, Vite | Displays functions, disassembly, CFGs, and transformation controls. |
| `backend` | Go | Validates uploads and provides the analysis and transformation API. |
| `rawpdb-helper` | C++ and RawPDB | Reads large native PDB files. |
| External tools | LLVM and the private Remill recompiler | Provide disassembly and optional PE transformation. |

## Requirements

Install these tools before you build the complete application:

- Windows on an x86-64 computer
- Go 1.25 or later
- Node.js and npm
- CMake 3.20 or later
- Microsoft Visual C++ build tools

Install LLVM when you want disassembly and CFG support. Supply the external
Remill recompiler and its runtime files only when you want transformations.

## Local setup

### 1. Configure the backend

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

The backend loads `.env` from the repository root. A process environment
variable has priority over the same variable in `.env`.

> [!CAUTION]
> Do not commit `.env`. Configure the Datadog API key in the Datadog Agent, not
> in this project. The repository `.gitignore` file excludes `.env`.

### 2. Build the RawPDB helper

This step is optional. Without the helper, the backend uses its Go PDB parser.

Run these commands from the repository root:

```powershell
cmake -S rawpdb-helper -B rawpdb-helper/build -A x64
cmake --build rawpdb-helper/build --config Release --parallel
```

The backend automatically finds this output file:

```text
rawpdb-helper/build/bin/Release/rawpdb_analyzer.exe
```

### 3. Configure optional analysis and transformation tools

Set `RECOMPILER_OBJDUMP` in `.env` to the full path of `llvm-objdump.exe` when
you want disassembly and CFG support:

```dotenv
RECOMPILER_OBJDUMP=C:\Program Files\LLVM\bin\llvm-objdump.exe
```

The transformation executable is not part of this repository. If you have a
compatible build, set its path in `.env`:

```dotenv
RECOMPILER_PATH=./recompiler/remill_recompiler.exe
```

The backend also accepts a directory that contains `remill_recompiler.exe`.
See [`backend/README.md`](backend/README.md) for LLVM and Remill runtime-path
overrides.

### 4. Start the backend

```powershell
Set-Location backend
go run .
```

The API uses port 8080 on all network interfaces by default. Use
`http://127.0.0.1:8080` from the local computer.

### 5. Start the frontend

Open a second PowerShell terminal. Run these commands:

```powershell
Set-Location frontend
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:5173`. The Vite development server sends `/api`
requests to `http://127.0.0.1:8080`.

## Use the application

1. Select one x86-64 `.exe`, `.dll`, or `.sys` file.
2. Select its native PDB file if one is available.
3. Select **Analyze**.
4. Select a function to see its details.
5. Open **Disassembly** or **Control flow**.
6. Open **Transformations** to apply an available obfuscation or deobfuscation pass.

The backend rejects a PDB file when its GUID or age does not match the PE
file.

## Configuration

Set these values in `.env` or in the process environment:

### Backend analysis and tools

| Variable | Default | Description |
| --- | --- | --- |
| `ADDR` | `:8080` | Sets the API listen address. |
| `RECOMPILER_PATH` | Not set | Sets the external transformation executable or its directory. |
| `RECOMPILER_RAWPDB` | Automatic | Sets the RawPDB helper path. |
| `RECOMPILER_OBJDUMP` | Automatic when bundled | Sets the `llvm-objdump.exe` path. |
| `RECOMPILER_MAX_UPLOAD_MIB` | `1024` | Sets the limit for each uploaded file. The range is 1 through 4096 MiB. |
| `RECOMPILER_CACHE_MIB` | `4096` or larger | Sets the disk-cache capacity. The range is 64 through 65536 MiB. |
| `RECOMPILER_ANALYSIS_WORKERS` | CPU-based | Sets Go parser workers for one job. The range is 1 through 64. |
| `RECOMPILER_ANALYSIS_JOBS` | CPU-based | Sets the number of simultaneous analysis jobs. The range is 1 through 16. |
| `RECOMPILER_LOG_FILE` | `C:\ProgramData\recompiler\logs\backend.log` | Sets the backend log path. |

Set `RECOMPILER_ENV_FILE` in the process environment to select a different
environment file. Relative tool paths in `.env` are relative to the location
of that file.

### Datadog backend telemetry

| Variable | Default | Description |
| --- | --- | --- |
| `DD_TRACE_ENABLED` | `false` | Sends HTTP and analysis spans to the local Datadog Agent. |
| `DD_PROFILING_ENABLED` | `false` | Sends runtime profiles to the local Datadog Agent. |
| `DD_AGENT_HOST` | `127.0.0.1` | Sets the Datadog Agent host for APM and profiling. |
| `DD_TRACE_AGENT_PORT` | `8126` | Sets the Datadog Agent trace port. |
| `DD_SERVICE` | `binary-analysis-api` | Sets the correlated Datadog service name. |
| `DD_ENV` | `development` | Sets the correlated Datadog environment. |
| `DD_VERSION` | `dev` | Sets the deployed application version. |

### Frontend

The frontend uses these build variables. Copy `frontend/.env.example` to
`frontend/.env.local` to set them for local development.

| Variable | Default | Description |
| --- | --- | --- |
| `VITE_API_URL` | Same origin | Sets the API origin for a production frontend build. |
| `VITE_DD_RUM_APPLICATION_ID` | Empty | Enables Browser RUM when this value and the client token are set. |
| `VITE_DD_RUM_CLIENT_TOKEN` | Empty | Sets the public RUM client token. Do not use an API key. |
| `VITE_DD_SITE` | `datadoghq.com` | Sets the Datadog site. |
| `VITE_DD_SERVICE` | `binary-analysis-web` | Sets the frontend service name. |
| `VITE_DD_ENV` | `development` | Sets the frontend environment. |
| `VITE_DD_VERSION` | `dev` | Sets the frontend release version. |
| `VITE_DD_SESSION_SAMPLE_RATE` | `100` | Sets the percentage of browser sessions to collect. |
| `VITE_DD_TRACE_SAMPLE_RATE` | `100` | Sets the percentage of RUM requests that inject trace context. |

## API summary

All upload endpoints use `multipart/form-data`.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Reports API availability. |
| `POST /api/analyze` | Validates uploads and returns function information. |
| `POST /api/disassemble` | Returns instructions, basic blocks, and CFG edges. |
| `POST /api/transform` | Applies allowlisted passes to as many as 32 verified functions. |

An analysis response contains a `cacheId`. Send this value in later requests.
This action prevents another upload of the PE and PDB files.

The cache keeps a maximum of 16 analyzed upload pairs. An unused entry expires
after two hours. The backend removes all entries when it stops.

See [`backend/README.md`](backend/README.md) for request fields and API limits.

## PDB support

The application accepts native Microsoft MSF 7.0 PDB files. It does not accept
portable PDB files from managed .NET builds.

RawPDB memory-maps large PDB files and returns only function records. The Go
backend verifies the PDB identity and each executable relative virtual address
(RVA). The helper uses a pinned RawPDB revision under the BSD 2-Clause license.

## Logs and performance data

The backend writes the same log messages to the console and this file:

```text
C:\ProgramData\recompiler\logs\backend.log
```

Successful analysis responses include a `Server-Timing` header. It reports
upload, PDB analysis, and cache durations.

The function table displays 500 rows on each page. JSON responses use gzip
when the browser accepts it.

### Datadog log collection

The backend emits one-line JSON events for HTTP requests, analysis jobs, queue
time, upload size, response size, and errors. It does not add file names,
function addresses, cache IDs, or client IP addresses to these events.

The repository includes this Datadog Agent configuration:

```text
datadog/conf.d/go.d/conf.yaml
```

Enable logs in `C:\ProgramData\Datadog\datadog.yaml`:

```yaml
logs_enabled: true
```

Run these commands in PowerShell as an administrator:

```powershell
New-Item -ItemType Directory -Force 'C:\ProgramData\Datadog\conf.d\go.d'
Copy-Item 'datadog\conf.d\go.d\conf.yaml' 'C:\ProgramData\Datadog\conf.d\go.d\conf.yaml' -Force
Restart-Service DatadogAgent
```

The Agent sends the logs with service `binary-analysis-api`, source `go`, and
tag `env:production`. Keep the Datadog API key in the Agent configuration.

### Datadog APM, profiling, RUM, and alerts

Set `DD_TRACE_ENABLED=true` and `DD_PROFILING_ENABLED=true` to send backend
traces and profiles to the local Agent. HTTP requests include child spans for
queue wait, PE and PDB analysis, cache writes, disassembly, and transformations.
Correlated JSON logs include the trace ID and span ID.

Browser RUM is disabled until both RUM credentials are set in
`frontend/.env.local`. RUM masks user input and does not record sessions. It
collects resource, interaction, and long-task telemetry. Analysis actions do
not include file names or file contents.

The `datadog/terraform` directory contains six log-based metrics, four
monitors, a 30-day request-success SLO, a service dashboard, and a Synthetic
health check. Log-based metrics are billable Datadog custom metrics. Read
[`datadog/README.md`](datadog/README.md) before you apply the configuration.

## Test the project

Run the backend tests:

```powershell
Set-Location backend
go test ./...
```

Build the frontend:

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run build
```

The workflow in `.github/workflows/windows-ci.yml` builds the RawPDB helper,
tests and vets the backend, builds the frontend, and validates the Terraform
configuration on each push and pull request.

## Production deployment

Do not use the Vite development server as a public server.

Build the frontend with `npm.cmd run build`. Serve the `frontend/dist` directory
with a production web server. Send `/api` requests to the Go backend, or set
`VITE_API_URL` before the frontend build.

Configure the public proxy for the maximum upload size and request duration.
A large PDB file can take several minutes to upload through a slow connection.

Add these controls before a public deployment:

- Authentication
- Rate limits
- TLS
- Upload quotas
- Request logging
- File-retention controls
- Process isolation for native analysis tools

## Known limits

- The backend accepts only x86-64 PE files.
- The backend does not accept portable PDB files.
- A supplied PDB file must match the PE CodeView identity.
- An indirect branch cannot always produce a direct CFG target.
- Disassembly requires LLVM objdump.
- Transformations require a compatible external Remill recompiler and runtime files.

## Project layout

```text
.
|-- .github/          Windows continuous-integration workflow
|-- backend/          Go API
|-- datadog/          Agent, RUM, dashboard, monitor, and SLO configuration
|-- frontend/         SolidJS web application
|-- rawpdb-helper/    RawPDB C++ helper
|-- .env.example      Backend configuration example
`-- README.md         Project documentation
```

## Report a problem

Create a GitHub issue with these details:

- The operation that failed
- The complete error message
- The Windows version
- The Go, Node.js, and CMake versions
- The PE size and PDB size

Do not attach a private binary or PDB file to a public issue.

## License

This repository does not yet include a project license. All rights are
reserved unless a license states otherwise. RawPDB keeps its BSD 2-Clause
license in `rawpdb-helper/RAW_PDB_LICENSE.txt`.
