# Web frontend

This SolidJS and TypeScript application provides the browser interface for the
x86-64 PE analysis backend. It displays discovered functions, Intel-syntax
disassembly, interactive control-flow graphs, and optional transformation
controls.

## Requirements

- Node.js 24 or later
- npm
- The Go backend running locally or at a configured API origin

## Configure the API and Datadog RUM

Copy the public configuration template:

```powershell
Copy-Item .env.example .env.local
```

Leave `VITE_API_URL` empty during local development. The Vite server proxies
`/api` to `http://127.0.0.1:8080`. Set it to the API origin for a deployment
that serves the frontend and backend from different origins.

Datadog RUM stays disabled unless both `VITE_DD_RUM_APPLICATION_ID` and
`VITE_DD_RUM_CLIENT_TOKEN` are set. Do not put a Datadog API key in a frontend
environment file because Vite includes `VITE_` values in the browser bundle.

## Development

```powershell
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:5173`.

## Production build

```powershell
npm.cmd ci
npm.cmd run build
```

The build output is written to `dist`. Serve that directory with a production
web server. Do not expose the Vite development server publicly.

See the repository [`README.md`](../README.md) for the complete setup and
security requirements.
