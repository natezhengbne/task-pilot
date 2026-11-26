# TaskPilot

A TypeScript (Bun + Hono) **capability API server** designed to be orchestrated by **n8n** (compatible with both local n8n v2 and Docker n8n v3).

* **n8n** owns the **Workflow** (form upload, branching, approvals, notifications).
* **TaskPilot** runs natively on Windows (direct access to local `gh`, Copilot CLI, Git, and npm) and exposes **source-agnostic domain HTTP APIs**.

## Architecture

```text
src/
├── server.ts                          # Bun.serve entrypoint (default http://127.0.0.1:3456)
├── cli.ts                             # Optional local CLI runner calling the same domain logic
├── domain/
│   ├── vulnerability.ts               # Vendor-neutral Finding & ingest policy
│   └── remediation-plan.ts            # Lockfile-backed target attribution & repo plan grouping
├── services/
│   ├── vulnerability-sources.ts       # Source adapter registry (wiz-graphql, future dependabot/snyk...)
│   ├── wiz/                           # Wiz GraphQL adapter -> VulnerabilityFinding[]
│   ├── github/                        # Read-only GitHub client reusing local `gh api`
│   └── npm/                           # npm v2/v3 package-lock.json dependency chain analyzer
├── http/
│   ├── app.ts                         # Hono app, optional Bearer auth, /health, error handler
│   └── routes/
│       └── vulnerabilities.ts         # POST /ingest, POST /plan, GET /sources
└── shared/                            # Subprocess runner, CLI I/O, .runs/ artifact store
```

## Quick Start

```powershell
# Install dependencies (Bun + TypeScript 7 + Hono)
bun install

# Run unit & HTTP tests + typecheck
bun test
bun run typecheck

# Terminal 1: Start TaskPilot HTTP API on http://127.0.0.1:3456
bun run dev

# Terminal 2: Start n8n locally (v2.49.6; workflow uses only v3-compatible HTTP/Form nodes)
.\scripts\start-n8n.ps1
```

Import `n8n/wiz-remediation.workflow.json` into n8n (`http://localhost:5678`). The workflow uses only v2/v3-compatible core nodes (`Form Trigger` → `Extract from File (JSON)` → `HTTP Request` sending pure `application/json`) and returns standardized `targets[]` and `findings[]`.

### Optional Security (Recommended when calling from Docker n8n v3)

```powershell
$env:TASKPILOT_API_TOKEN = "your-local-secret"
bun run dev
```

When set, all `/api/*` endpoints require `Authorization: Bearer <token>`.
