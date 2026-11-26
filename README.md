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
│   ├── remediation-plan.ts            # Lockfile-backed target attribution & repo plan grouping
│   └── remediation.ts                 # Branch naming, Copilot prompt builder & Draft PR Markdown report
├── services/
│   ├── vulnerability-sources.ts       # Source adapter registry (wiz-graphql, future dependabot/snyk...)
│   ├── wiz/                           # Wiz GraphQL adapter -> VulnerabilityFinding[]
│   ├── github/                        # Read-only GitHub client reusing local `gh api`
│   ├── npm/                           # npm v2/v3 package-lock.json dependency chain analyzer
│   └── remediation/                   # Phase 2 & 3: git workspace, Copilot CLI, verify & Draft PR
├── http/
│   ├── app.ts                         # Hono app, optional Bearer auth, /health, error handler
│   └── routes/
│       ├── github.ts                  # GET /api/github/status
│       ├── vulnerabilities.ts         # Phase 1: POST /ingest, POST /plan, GET /sources
│       └── remediation.ts             # Phase 2 & 3: /preflight, /workspace/prepare, /patch, /verify, /pr
└── shared/                            # Subprocess runner, CLI I/O, .runs/ artifact store
```

## Quick Start

```powershell
# Install dependencies (Bun + TypeScript 7 + Hono)
bun install

# Run unit & HTTP tests + typecheck
bun test
bun run typecheck

# Option A: Native Windows (Bun + n8n via npx)
# Terminal 1: Start TaskPilot HTTP API on http://127.0.0.1:3456
bun run dev

# Terminal 2: Start n8n locally (latest; workflow uses only v3-compatible HTTP/Form nodes)
.\scripts\start-n8n.ps1

# Option B (Recommended if npm install is slow on Windows): Windows Bun + WSL Docker n8n
# Terminal 1: Start TaskPilot HTTP API
bun run dev

# Terminal 2 (in WSL): Start n8n in Docker via Docker Compose (defaults to http://localhost:3456)
./scripts/start-n8n-docker.sh   # or: docker compose up -d
```

Import `n8n/wiz-remediation.workflow.json` into n8n (`http://localhost:5678`). It is a single-file, vertically layered 3-phase workflow (Row 1: Phase 1 upload/ingest/plan, Row 2: Phase 2 per-repo workspace + Copilot patch/verify retry loop, Row 3: Phase 3 Draft PR / report & final summary).

### Optional Security (Recommended when calling from Docker n8n v3)

```powershell
$env:TASKPILOT_API_TOKEN = "your-local-secret"
bun run dev
```

When set, all `/api/*` endpoints require `Authorization: Bearer <token>`.
