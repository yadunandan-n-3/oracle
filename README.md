# ORACLE

ORACLE is an AI-native cybersecurity operations platform. Users define security
missions—such as an external attack-surface assessment, API assessment, cloud
audit, or incident investigation—and the runtime turns those goals into tasks,
collects immutable evidence, correlates findings, scores risk, and produces
operator-facing reports and explanations.

## Architecture

- **FastAPI backend** — REST endpoints for missions, assets, findings, reports,
  graph exploration, search, statistics, benchmarking, and the AI copilot.
- **ORACLE runtime** — mission planning, scheduling, policy enforcement, shared
  state, validation, event delivery, resilience, and telemetry.
- **Security intelligence** — CVE/CWE, OWASP, EPSS, KEV, MITRE ATT&CK,
  correlation rules, risk scoring, and explanation services.
- **Tool plugins** — normalized integrations for scanners such as Nmap and
  Nuclei.
- **Next.js console** — dashboard and workflows for missions, findings, assets,
  reports, graph data, search, and copilot interaction.
- **Optional infrastructure** — PostgreSQL, Redis, Neo4j, Qdrant, and MinIO via
  Docker Compose.

See [the architecture guide](docs/ARCHITECTURE.md) for the component model and
[the implementation status](docs/implementation-status.md) for current health.

## Requirements

- Python 3.10 or newer (Python 3.12 is the configured development target)
- Node.js 20 or newer
- Docker Desktop for the optional infrastructure services

## Local setup

Install the backend and development dependencies:

```bash
python -m venv .venv
./.venv/Scripts/python -m pip install -e ".[dev]"
```

On Linux or macOS, use `./.venv/bin/python` instead.

Install the frontend dependencies:

```bash
cd frontend
npm install
```

Optionally start the infrastructure stack from the repository root:

```bash
docker compose -f docker/docker-compose.yml up -d
```

Run the backend and frontend in separate terminals:

```bash
./.venv/Scripts/python -m uvicorn backend.main:app --reload
```

```bash
cd frontend
npm run dev
```

The API is available at `http://localhost:8000` with interactive documentation
at `/docs`. The console is available at `http://localhost:3000` and uses
`NEXT_PUBLIC_API_URL` when set, otherwise `http://localhost:8000/api`.

## Verification

```bash
./.venv/Scripts/python -m pytest -q
cd frontend
npm run lint
npm run build
```

The full local suite currently contains 359 backend tests. External service
connectivity and real scanner binaries require the optional infrastructure and
tools to be running.

