# ORACLE OS Architecture

> AI-native Operating System for Cybersecurity

## Table of Contents
1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [System Architecture](#system-architecture)
4. [Runtime Architecture](#runtime-architecture)
5. [Mission Lifecycle](#mission-lifecycle)
6. [Domain Models](#domain-models)
7. [Event System](#event-system)
8. [Capability Graph](#capability-graph)
9. [Plugin System](#plugin-system)
10. [Development Guide](#development-guide)

---

## Overview

ORACLE is an **AI-native Operating System for Cybersecurity**. It is not an application — it is a platform on which security agents, tools, and integrations run.

### Design Philosophy

| Principle | Description |
|-----------|-------------|
| **Mission-driven** | Users create missions, not scans |
| **Event-driven** | Everything is an event |
| **Evidence-first** | Everything becomes evidence |
| **Capability-based** | Agents compose capabilities |
| **Policy-enforced** | Every action checks policy |
| **Plugin-extensible** | Every tool is a plugin |

---

## Core Concepts

### 1. Mission

The highest-level abstraction. Users describe what they want to accomplish:

```text
External Attack Surface Assessment
API Security Assessment
Cloud Audit
Incident Investigation
```

### 2. Capability

Reusable building blocks that agents compose:

```text
port_scanning
service_discovery
technology_detection
vulnerability_scanning
risk_assessment
```

### 3. Evidence

The universal data model. Everything — raw output, parsed findings, validated results — is Evidence.

### 4. Event

All communication happens through events. No component calls another directly.

### 5. Plugin

Tools, agents, and integrations are plugins that follow standard interfaces.

---

## System Architecture

```
                    ┌──────────────────────┐
                    │   Next.js Dashboard   │
                    │  (TypeScript/Tailwind) │
                    └──────────┬───────────┘
                               │ REST API
                    ┌──────────▼───────────┐
                    │   FastAPI Backend     │
                    │   (Python 3.12)       │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   ORACLE Runtime      │
                    │   (The Kernel)        │
                    └──────────┬───────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   AI Layer    │    │  Tool Plugins │    │  External     │
│  (LangGraph)  │    │  (Nmap, etc)  │    │  Services     │
└───────────────┘    └───────────────┘    └───────────────┘
```

---

## Runtime Architecture

The Runtime is the operating system kernel. It owns all orchestration.

```
                    ┌─────────────────────────────┐
                    │      ORACLE Runtime          │
                    │                              │
                    │  ┌───────────────────────┐   │
                    │  │     Event Bus          │   │
                    │  │  (Pub/Sub Messaging)   │   │
                    │  └───────────────────────┘   │
                    │                              │
   ┌────────────┬────────────┬────────────┬────────┴───┐
   │            │            │            │            │
   ▼            ▼            ▼            ▼            ▼
┌──────┐  ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐
│Mission│  │ Planner  │ │Scheduler│ │Workflow  │ │  State   │
│Manager│  │(Goal→Task)│ │(Priority│ │ Engine   │ │ Manager  │
│       │  │          │ │ Queue)  │ │(Orch.)   │ │(Live St.)│
└──────┘  └──────────┘ └─────────┘ └──────────┘ └──────────┘
   │            │            │            │            │
   ▼            ▼            ▼            ▼            ▼
┌──────────┐ ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐
│ Policy   │ │ Resource │ │Telemetry│ │Validator │ │ Evidence │
│ Engine   │ │ Manager  │ │         │ │          │ │ Engine   │
└──────────┘ └──────────┘ └─────────┘ └──────────┘ └──────────┘
```

---

## Mission Lifecycle

```
CREATE → PLAN → EXECUTE → MONITOR → COMPLETE

1. CREATE
   User defines mission scope, goals, and targets
   → MISSION_CREATED event

2. PLAN
   Mission Manager invokes Planner
   Planner breaks goals into capability-based tasks
   Policy Engine validates the plan
   → MISSION_PLANNED event

3. EXECUTE
   Scheduler dispatches tasks via priority queue
   Workflow Engine coordinates execution order
   Agents execute tasks, tools run in sandbox
   Evidence collected and validated
   → Various progress events

4. MONITOR
   State Manager tracks live state
   Real-time updates to dashboard
   Telemetry captures metrics
   → Continuous event stream

5. COMPLETE
   All tasks completed or failed
   Report generated
   State archived
   → MISSION_COMPLETED / MISSION_FAILED event
```

---

## Event System

All communication is event-driven. No component calls another directly.

```python
# Producer publishes
event = OracleEvent(
    event_type=EventType.ASSET_DISCOVERED,
    source="discovery_agent",
    data={"asset": asset.model_dump()}
)
await event_bus.publish(event)

# Subscriber receives
async def on_asset_discovered(event: OracleEvent):
    asset = event.data["asset"]
    await knowledge_graph.add_asset(asset)

event_bus.subscribe(
    "graph_updater",
    {EventType.ASSET_DISCOVERED},
    on_asset_discovered
)
```

### Key Event Types

| Category | Events |
|----------|--------|
| System | SYSTEM_STARTUP, SYSTEM_SHUTDOWN, SYSTEM_ERROR |
| Mission | MISSION_CREATED, MISSION_STARTED, MISSION_PLANNED, MISSION_COMPLETED |
| Discovery | ASSET_DISCOVERED, SERVICE_IDENTIFIED, TECHNOLOGY_DETECTED |
| Findings | VULNERABILITY_FOUND, VULNERABILITY_CONFIRMED, EXPOSURE_DETECTED |
| Evidence | EVIDENCE_COLLECTED, EVIDENCE_VALIDATED |
| Risk | RISK_CALCULATED, RISK_UPDATED |
| Graph | GRAPH_UPDATED, ATTACK_PATH_FOUND |
| Policy | POLICY_CHECK_PASSED, POLICY_CHECK_FAILED, POLICY_VIOLATION |

---

## Domain Models

Business objects exist independently of persistence.

```
oracle/domain/
├── asset.py        # Discovered digital assets
├── evidence.py     # Universal evidence model
├── finding.py      # Validated security findings
├── mission.py      # Mission definitions + templates
├── report.py       # Generated reports
├── risk.py         # Risk assessment models
├── organization.py # Organization/project structure
└── user.py         # User accounts and roles
```

---

## Capability Graph

Agents don't own capabilities — they compose them.

```text
API Security Mission
│
├── Capability: api_discovery
│   └── Tools: [ffuf, nuclei]
│
├── Capability: authentication_testing
│   └── Tools: [zap, custom]
│
├── Capability: vulnerability_scanning
│   └── Tools: [nuclei, zap]
│
├── Capability: risk_assessment
│   └── Tools: [engine]
│
└── Capability: reporting
    └── Tools: [report_generator]
```

---

## Plugin System

Every tool follows the same interface:

```python
class SecurityTool(Protocol):
    name: str
    capabilities: List[str]

    async def health_check(self) -> Dict[str, Any]: ...
    async def execute(self, config: Dict) -> AsyncIterator[bytes]: ...
    async def parse(self, output: bytes) -> List[Evidence]: ...
    async def normalize(self, evidence: List[Evidence]) -> List[Evidence]: ...
```

Every agent follows the same interface:

```python
class OracleAgent(Protocol):
    name: str
    capabilities: List[Capability]

    async def plan(self, context) -> List[Dict]: ...
    async def execute(self, context) -> AsyncIterator[Evidence]: ...
    async def validate(self, context) -> List[Evidence]: ...
    async def explain(self, context) -> str: ...
```

---

## Development Guide

### Prerequisites

- Python 3.12+
- Docker Desktop
- Node.js 20+

### Setup

```bash
# Clone repository
git clone https://github.com/your-org/oracle.git
cd oracle

# Install Python dependencies
pip install -e ".[dev]"

# Start infrastructure
docker compose -f docker/docker-compose.yml up -d

# Start backend
uvicorn backend.main:app --reload

# Start frontend
cd frontend && npm install && npm run dev
```

### Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=oracle --cov-report=html

# Specific test file
pytest tests/unit/test_event_bus.py
```

### Code Quality

```bash
# Format code
ruff format .

# Lint
ruff check .

# Type check
mypy .
```

### Project Structure

```
oracle/
├── core/           # Shared infrastructure
│   ├── config/     # Configuration management
│   ├── events/     # Event definitions
│   ├── exceptions/ # Error hierarchy
│   ├── interfaces/ # Abstract protocols
│   ├── logging/    # Structured logging
│   ├── security/   # Auth & crypto
│   ├── telemetry/  # OpenTelemetry
│   └── utils/      # Common utilities
│
├── backend/        # FastAPI application
│   ├── api/        # REST API routes
│   ├── auth/       # Authentication
│   ├── models/     # SQLAlchemy models
│   ├── schemas/    # Pydantic schemas
│   └── services/   # Business logic
│
├── runtime/        # Operating system kernel
│   ├── event_bus/  # Pub/sub messaging
│   ├── mission_manager/ # Mission lifecycle
│   ├── planner/    # Goal decomposition
│   ├── scheduler/  # Priority queue
│   ├── workflow/   # Orchestration
│   ├── state_manager/ # Live mission state
│   ├── policy_engine/ # Governance
│   ├── resource_manager/ # Compute limits
│   └── validator/  # Evidence validation
│
├── domain/         # Business objects
│   ├── asset/      # Digital assets
│   ├── evidence/   # Universal evidence
│   ├── finding/    # Security findings
│   ├── mission/    # Mission definitions
│   ├── report/     # Report generation
│   ├── risk/       # Risk assessment
│   ├── organization/ # Org structure
│   └── user/       # User accounts
│
├── ai/             # AI layer
│   ├── agents/     # Agent implementations
│   ├── llm/        # LLM clients
│   ├── prompts/    # Prompt builder
│   ├── embeddings/ # Vector embeddings
│   └── rag/        # RAG pipeline
│
├── knowledge/      # Knowledge service
│   ├── mitre/      # MITRE ATT&CK
│   ├── owasp/      # OWASP Top 10
│   ├── cve/        # CVE database
│   └── cwe/        # CWE database
│
├── tools/          # Tool plugins
│   ├── nmap/       # Port scanning
│   ├── nuclei/     # Vulnerability scanning
│   ├── zap/        # Web app scanning
│   └── common/     # Shared tool code
│
├── docker/         # Container configs
├── docs/           # Documentation
├── tests/          # Test suites
└── scripts/        # Utility scripts
```

## License

MIT
