# ORACLE Sprint 6–8 Roadmap

> Dashboard → Knowledge Graph → AI Security Analyst

---

## Priority Legend
⭐ = Must-have for demo
☆ = Nice-to-have

---

## Phase 0 — API Stabilization (Priority: ⭐⭐⭐⭐⭐)

### 0.1 Findings API
- [ ] `backend/api/findings.py` — CRUD + filtering by severity, status, mission, asset
- [ ] Models: FindingResponse, FindingListResponse
- [ ] Register router in `backend/main.py`

### 0.2 Reports API
- [ ] `backend/api/reports.py` — Generate, list, get, export reports
- [ ] Models: ReportResponse, ReportListResponse
- [ ] Register router in `backend/main.py`

### 0.3 Knowledge Graph API
- [ ] `backend/api/graph.py` — Get mission graph, attack paths, node details
- [ ] Models: GraphResponse, AttackPathResponse
- [ ] Register router in `backend/main.py`

### 0.4 Timeline API
- [ ] `backend/api/timeline.py` — Get mission event timeline with structured steps
- [ ] Register router in `backend/main.py`

### 0.5 Search API
- [ ] `backend/api/search.py` — Universal search across assets, findings, missions, reports, CVEs
- [ ] Register router in `backend/main.py`

### 0.6 Statistics/Risk API
- [ ] `backend/api/statistics.py` — Aggregate statistics for dashboard widgets
- [ ] Register router in `backend/main.py`

---

## Phase 1 — Dashboard Service (Priority: ⭐⭐⭐⭐⭐)

### 1.1 Dashboard Service
- [ ] `backend/services/dashboard.py` — `DashboardService` that aggregates:
  - Mission counts (active, completed, failed, total)
  - Active assets count
  - Risk distribution (critical/high/medium/low/none)
  - Top vulnerabilities (by risk score)
  - Recent missions (last 10)
  - Recent findings (last 20)
  - Risk trend over time
  - Top CVEs by frequency
  - Recent reports
  - AI recommendations summary

### 1.2 Dashboard API
- [ ] `backend/api/dashboard.py` — `GET /dashboard` returns all aggregated data
- [ ] Register router in `backend/main.py`

---

## Phase 2 — Backend Enhancement (Priority: ⭐⭐⭐⭐⭐)

### 2.1 Copilot API
- [ ] `backend/api/copilot.py` — Chat endpoint with RAG pipeline
- [ ] Models: CopilotRequest, CopilotResponse
- [ ] Register router in `backend/main.py`

### 2.2 OpenAPI Documentation
- [ ] Add comprehensive docstrings to all API endpoints
- [ ] Add response models for auto-generated Swagger docs

### 2.3 Benchmarking Endpoints
- [ ] `backend/api/benchmark.py` — `/api/benchmark/*` endpoints
- [ ] Metrics collection (discovery, correlation, TI, risk, LLM latency)
- [ ] Register router in `backend/main.py`

---

## Phase 3 — Next.js Frontend Setup (Priority: ⭐⭐⭐⭐⭐)

### 3.1 Project Initialization
- [ ] Initialize Next.js 14+ with TypeScript
- [ ] Configure Tailwind CSS
- [ ] Set up project structure (components, pages, services, types)
- [ ] Create API client layer (`services/api.ts`)
- [ ] Install dependencies: TanStack Query, React Flow, Cytoscape.js, Apache ECharts

### 3.2 Layout Components
- [ ] `Layout.tsx` — Main layout with sidebar and header
- [ ] `Sidebar.tsx` — Navigation sidebar with links
- [ ] `Header.tsx` — Top header with search bar and user menu
- [ ] Types definitions (`types/index.ts`)

---

## Phase 4 — Dashboard UI (Priority: ⭐⭐⭐⭐⭐)

### 4.1 Dashboard Page
- [ ] `pages/dashboard.tsx` — Main dashboard page
- [ ] Widget: Mission Status (ECharts donut chart)
- [ ] Widget: Assets (count + trend)
- [ ] Widget: Findings by Severity (ECharts bar chart)
- [ ] Widget: Critical Findings alert
- [ ] Widget: Risk Trend (ECharts line chart)
- [ ] Widget: Top CVEs (table)
- [ ] Widget: Recent Reports (list)
- [ ] Widget: AI Recommendations (card)
- [ ] Widget: Active Missions (table)

---

## Phase 5 — Missions Pages (Priority: ⭐⭐⭐⭐⭐)

### 5.1 Missions List
- [ ] `pages/missions/index.tsx` — Mission list with filters
- [ ] `components/missions/MissionCard.tsx` — Mission summary card
- [ ] `components/missions/MissionFilters.tsx` — Status/type/date filters

### 5.2 Mission Detail
- [ ] `pages/missions/[id].tsx` — Mission detail page
- [ ] `components/missions/MissionHeader.tsx` — Mission info header
- [ ] `components/missions/MissionStats.tsx` — Stats grid
- [ ] `components/missions/MissionTimeline.tsx` — Timeline component

### 5.3 Create Mission
- [ ] `pages/missions/new.tsx` — Create mission form
- [ ] `components/missions/CreateMissionForm.tsx` — Form with target inputs

---

## Phase 6 — Assets Pages (Priority: ⭐⭐⭐⭐⭐)

### 6.1 Assets List
- [ ] `pages/assets/index.tsx` — Asset list with filtering
- [ ] `components/assets/AssetCard.tsx` — Asset summary card
- [ ] `components/assets/AssetFilters.tsx` — Type/status/ports filters

### 6.2 Asset Detail
- [ ] `pages/assets/[id].tsx` — Asset detail page
- [ ] `components/assets/AssetHeader.tsx` — Asset info header
- [ ] `components/assets/AssetFindings.tsx` — Findings for this asset
- [ ] `components/assets/AssetGraph.tsx` — Mini knowledge graph for asset

---

## Phase 7 — Findings Pages (Priority: ⭐⭐⭐⭐⭐)

### 7.1 Findings List
- [ ] `pages/findings/index.tsx` — Finding list with filtering
- [ ] `components/findings/FindingCard.tsx` — Finding summary card
- [ ] `components/findings/FindingFilters.tsx` — Severity/status/asset filters

### 7.2 Finding Detail
- [ ] `pages/findings/[id].tsx` — Finding detail page
- [ ] `components/findings/FindingHeader.tsx` — Finding info header
- [ ] `components/findings/FindingRisk.tsx` — Risk breakdown
- [ ] `components/findings/FindingEvidence.tsx` — Evidence timeline
- [ ] `components/findings/FindingAIExplanation.tsx` — AI explanation card

---

## Phase 8 — Reports Pages (Priority: ⭐⭐⭐⭐)

### 8.1 Reports List
- [ ] `pages/reports/index.tsx` — Report list
- [ ] `components/reports/ReportCard.tsx` — Report summary card

### 8.2 Report Detail
- [ ] `pages/reports/[id].tsx` — Report detail with HTML rendering
- [ ] `components/reports/ReportViewer.tsx` — Report rendering component

### 8.3 Generate Report
- [ ] `pages/reports/generate.tsx` — Report generation form

---

## Phase 9 — Mission Timeline (Priority: ⭐⭐⭐⭐⭐)

### 9.1 Timeline Page
- [ ] `pages/missions/[id]/timeline.tsx` — Full timeline page
- [ ] `components/timeline/TimelineVisualization.tsx` — Interactive timeline
- [ ] `components/timeline/TimelineStep.tsx` — Individual step component
- [ ] `components/timeline/StepDetail.tsx` — Step input/output viewer
- [ ] `components/timeline/MissionReplay.tsx` — Auto-play mission replay

---

## Phase 10 — Knowledge Graph Visualization (Priority: ⭐⭐⭐⭐⭐)

### 10.1 Graph Page
- [ ] `pages/graph/index.tsx` — Knowledge graph page
- [ ] `pages/graph/mission/[id].tsx` — Mission-specific graph
- [ ] `components/graph/KnowledgeGraph.tsx` — Cytoscape.js graph container
- [ ] `components/graph/GraphControls.tsx` — Zoom, filter, layout controls
- [ ] `components/graph/GraphLegend.tsx` — Node/edge legend
- [ ] `components/graph/NodeDetail.tsx` — Node detail panel on click

### 10.2 Attack Path Visualization
- [ ] `pages/graph/attack-paths.tsx` — Attack path analysis page
- [ ] `components/graph/AttackPathView.tsx` — Attack path visualization
- [ ] `components/graph/AttackPathList.tsx` — List of found paths

---

## Phase 11 — AI Security Analyst (Priority: ⭐⭐⭐⭐⭐)

### 11.1 Copilot Page
- [ ] `pages/copilot/index.tsx` — AI Security Analyst chat page
- [ ] `components/copilot/ChatInterface.tsx` — Full chat interface
- [ ] `components/copilot/ChatMessage.tsx` — Message bubble component
- [ ] `components/copilot/QuickActions.tsx` — Suggested questions
- [ ] `components/copilot/ChatSidebar.tsx` — Conversation history

---

## Phase 12 — Universal Search (Priority: ⭐⭐⭐⭐)

### 12.1 Search Implementation
- [ ] `components/search/SearchBar.tsx` — Global search bar in header
- [ ] `components/search/SearchResults.tsx` — Search results dropdown
- [ ] `pages/search.tsx` — Full search results page

---

## Phase 13 — Benchmarking (Priority: ⭐⭐⭐⭐)

### 13.1 Benchmark UI
- [ ] `pages/benchmark/index.tsx` — Benchmark dashboard
- [ ] `components/benchmark/BenchmarkChart.tsx` — Latency charts
- [ ] `components/benchmark/BenchmarkTable.tsx` — Metrics table

---

## Phase 14 — Documentation (Priority: ⭐⭐⭐⭐)

### 14.1 Project Documentation
- [ ] `docs/ARCHITECTURE.md` — Update with new frontend architecture
- [ ] `docs/API.md` — API reference
- [ ] `docs/DASHBOARD.md` — Dashboard guide
- [ ] `docs/DEPLOYMENT.md` — Deployment guide
- [ ] `README.md` — Update with new features and screenshots

---

## Progress Tracking

| Phase | Feature | Status |
|-------|---------|--------|
| 0 | API Stabilization | ✅ Complete |
| 1 | Dashboard Service | ✅ Complete |
| 2 | Backend Enhancement | ✅ Complete |
| 3 | Frontend Setup | ✅ Complete |
| 4 | Dashboard UI | ✅ Complete |
| 5 | Missions Pages | ✅ Complete |
| 6 | Assets Pages | ✅ Complete |
| 7 | Findings Pages | ✅ Complete |
| 8 | Reports Pages | ✅ Complete |
| 9 | Mission Timeline | ✅ Complete |
| 10 | Knowledge Graph | ✅ Complete |
| 11 | AI Security Analyst | ✅ Complete |
| 12 | Universal Search | ✅ Complete |
| 13 | Benchmarking | ✅ Complete |
| 14 | Documentation | ⬜ Not Started |

