# ORACLE v0.2 — Stabilization & Polish TODO

## Phase 1 — Backend Stabilization ✅ Complete

### API Enhancements
- [x] 1A.1 Add pagination metadata to `GET /missions` (total, limit, offset, page, pages, has_next, has_prev)
- [x] 1A.2 Add sorting support to `GET /missions` (sort_by: created_at, name, status, priority, mission_type; sort_order: asc/desc)
- [x] 1A.3 Add pagination metadata to `GET /findings`
- [x] 1A.4 Add sorting support to `GET /findings` (sort_by: severity, risk_score, discovered_at, title, status)
- [x] 1A.5 Add try/except error handling to `dashboard.py` with graceful degradation

## Phase 2 — Integration & E2E Testing

### API Tests
- [ ] 2.1 Missions API integration tests
- [ ] 2.2 Findings API integration tests
- [ ] 2.3 Dashboard API integration tests
- [ ] 2.4 Graph API integration tests
- [ ] 2.5 Copilot API integration tests
- [ ] 2.6 Reports API integration tests
- [ ] 2.7 Search API integration tests
- [ ] 2.8 Runtime integration tests
- [ ] 2.9 Full E2E pipeline

## Phase 3 — UI Polish

### Dashboard
- [ ] 3.1 Replace CSS bars with Recharts bar chart for severity
- [ ] 3.2 Add risk trend line chart
- [ ] 3.3 Add mission status donut chart
- [ ] 3.4 Add assets by type chart
- [ ] 3.5 Add top CVEs chart

### Knowledge Graph
- [ ] 3.6 Interactive graph with zoom/pan
- [ ] 3.7 Click node → details panel
- [ ] 3.8 Highlight relationships
- [ ] 3.9 Filter by node type

### AI Copilot
- [ ] 3.10 Improve retrieval pipeline with richer context

## Phase 4 — Benchmarking & Performance

- [ ] 4.1 Collect benchmark measurements
- [ ] 4.2 Create benchmark results dashboard

## Phase 5 — Documentation & Demo

- [ ] 5.1 README.md
- [ ] 5.2 ARCHITECTURE.md with diagrams
- [ ] 5.3 API.md
- [ ] 5.4 DEPLOYMENT.md
- [ ] 5.5 USER_GUIDE.md
- [ ] 5.6 DEVELOPER_GUIDE.md
