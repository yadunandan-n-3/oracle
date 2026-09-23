# Sprint 5 — Intelligence Pipeline

## Status: In Progress

---

## Architecture & Design Principles
- Evidence is **immutable** — never modified after collection
- Threat Intelligence uses **provider-based** architecture (MITRE, CVE, EPSS, KEV, OWASP)
- Correlation uses **extensible rule engine** (CorrelationRule base class)
- Risk Engine V2 alongside V1 (backward compatible)
- AI Explanation returns **structured JSON**, never reads raw tool output
- Event-driven pipeline with `FindingEnrichedEvent`

---

## Phase 1: Domain Models & Base Infrastructure

### 1.1 Domain Intelligence Models
- [ ] `domain/intelligence/__init__.py` — `ThreatIntelligence`, `EnrichedFinding`, `CVEInfo`, `CWEInfo`, `OWASPInfo`, `EPSSInfo`, `KEVInfo`
- [ ] `domain/correlation/__init__.py` — `CorrelationRule`, `CorrelationResult`, `EvidenceCorrelator`
- [ ] `domain/scoring/__init__.py` — `OracleRiskScoreV2`, `RiskFactorV2`, `RiskExplanation`
- [ ] `domain/scoring/asset_intelligence.py` — `AssetIntelligence` model
- [ ] `domain/scoring/finding_revision.py` — `FindingRevision`, `VersionedFinding`

### 1.2 Event Models
- [ ] Update `core/events/__init__.py` — Add `FindingEnrichedEvent`

---

## Phase 2: Milestone 1 — Threat Intelligence Engine

### 2.1 Provider Base
- [ ] `knowledge/intelligence/__init__.py` — `ThreatIntelligenceProvider` base class

### 2.2 CVE Service
- [ ] `knowledge/cve/__init__.py` — `CVEService` with NVD API, local cache, fallback

### 2.3 CWE Service
- [ ] `knowledge/cwe/__init__.py` — `CWEService` with CWE database lookup

### 2.4 OWASP Service
- [ ] `knowledge/owasp/__init__.py` — `OWASPService` with CWE→OWASP mapping

### 2.5 EPSS Service
- [ ] `knowledge/epss/__init__.py` — `EPSSService` with FIRST API integration

### 2.6 KEV Service
- [ ] `knowledge/kev/__init__.py` — `KEVService` with CISA KEV catalog

### 2.7 Threat Intelligence Orchestrator
- [ ] `knowledge/intelligence/service.py` — `ThreatIntelligenceService` (orchestrates all providers)

---

## Phase 3: Milestone 2 — Evidence Correlation Engine

### 3.1 Correlation Rule Engine
- [ ] `domain/correlation/rules/__init__.py`
- [ ] `domain/correlation/rules/apache_rule.py` — Detect Apache + CVE-2021-41773 pattern
- [ ] `domain/correlation/rules/ssh_rule.py` — SSH version + CVE correlation
- [ ] `domain/correlation/rules/http_rule.py` — HTTP service + vulnerability correlation
- [ ] `domain/correlation/rules/generic_rule.py` — IP/hostname/port/technology matching

### 3.2 Evidence Correlator
- [ ] `domain/correlation/correlator.py` — `EvidenceCorrelator` that runs all rules

---

## Phase 4: Security Intelligence Service

### 4.1 Security Intelligence Service
- [ ] `domain/intelligence/service.py` — `SecurityIntelligenceService` (combines evidence + threat intel + correlation)

---

## Phase 5: Milestone 3 — Oracle Risk Engine V2

### 5.1 Risk Engine V2
- [ ] `domain/risk/engine_v2.py` — `RiskEngineV2` with 0-100 scoring, all requested inputs

---

## Phase 6: Milestone 4 — AI Explanation Engine

### 6.1 LLM Provider Abstraction
- [ ] `ai/providers/__init__.py` — `LLMProvider` ABC + `OpenAIProvider` + `MockProvider`

### 6.2 Prompt Templates
- [ ] `ai/prompts/explanation_prompts.py` — Structured prompt templates

### 6.3 AI Explanation Service
- [ ] `ai/explanation/__init__.py` — `AIExplanationService` with prompt builder, structured JSON output

---

## Phase 7: Pipeline Integration

### 7.1 Wire Into Runtime
- [ ] Update `runtime/runtime.py` — Add enrichment, correlation, risk v2, explanation steps

### 7.2 Wire Into Report Generator
- [ ] Update `domain/report/generator.py` — Use enriched findings + AI explanations

### 7.3 Update Knowledge Graph
- [ ] Update `knowledge/__init__.py` — Add enriched finding nodes

---

## Phase 8: Tests

### 8.1 Unit Tests
- [ ] `tests/unit/test_cve_service.py`
- [ ] `tests/unit/test_epss_service.py`
- [ ] `tests/unit/test_kev_service.py`
- [ ] `tests/unit/test_owasp_service.py`
- [ ] `tests/unit/test_correlation.py`
- [ ] `tests/unit/test_risk_engine_v2.py`
- [ ] `tests/unit/test_explanation_engine.py`
- [ ] `tests/unit/test_threat_intelligence.py`
- [ ] `tests/unit/test_security_intelligence.py`

### 8.2 Integration Tests
- [ ] `tests/integration/test_intelligence_pipeline.py` — Full pipeline test

---

## Progress

| Phase | Status |
|-------|--------|
| Phase 1: Domain Models & Base Infrastructure | ✅ Complete |
| Phase 2: Threat Intelligence Engine | ✅ Complete |
| Phase 3: Evidence Correlation Engine | ✅ Complete |
| Phase 4: Security Intelligence Service | ✅ Complete |
| Phase 5: Risk Engine V2 | ✅ Complete |
| Phase 6: AI Explanation Engine | ✅ Complete |
| Phase 7: Pipeline Integration | ✅ Complete |
| Phase 8: Tests | ✅ Complete (47 new unit tests, all passing) |

