-- ============================================================================
-- ORACLE Database Schema
-- ============================================================================
-- PostgreSQL initialization script for the ORACLE platform.
-- Creates all tables needed for the Mission -> Discovery -> Evidence pipeline.

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- Organizations
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT DEFAULT '',
    slug            VARCHAR(255) UNIQUE,
    domain          VARCHAR(255),
    plan            VARCHAR(50) DEFAULT 'free',
    is_active       BOOLEAN DEFAULT TRUE,
    settings        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- Users
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    name            VARCHAR(255) DEFAULT '',
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(50) DEFAULT 'viewer',
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    is_active       BOOLEAN DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);

-- ============================================================================
-- Missions
-- ============================================================================

CREATE TABLE IF NOT EXISTS missions (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                    VARCHAR(255) NOT NULL,
    description             TEXT DEFAULT '',
    mission_type            VARCHAR(50) NOT NULL,
    priority                VARCHAR(20) DEFAULT 'medium',
    status                  VARCHAR(20) DEFAULT 'draft',

    -- Target scope
    target_domains          TEXT[] DEFAULT '{}',
    target_ip_ranges        TEXT[] DEFAULT '{}',
    target_urls             TEXT[] DEFAULT '{}',
    target_api_endpoints    TEXT[] DEFAULT '{}',
    target_excluded         TEXT[] DEFAULT '{}',

    -- Organization
    organization_id         UUID REFERENCES organizations(id) ON DELETE SET NULL,
    project_id              UUID,
    created_by              VARCHAR(255),
    assigned_to             VARCHAR(255),

    -- Policy
    policy_id               UUID,
    allowed_techniques      TEXT[] DEFAULT '{}',
    restricted_techniques   TEXT[] DEFAULT '{}',

    -- Execution
    max_duration_minutes    INTEGER,
    schedule                VARCHAR(100),
    auto_remediate          BOOLEAN DEFAULT FALSE,

    -- Results summary
    total_assets_discovered INTEGER DEFAULT 0,
    total_findings          INTEGER DEFAULT 0,
    critical_findings       INTEGER DEFAULT 0,
    high_findings           INTEGER DEFAULT 0,
    medium_findings         INTEGER DEFAULT 0,
    low_findings            INTEGER DEFAULT 0,
    overall_risk_score      REAL,

    -- Goals stored as JSON array
    goals                   JSONB DEFAULT '[]',

    -- Timeline
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    updated_at              TIMESTAMPTZ DEFAULT NOW(),

    -- Tags & metadata
    tags                    TEXT[] DEFAULT '{}',
    metadata                JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_missions_status ON missions(status);
CREATE INDEX IF NOT EXISTS idx_missions_type ON missions(mission_type);
CREATE INDEX IF NOT EXISTS idx_missions_organization ON missions(organization_id);
CREATE INDEX IF NOT EXISTS idx_missions_created_at ON missions(created_at DESC);

-- ============================================================================
-- Tasks (planned and executed)
-- ============================================================================

CREATE TABLE IF NOT EXISTS tasks (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id          UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    goal_id             UUID,
    name                VARCHAR(255) NOT NULL,
    description         TEXT DEFAULT '',
    status              VARCHAR(20) DEFAULT 'pending',
    priority            INTEGER DEFAULT 2,

    -- Capability requirements
    required_capabilities   TEXT[] DEFAULT '{}',
    required_tools          TEXT[] DEFAULT '{}',

    -- Dependencies
    depends_on          UUID[] DEFAULT '{}',

    -- Execution config
    config              JSONB DEFAULT '{}',
    timeout_seconds     INTEGER DEFAULT 300,
    retry_on_failure    BOOLEAN DEFAULT TRUE,
    max_retries         INTEGER DEFAULT 3,

    -- Results
    evidence_ids        UUID[] DEFAULT '{}',
    error               TEXT,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tasks_mission ON tasks(mission_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);

-- ============================================================================
-- Assets
-- ============================================================================

CREATE TABLE IF NOT EXISTS assets (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id      UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    asset_type      VARCHAR(50) NOT NULL,
    value           VARCHAR(255) NOT NULL,
    label           VARCHAR(255) DEFAULT '',
    description     TEXT DEFAULT '',
    status          VARCHAR(20) DEFAULT 'active',
    criticality     VARCHAR(20) DEFAULT 'unknown',
    ip_addresses    TEXT[] DEFAULT '{}',
    hostnames       TEXT[] DEFAULT '{}',
    domains         TEXT[] DEFAULT '{}',
    open_ports      INTEGER[] DEFAULT '{}',
    services        TEXT[] DEFAULT '{}',
    technologies    TEXT[] DEFAULT '{}',
    mac_address     VARCHAR(17),
    os              VARCHAR(255),
    os_version      VARCHAR(100),
    tags            TEXT[] DEFAULT '{}',
    metadata        JSONB DEFAULT '{}',
    first_seen_at   TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(mission_id, value)
);

CREATE INDEX IF NOT EXISTS idx_assets_mission ON assets(mission_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);

-- ============================================================================
-- Evidence
-- ============================================================================

CREATE TABLE IF NOT EXISTS evidence (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id          UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    evidence_type       VARCHAR(50) NOT NULL,
    status              VARCHAR(20) DEFAULT 'collected',
    title               VARCHAR(255) NOT NULL,
    description         TEXT DEFAULT '',
    confidence          REAL DEFAULT 0.0,
    severity            VARCHAR(20) DEFAULT 'informational',

    -- Source info
    source_tool_name    VARCHAR(100) NOT NULL,
    source_tool_version VARCHAR(50) DEFAULT '',
    source_command      TEXT DEFAULT '',
    source_agent_name   VARCHAR(100) DEFAULT '',
    source_execution_id UUID,

    -- Asset reference
    asset_id            UUID REFERENCES assets(id) ON DELETE SET NULL,
    asset_value         VARCHAR(255) DEFAULT '',

    -- Data
    raw_data            JSONB DEFAULT '{}',
    normalized_data     JSONB DEFAULT '{}',

    -- Correlations
    correlated_evidence_ids UUID[] DEFAULT '{}',

    -- Security references
    cve_ids             TEXT[] DEFAULT '{}',
    cwe_ids             TEXT[] DEFAULT '{}',
    mitre_techniques    TEXT[] DEFAULT '{}',

    -- Validation
    validated_at        TIMESTAMPTZ,
    validated_by        VARCHAR(100),
    validation_method   VARCHAR(100) DEFAULT '',

    -- Hash for deduplication
    hash                VARCHAR(64),

    -- Tags & metadata
    tags                TEXT[] DEFAULT '{}',
    metadata            JSONB DEFAULT '{}',

    -- Timeline
    collected_at        TIMESTAMPTZ DEFAULT NOW(),
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_mission ON evidence(mission_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_evidence_asset ON evidence(asset_id);
CREATE INDEX IF NOT EXISTS idx_evidence_hash ON evidence(hash);

-- ============================================================================
-- Findings
-- ============================================================================

CREATE TABLE IF NOT EXISTS findings (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id              UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    title                   VARCHAR(255) NOT NULL,
    description             TEXT DEFAULT '',
    severity                VARCHAR(20) DEFAULT 'medium',
    status                  VARCHAR(20) DEFAULT 'open',

    -- Asset reference
    asset_id                UUID REFERENCES assets(id) ON DELETE SET NULL,
    asset_value             VARCHAR(255) DEFAULT '',
    asset_type              VARCHAR(50) DEFAULT '',

    -- Related evidence
    evidence_ids            UUID[] DEFAULT '{}',

    -- Vulnerability references
    cve_id                  VARCHAR(20),
    cwe_id                  VARCHAR(20),
    cvss_score              REAL,
    cvss_vector             VARCHAR(100),
    mitre_technique_id      VARCHAR(20),
    mitre_tactic            VARCHAR(50),

    -- Remediation
    remediation_steps       TEXT[] DEFAULT '{}',
    remediation_effort      VARCHAR(50) DEFAULT '',
    remediation_deadline    TIMESTAMPTZ,
    proof_of_concept        TEXT DEFAULT '',

    -- Context
    affected_component      VARCHAR(255) DEFAULT '',
    affected_url            TEXT DEFAULT '',
    affected_port           INTEGER,
    business_impact         TEXT DEFAULT '',
    data_classification     VARCHAR(50) DEFAULT '',
    internet_exposed        BOOLEAN DEFAULT FALSE,
    authentication_required BOOLEAN DEFAULT FALSE,

    -- Risk scoring
    risk_score              REAL,
    confidence              REAL DEFAULT 0.0,

    -- Audit
    discovered_by           VARCHAR(100) DEFAULT '',
    assigned_to             VARCHAR(100),
    discovered_at           TIMESTAMPTZ DEFAULT NOW(),
    resolved_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW(),

    -- Tags & metadata
    tags                    TEXT[] DEFAULT '{}',
    metadata                JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_mission ON findings(mission_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve_id);

-- ============================================================================
-- Risks
-- ============================================================================

CREATE TABLE IF NOT EXISTS risks (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id      UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    finding_id      UUID REFERENCES findings(id) ON DELETE SET NULL,
    asset_id        UUID REFERENCES assets(id) ON DELETE SET NULL,
    risk_score      REAL NOT NULL DEFAULT 0.0,
    likelihood      REAL DEFAULT 0.5,
    impact          REAL DEFAULT 0.5,
    severity        VARCHAR(20) DEFAULT 'medium',

    -- Risk factors
    factors         JSONB DEFAULT '{}',

    -- Business context
    business_impact TEXT DEFAULT '',
    data_sensitivity VARCHAR(50) DEFAULT '',
    exploitability  REAL DEFAULT 0.5,

    -- Actions
    recommended_action TEXT DEFAULT '',
    owner           VARCHAR(100),
    deadline        TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'open',

    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risks_mission ON risks(mission_id);
CREATE INDEX IF NOT EXISTS idx_risks_score ON risks(risk_score DESC);

-- ============================================================================
-- Reports
-- ============================================================================

CREATE TABLE IF NOT EXISTS reports (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id      UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    title           VARCHAR(255) NOT NULL,
    format          VARCHAR(20) DEFAULT 'html',
    status          VARCHAR(20) DEFAULT 'draft',
    sections        JSONB DEFAULT '[]',
    executive_summary TEXT DEFAULT '',
    recommendations TEXT[] DEFAULT '{}',
    findings_summary JSONB DEFAULT '{}',
    statistics      JSONB DEFAULT '{}',
    generated_by    VARCHAR(100),
    generated_at    TIMESTAMPTZ,
    file_path       TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_mission ON reports(mission_id);

-- ============================================================================
-- Asset Relationships (for Neo4j fallback / query)
-- ============================================================================

CREATE TABLE IF NOT EXISTS asset_relationships (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id          UUID NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    source_asset_id     UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id     UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    relationship_type   VARCHAR(50) NOT NULL,
    properties          JSONB DEFAULT '{}',
    confidence          REAL DEFAULT 1.0,
    discovered_at       TIMESTAMPTZ DEFAULT NOW(),
    created_at          TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(source_asset_id, target_asset_id, relationship_type)
);

CREATE INDEX IF NOT EXISTS idx_relationships_mission ON asset_relationships(mission_id);
CREATE INDEX IF NOT EXISTS idx_relationships_source ON asset_relationships(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_relationships_target ON asset_relationships(target_asset_id);

-- ============================================================================
-- Event Log (for mission timeline)
-- ============================================================================

CREATE TABLE IF NOT EXISTS event_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id      UUID REFERENCES missions(id) ON DELETE CASCADE,
    event_type      VARCHAR(100) NOT NULL,
    source          VARCHAR(100) DEFAULT '',
    data            JSONB DEFAULT '{}',
    correlation_id  VARCHAR(100),
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_event_log_mission ON event_log(mission_id);
CREATE INDEX IF NOT EXISTS idx_event_log_type ON event_log(event_type);
CREATE INDEX IF NOT EXISTS idx_event_log_timestamp ON event_log(timestamp DESC);

-- ============================================================================
-- Config / Settings
-- ============================================================================

CREATE TABLE IF NOT EXISTS system_config (
    key             VARCHAR(255) PRIMARY KEY,
    value           JSONB NOT NULL,
    description     TEXT DEFAULT '',
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- Functions & Triggers
-- ============================================================================

-- Auto-update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables with updated_at
CREATE TRIGGER update_organizations_updated_at
    BEFORE UPDATE ON organizations FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_missions_updated_at
    BEFORE UPDATE ON missions FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tasks_updated_at
    BEFORE UPDATE ON tasks FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_assets_updated_at
    BEFORE UPDATE ON assets FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_evidence_updated_at
    BEFORE UPDATE ON evidence FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_findings_updated_at
    BEFORE UPDATE ON findings FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_risks_updated_at
    BEFORE UPDATE ON risks FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Seed Data
-- ============================================================================

-- Default organization
INSERT INTO organizations (id, name, slug, description)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Default Organization',
    'default',
    'Default organization for self-hosted ORACLE instances'
) ON CONFLICT (id) DO NOTHING;

-- Default admin user (password: admin123)
INSERT INTO users (id, email, name, password_hash, role, organization_id)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    'admin@oracle.local',
    'Admin',
    '$2b$12$LJ3m4ys3Lk0TSwHnbfOMiOXPm1QnqYjsUkqULvFZqGzGqGzGqGzG',
    'admin',
    '00000000-0000-0000-0000-000000000001'
) ON CONFLICT (id) DO NOTHING;
