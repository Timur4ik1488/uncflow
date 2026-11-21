-- =============================================================================
-- AI Security Workflow Platform — PostgreSQL Database Schema
-- Designed for Cyber Garden 2026 (Case: Bank Center-Invest)
-- =============================================================================

-- 1. Workflow Runs: Execution history, metadata, and status
CREATE TABLE IF NOT EXISTS workflow_runs (
    id VARCHAR(64) PRIMARY KEY,
    workflow_id VARCHAR(64) NOT NULL,
    workflow_name VARCHAR(255) NOT NULL,
    success BOOLEAN NOT NULL DEFAULT true,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ,
    findings_count INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_runs_created_at ON workflow_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_workflow_id ON workflow_runs(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_success ON workflow_runs(success);

-- 2. Findings: Individual security issues (SECRET, SAST, SCA)
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    run_id VARCHAR(64) REFERENCES workflow_runs(id) ON DELETE CASCADE,
    category VARCHAR(32) NOT NULL, -- SECRET | SAST | SCA
    path TEXT NOT NULL,
    line INTEGER,
    end_line INTEGER,
    class VARCHAR(128),
    group_name VARCHAR(255),
    artifact VARCHAR(255),
    version VARCHAR(64),
    advisory_id VARCHAR(64),
    severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM', -- CRITICAL | HIGH | MEDIUM | LOW
    description TEXT,
    remediation TEXT,
    raw_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(class);
CREATE INDEX IF NOT EXISTS idx_findings_advisory_id ON findings(advisory_id);
CREATE INDEX IF NOT EXISTS idx_findings_path ON findings(path);

-- 3. Workflow Templates: Catalog of visual scenarios (Multi-User & Multi-Tenant ready)
CREATE TABLE IF NOT EXISTS workflow_templates (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(64) NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    author VARCHAR(128) DEFAULT 'Anonymous',
    user_id VARCHAR(64) NOT NULL DEFAULT 'default_user',
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    is_builtin BOOLEAN NOT NULL DEFAULT FALSE,
    graph JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workflow_templates_category ON workflow_templates(category);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_is_builtin ON workflow_templates(is_builtin);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_user_id ON workflow_templates(user_id);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_is_public ON workflow_templates(is_public);

-- 4. Dual Reports: JSON & Markdown audit reports
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    run_id VARCHAR(64) REFERENCES workflow_runs(id) ON DELETE SET NULL,
    total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
    summary JSONB NOT NULL,
    json_content JSONB NOT NULL,
    markdown_content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_run_id ON reports(run_id);

-- 5. Vulnerability Database: Maven/OSV advisories cache
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id VARCHAR(64) PRIMARY KEY,
    aliases TEXT[] DEFAULT '{}',
    group_name VARCHAR(255) NOT NULL,
    artifact VARCHAR(255) NOT NULL,
    affected_ranges JSONB,
    fixed_versions TEXT[] DEFAULT '{}',
    severity VARCHAR(32),
    details TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_group_artifact ON vulnerabilities(group_name, artifact);

-- 6. Vault Secrets: Encrypted credentials (AES-256-GCM)
CREATE TABLE IF NOT EXISTS vault_secrets (
    key VARCHAR(128) PRIMARY KEY,
    encrypted_value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. User Accounts & Multi-Tenant Profiles (GitHub & GitVerse Integration)
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    github_id VARCHAR(64),
    github_username VARCHAR(128),
    github_token TEXT,
    gitverse_username VARCHAR(128),
    gitverse_token TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);

-- 8. User Auth Sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    token VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
