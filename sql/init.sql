```sql
-- =====================================================
-- Cyber Vulnerability Intelligence
-- PostgreSQL Database Schema
-- =====================================================

-- 1. Main vulnerability table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id VARCHAR(30) PRIMARY KEY,

    description TEXT,

    cvss_version VARCHAR(10),
    cvss_score NUMERIC(3, 1),
    severity VARCHAR(20),

    published_at TIMESTAMPTZ,
    last_modified_at TIMESTAMPTZ,

    affected_products JSONB DEFAULT '[]'::jsonb,

    reference_urls JSONB DEFAULT '[]'::jsonb,

    source_count INTEGER DEFAULT 0,
    sources JSONB DEFAULT '[]'::jsonb,

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. Individual source records
CREATE TABLE IF NOT EXISTS vulnerability_sources (
    id BIGSERIAL PRIMARY KEY,

    cve_id VARCHAR(30) NOT NULL
        REFERENCES vulnerabilities(cve_id)
        ON DELETE CASCADE,

    source_name VARCHAR(50) NOT NULL,
    source_record_id TEXT,

    source_published_at TIMESTAMPTZ,
    source_updated_at TIMESTAMPTZ,

    source_url TEXT,
    raw_data JSONB DEFAULT '{}'::jsonb,

    collected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (cve_id, source_name)
);

-- 3. Pipeline execution history
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id BIGSERIAL PRIMARY KEY,

    dag_id VARCHAR(250),
    run_id VARCHAR(250),

    source_name VARCHAR(50),
    status VARCHAR(30) NOT NULL,

    records_fetched INTEGER DEFAULT 0,
    records_inserted INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    records_rejected INTEGER DEFAULT 0,

    error_message TEXT,

    started_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ
);

-- 4. Data quality results
CREATE TABLE IF NOT EXISTS data_quality_checks (
    id BIGSERIAL PRIMARY KEY,

    cve_id VARCHAR(30),
    source_name VARCHAR(50),

    check_name VARCHAR(100) NOT NULL,
    passed BOOLEAN NOT NULL,

    details TEXT,

    checked_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- Indexes
-- =====================================================

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published
    ON vulnerabilities (published_at DESC);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss
    ON vulnerabilities (cvss_score DESC);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity
    ON vulnerabilities (severity);

CREATE INDEX IF NOT EXISTS idx_vulnerability_sources_source
    ON vulnerability_sources (source_name);

CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started
    ON pipeline_runs (started_at DESC);

CREATE INDEX IF NOT EXISTS idx_quality_checks_cve
    ON data_quality_checks (cve_id);

-- =====================================================
-- Dashboard-friendly view
-- =====================================================

CREATE OR REPLACE VIEW critical_vulnerabilities AS
SELECT
    cve_id,
    description,
    cvss_version,
    cvss_score,
    severity,
    published_at,
    last_modified_at,
    affected_products,
    reference_urls,
    source_count,
    sources,
    updated_at
FROM vulnerabilities
WHERE cvss_version IN ('3.0', '3.1')
  AND cvss_score >= 9.0
  AND published_at >= CURRENT_TIMESTAMP - INTERVAL '60 days';

-- =====================================================
-- Schema completed
-- =====================================================
```