-- Migration: Add QuickBooks OAuth tokens storage
-- Run this against your PostgreSQL database

-- QuickBooks OAuth tokens table
CREATE TABLE IF NOT EXISTS qb_tokens (
    id SERIAL PRIMARY KEY,
    realm_id VARCHAR(50) NOT NULL UNIQUE,  -- QuickBooks company ID
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_at TIMESTAMP NOT NULL,
    refresh_token_expires_at TIMESTAMP,
    company_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- QuickBooks sync log (track what's been synced)
CREATE TABLE IF NOT EXISTS qb_sync_log (
    id SERIAL PRIMARY KEY,
    realm_id VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,  -- estimate, invoice, customer
    qb_id VARCHAR(100) NOT NULL,        -- ID in QuickBooks
    local_id INTEGER,                    -- ID in our system (job_id, etc)
    sync_direction VARCHAR(20) DEFAULT 'import',  -- import, export
    status VARCHAR(50) DEFAULT 'success',
    error_message TEXT,
    synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(realm_id, entity_type, qb_id)
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_qb_tokens_realm_id ON qb_tokens(realm_id);
CREATE INDEX IF NOT EXISTS idx_qb_sync_log_realm ON qb_sync_log(realm_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_qb_sync_log_qb_id ON qb_sync_log(qb_id);

COMMENT ON TABLE qb_tokens IS 'Stores QuickBooks OAuth tokens for API access';
COMMENT ON TABLE qb_sync_log IS 'Tracks synced entities between QuickBooks and Foreman';
