-- ============================================================================
-- Migration: Add idempotency and signing lock columns to signing_sessions
-- Purpose: Double-submit protection for signing endpoint
-- ============================================================================

-- Add columns for atomic signing lock
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS signing_started_at TIMESTAMPTZ;

-- Add columns for idempotency
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS idempotency_response JSONB;

-- Index for idempotency key lookup
CREATE INDEX IF NOT EXISTS idx_signing_sessions_idempotency_key
ON signing_sessions(idempotency_key)
WHERE idempotency_key IS NOT NULL;

-- Comments
COMMENT ON COLUMN signing_sessions.signing_started_at IS 'Timestamp when signing process started (for lock/race detection)';
COMMENT ON COLUMN signing_sessions.idempotency_key IS 'Client-provided idempotency key for replay protection';
COMMENT ON COLUMN signing_sessions.idempotency_response IS 'Cached response for idempotent replay';
