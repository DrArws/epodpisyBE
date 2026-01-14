-- Migration: Add missing columns to signing_sessions table
-- Date: 2026-01-10
-- Description: Adds verification_id, final_hash, OTP rate limiting, and invalidation columns

-- ============================================================================
-- P0-5: Add verification_id and final_hash columns
-- ============================================================================

-- verification_id: Public ID shown on signature stamp and used for verification
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS verification_id TEXT UNIQUE;

-- final_hash: SHA-256 hash of the signed PDF (computed AFTER stamp is added)
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS final_hash TEXT;

-- signed_at: When the document was signed (may already exist)
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS signed_at TIMESTAMPTZ;

-- ============================================================================
-- P0-2: Add invalidation column for session revocation
-- ============================================================================

-- invalidated_at: Set when session is revoked (e.g., when re-sending links)
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS invalidated_at TIMESTAMPTZ;

-- ============================================================================
-- P1-6: Add OTP rate limiting columns
-- ============================================================================

-- OTP send rate limiting
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS otp_sent_count INTEGER DEFAULT 0;

ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS otp_last_sent_at TIMESTAMPTZ;

-- OTP verification attempt limiting
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS otp_verify_attempts INTEGER DEFAULT 0;

-- Lock session after too many failed attempts
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS otp_locked_until TIMESTAMPTZ;

-- ============================================================================
-- Indexes for performance
-- ============================================================================

-- Index for verification lookups
CREATE INDEX IF NOT EXISTS idx_signing_sessions_verification_id
ON signing_sessions (verification_id)
WHERE verification_id IS NOT NULL;

-- Index for finding active sessions
CREATE INDEX IF NOT EXISTS idx_signing_sessions_expires_at
ON signing_sessions (expires_at)
WHERE invalidated_at IS NULL;

-- Index for document sessions lookup
CREATE INDEX IF NOT EXISTS idx_signing_sessions_document_id
ON signing_sessions (document_id);

-- ============================================================================
-- Comments for documentation
-- ============================================================================

COMMENT ON COLUMN signing_sessions.verification_id IS 'Public verification ID shown on signature stamp';
COMMENT ON COLUMN signing_sessions.final_hash IS 'SHA-256 hash of signed PDF, computed after stamp is added';
COMMENT ON COLUMN signing_sessions.invalidated_at IS 'When session was revoked (e.g., link re-sent)';
COMMENT ON COLUMN signing_sessions.otp_sent_count IS 'Number of OTP codes sent in current window';
COMMENT ON COLUMN signing_sessions.otp_last_sent_at IS 'Timestamp of last OTP send';
COMMENT ON COLUMN signing_sessions.otp_verify_attempts IS 'Failed OTP verification attempts';
COMMENT ON COLUMN signing_sessions.otp_locked_until IS 'Session locked until this time after too many failed attempts';
