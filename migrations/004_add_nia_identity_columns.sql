-- Migration: Add NIA (Národní identitní autorita) identity verification columns
-- Date: 2026-02-01
-- Description: Adds columns to support NIA SAML2/eIDAS identity verification
--              as an alternative to OTP (SMS/WhatsApp) verification.

-- ============================================================================
-- signing_sessions: NIA identity verification columns
-- ============================================================================

-- Identity method used for this session: 'otp' (default) or 'nia'
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS identity_method TEXT NOT NULL DEFAULT 'otp';

-- When identity was verified (NIA or OTP). Generalizes otp_verified_at.
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS identity_verified_at TIMESTAMPTZ;

-- SAML RelayState / CSRF token for NIA flow (random UUID, single-use)
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS nia_state TEXT;

-- NIA subject identifier (NameID / SePP - unique per SeP)
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS nia_subject TEXT;

-- Level of Assurance from NIA assertion
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS nia_loa TEXT;

-- Full NIA SAML attributes (claims) as JSONB
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS nia_attributes JSONB;

-- AuthnInstant from NIA SAML assertion
ALTER TABLE signing_sessions
ADD COLUMN IF NOT EXISTS nia_authn_instant TIMESTAMPTZ;

-- ============================================================================
-- document_signers: Optional NIA identity transfer on signing completion
-- ============================================================================

-- NIA subject (SePP) transferred from session after successful signing
ALTER TABLE document_signers
ADD COLUMN IF NOT EXISTS nia_subject TEXT;

-- When NIA identity was verified for this signer
ALTER TABLE document_signers
ADD COLUMN IF NOT EXISTS nia_verified_at TIMESTAMPTZ;

-- ============================================================================
-- Constraints
-- ============================================================================

-- Ensure identity_method is one of the allowed values
-- Using a DO block to make it idempotent
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'signing_sessions_identity_method_chk'
    ) THEN
        ALTER TABLE signing_sessions
        ADD CONSTRAINT signing_sessions_identity_method_chk
        CHECK (identity_method IN ('otp', 'nia'));
    END IF;
END$$;

-- ============================================================================
-- Indexes
-- ============================================================================

-- Index for NIA state lookup (used in ACS callback)
CREATE INDEX IF NOT EXISTS idx_signing_sessions_nia_state
ON signing_sessions (nia_state)
WHERE nia_state IS NOT NULL;

-- Index for NIA subject lookup (optional, for identity reuse queries)
CREATE INDEX IF NOT EXISTS idx_signing_sessions_nia_subject
ON signing_sessions (nia_subject)
WHERE nia_subject IS NOT NULL;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON COLUMN signing_sessions.identity_method IS 'Identity verification method: otp (SMS/WhatsApp) or nia (NIA SAML2/eIDAS)';
COMMENT ON COLUMN signing_sessions.identity_verified_at IS 'When identity was verified via the chosen method';
COMMENT ON COLUMN signing_sessions.nia_state IS 'SAML RelayState / CSRF token for NIA flow (single-use UUID)';
COMMENT ON COLUMN signing_sessions.nia_subject IS 'NIA subject identifier (NameID / SePP pseudonym)';
COMMENT ON COLUMN signing_sessions.nia_loa IS 'Level of Assurance from NIA SAML assertion';
COMMENT ON COLUMN signing_sessions.nia_attributes IS 'NIA SAML attributes (claims) as JSONB';
COMMENT ON COLUMN signing_sessions.nia_authn_instant IS 'Authentication instant from NIA SAML assertion';
COMMENT ON COLUMN document_signers.nia_subject IS 'NIA subject (SePP) transferred from session after signing';
COMMENT ON COLUMN document_signers.nia_verified_at IS 'When NIA identity was verified for this signer';
