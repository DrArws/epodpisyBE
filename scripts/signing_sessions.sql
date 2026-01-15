-- ============================================================================
-- signing_sessions table
-- Stores signing session data for document signers (magic link tokens)
-- Note: Full admin access is handled via admin-proxy Edge Function, not service_role
-- ============================================================================

CREATE TABLE IF NOT EXISTS signing_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Foreign keys
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    signer_id UUID NOT NULL REFERENCES document_signers(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,

    -- Token authentication
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,

    -- Verification (public ID for verification endpoint)
    verification_id TEXT UNIQUE,  -- e.g., "VRF-ABC123"

    -- OTP verification
    otp_channel TEXT CHECK (otp_channel IN ('sms', 'whatsapp')),
    otp_verified_at TIMESTAMPTZ,
    otp_fallback_used BOOLEAN DEFAULT FALSE,

    -- Signing data
    signed_at TIMESTAMPTZ,
    signature_placement JSONB,  -- {page, x, y, w, h}
    final_hash TEXT,  -- SHA-256 of signed PDF (computed AFTER stamp added)

    -- Client info (captured on OTP verify/sign)
    ip_address INET,
    user_agent TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_signing_sessions_token_hash ON signing_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_signing_sessions_document_id ON signing_sessions(document_id);
CREATE INDEX IF NOT EXISTS idx_signing_sessions_signer_id ON signing_sessions(signer_id);
CREATE INDEX IF NOT EXISTS idx_signing_sessions_workspace_id ON signing_sessions(workspace_id);
CREATE INDEX IF NOT EXISTS idx_signing_sessions_expires_at ON signing_sessions(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_signing_sessions_verification_id ON signing_sessions(verification_id) WHERE verification_id IS NOT NULL;

-- RLS Policies
ALTER TABLE signing_sessions ENABLE ROW LEVEL SECURITY;

-- Anon can read sessions (for token validation and public verification)
CREATE POLICY "Anon can read signing_sessions"
    ON signing_sessions
    FOR SELECT
    TO anon
    USING (TRUE);

-- Anon can update sessions (for OTP verification and signing)
CREATE POLICY "Anon can update signing_sessions"
    ON signing_sessions
    FOR UPDATE
    TO anon
    USING (TRUE)
    WITH CHECK (TRUE);

-- Workspace members can read sessions in their workspace
CREATE POLICY "Workspace members can read signing_sessions"
    ON signing_sessions
    FOR SELECT
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Workspace members can create sessions
CREATE POLICY "Workspace members can create signing_sessions"
    ON signing_sessions
    FOR INSERT
    TO authenticated
    WITH CHECK (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Comments
COMMENT ON TABLE signing_sessions IS 'Signing sessions for document signers with magic link tokens';
COMMENT ON COLUMN signing_sessions.token_hash IS 'SHA-256 hash of the magic link token';
COMMENT ON COLUMN signing_sessions.verification_id IS 'Public verification ID (e.g., VRF-ABC123) for /verify endpoint';
COMMENT ON COLUMN signing_sessions.otp_channel IS 'Channel used for OTP: sms or whatsapp';
COMMENT ON COLUMN signing_sessions.otp_fallback_used IS 'Whether fallback to SMS was used when WhatsApp failed';
COMMENT ON COLUMN signing_sessions.signed_at IS 'Timestamp when document was signed';
COMMENT ON COLUMN signing_sessions.signature_placement IS 'JSON with signature position: {page, x, y, w, h}';
COMMENT ON COLUMN signing_sessions.final_hash IS 'SHA-256 hash of the signed PDF (computed after stamp added)';
