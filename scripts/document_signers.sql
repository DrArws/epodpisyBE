-- document_signers table RLS policies
-- Note: Full admin access is handled via admin-proxy Edge Function, not service_role

-- ============================================================================
-- Enable RLS
-- ============================================================================
ALTER TABLE document_signers ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- Public access (anon role)
-- ============================================================================

-- Anon can read signers (needed for /verify endpoint JOIN with signing_sessions)
-- This allows: SELECT "*, document_signers(name, email)" FROM signing_sessions
CREATE POLICY "Anon can read document_signers"
    ON document_signers
    FOR SELECT
    TO anon
    USING (TRUE);

-- ============================================================================
-- Authenticated access (workspace members)
-- ============================================================================

-- Workspace members can read signers in their workspace
CREATE POLICY "Workspace members can read document_signers"
    ON document_signers
    FOR SELECT
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Workspace members can create signers in their workspace
CREATE POLICY "Workspace members can create document_signers"
    ON document_signers
    FOR INSERT
    TO authenticated
    WITH CHECK (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Workspace members can update signers in their workspace
CREATE POLICY "Workspace members can update document_signers"
    ON document_signers
    FOR UPDATE
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    )
    WITH CHECK (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Workspace members can delete signers in their workspace
CREATE POLICY "Workspace members can delete document_signers"
    ON document_signers
    FOR DELETE
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON TABLE document_signers IS 'Signers assigned to documents for e-signing';
COMMENT ON COLUMN document_signers.status IS 'Signer status: pending, signed, declined';
