-- documents table RLS policies
-- Note: Full admin access is handled via admin-proxy Edge Function, not service_role

-- ============================================================================
-- Enable RLS
-- ============================================================================
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- Authenticated access (workspace members)
-- ============================================================================

-- Workspace members can read documents in their workspace
CREATE POLICY "Workspace members can read documents"
    ON documents
    FOR SELECT
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Workspace members can create documents in their workspace
CREATE POLICY "Workspace members can create documents"
    ON documents
    FOR INSERT
    TO authenticated
    WITH CHECK (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Workspace members can update documents in their workspace
CREATE POLICY "Workspace members can update documents"
    ON documents
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

-- Workspace members can delete documents in their workspace
CREATE POLICY "Workspace members can delete documents"
    ON documents
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
COMMENT ON TABLE documents IS 'Documents for e-signing with GCS storage paths';
COMMENT ON COLUMN documents.status IS 'Document status: draft, pending, sent, in_progress, completed, cancelled';
COMMENT ON COLUMN documents.gcs_original_path IS 'GCS path to original uploaded file';
COMMENT ON COLUMN documents.gcs_pdf_path IS 'GCS path to converted PDF';
COMMENT ON COLUMN documents.gcs_signed_path IS 'GCS path to signed PDF with all signatures';
COMMENT ON COLUMN documents.gcs_evidence_path IS 'GCS path to evidence/audit report';
