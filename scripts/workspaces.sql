-- workspaces table RLS policies
-- Note: Full admin access is handled via admin-proxy Edge Function, not service_role

-- ============================================================================
-- Enable RLS
-- ============================================================================
ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- Authenticated access (workspace members)
-- ============================================================================

-- Workspace members can read their workspace
CREATE POLICY "Workspace members can read workspaces"
    ON workspaces
    FOR SELECT
    TO authenticated
    USING (
        id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Only workspace admins/owners can update workspace settings
CREATE POLICY "Workspace admins can update workspaces"
    ON workspaces
    FOR UPDATE
    TO authenticated
    USING (
        id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    )
    WITH CHECK (
        id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Workspace creation is typically handled via admin-proxy or special signup flow
-- No INSERT policy for regular authenticated users

-- Only workspace owners can delete workspace
CREATE POLICY "Workspace owners can delete workspaces"
    ON workspaces
    FOR DELETE
    TO authenticated
    USING (
        id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
            AND role = 'owner'
        )
    );

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON TABLE workspaces IS 'Workspaces/organizations for multi-tenant e-signing';
COMMENT ON COLUMN workspaces.name IS 'Display name of the workspace';
