-- workspace_members table RLS policies
-- This is a critical table used by all other RLS policies to check workspace membership
-- Note: Full admin access is handled via admin-proxy Edge Function, not service_role

-- ============================================================================
-- Enable RLS
-- ============================================================================
ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- Authenticated access
-- ============================================================================

-- Users can read their own memberships (needed for auth flow and workspace selection)
CREATE POLICY "Users can read own memberships"
    ON workspace_members
    FOR SELECT
    TO authenticated
    USING (user_id = auth.uid());

-- Workspace admins/owners can read all members in their workspace
CREATE POLICY "Workspace admins can read all members"
    ON workspace_members
    FOR SELECT
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Workspace admins/owners can invite new members
CREATE POLICY "Workspace admins can invite members"
    ON workspace_members
    FOR INSERT
    TO authenticated
    WITH CHECK (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Workspace admins/owners can update member roles (but not their own)
CREATE POLICY "Workspace admins can update members"
    ON workspace_members
    FOR UPDATE
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
        AND user_id != auth.uid()  -- Cannot change own role
    )
    WITH CHECK (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
    );

-- Workspace admins/owners can remove members (but not themselves)
CREATE POLICY "Workspace admins can remove members"
    ON workspace_members
    FOR DELETE
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
            AND role IN ('owner', 'admin')
        )
        AND user_id != auth.uid()  -- Cannot remove self
    );

-- Users can leave workspace (delete own membership, except owners)
CREATE POLICY "Users can leave workspace"
    ON workspace_members
    FOR DELETE
    TO authenticated
    USING (
        user_id = auth.uid()
        AND role != 'owner'  -- Owners cannot leave, must transfer ownership first
    );

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON TABLE workspace_members IS 'Workspace membership with roles for multi-tenant access control';
COMMENT ON COLUMN workspace_members.role IS 'Member role: owner, admin, member';
COMMENT ON COLUMN workspace_members.user_id IS 'Reference to auth.users(id)';
