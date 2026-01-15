-- Email templates table
-- Run this in Supabase SQL Editor
-- Note: Full admin access is handled via admin-proxy Edge Function, not service_role

-- Create email_templates table
CREATE TABLE email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    template_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    html TEXT NOT NULL,
    text TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- One template per (workspace_id, template_type)
    UNIQUE (workspace_id, template_type)
);

-- Index for fast lookups
CREATE INDEX idx_email_templates_workspace_type ON email_templates(workspace_id, template_type);

-- RLS policies
ALTER TABLE email_templates ENABLE ROW LEVEL SECURITY;

-- Workspace members can read templates
CREATE POLICY "Workspace members can read templates"
ON email_templates FOR SELECT
USING (
    workspace_id IN (
        SELECT workspace_id FROM workspace_members
        WHERE user_id = auth.uid()
    )
);

-- Only admins/owners can insert/update/delete
CREATE POLICY "Workspace admins can manage templates"
ON email_templates FOR ALL
USING (
    workspace_id IN (
        SELECT workspace_id FROM workspace_members
        WHERE user_id = auth.uid()
        AND role IN ('admin', 'owner')
    )
);

-- Updated_at trigger
CREATE OR REPLACE FUNCTION update_email_templates_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER email_templates_updated_at
    BEFORE UPDATE ON email_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_email_templates_updated_at();
