-- ============================================================================
-- document_events table
-- Audit trail for all document-related events
-- ============================================================================

-- Event type enum
DO $$ BEGIN
    CREATE TYPE event_type AS ENUM (
        'DOCUMENT_CREATED',
        'FILE_UPLOADED',
        'FILE_CONVERTED',
        'SIGNING_LINK_SENT',
        'DOCUMENT_VIEWED',
        'OTP_SENT',
        'OTP_OK',
        'OTP_FAIL',
        'SIGNED',
        'DECLINED',
        'FINALIZED',
        'EVIDENCE_GENERATED'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS document_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Foreign keys
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    signer_id UUID REFERENCES document_signers(id) ON DELETE SET NULL,

    -- Event data
    event_type event_type NOT NULL,

    -- Client info
    ip_address INET,
    user_agent TEXT,

    -- Additional metadata (JSON)
    metadata JSONB DEFAULT '{}',

    -- Timestamp (immutable - events are never updated)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_document_events_document_id ON document_events(document_id);
CREATE INDEX IF NOT EXISTS idx_document_events_workspace_id ON document_events(workspace_id);
CREATE INDEX IF NOT EXISTS idx_document_events_signer_id ON document_events(signer_id);
CREATE INDEX IF NOT EXISTS idx_document_events_event_type ON document_events(event_type);
CREATE INDEX IF NOT EXISTS idx_document_events_created_at ON document_events(created_at);

-- Composite index for common query patterns
CREATE INDEX IF NOT EXISTS idx_document_events_doc_workspace
    ON document_events(document_id, workspace_id, created_at);

-- RLS Policies
ALTER TABLE document_events ENABLE ROW LEVEL SECURITY;

-- Service role can do everything
CREATE POLICY "Service role full access on document_events"
    ON document_events
    FOR ALL
    TO service_role
    USING (TRUE)
    WITH CHECK (TRUE);

-- Anon can insert events (for signing flow)
CREATE POLICY "Anon can insert document_events"
    ON document_events
    FOR INSERT
    TO anon
    WITH CHECK (TRUE);

-- Workspace members can read events in their workspace
CREATE POLICY "Workspace members can read document_events"
    ON document_events
    FOR SELECT
    TO authenticated
    USING (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Workspace members can create events
CREATE POLICY "Workspace members can create document_events"
    ON document_events
    FOR INSERT
    TO authenticated
    WITH CHECK (
        workspace_id IN (
            SELECT workspace_id FROM workspace_members
            WHERE user_id = auth.uid()
        )
    );

-- Comments
COMMENT ON TABLE document_events IS 'Immutable audit trail for all document events';
COMMENT ON COLUMN document_events.event_type IS 'Type of event from event_type enum';
COMMENT ON COLUMN document_events.metadata IS 'Additional event-specific data in JSON format';
COMMENT ON COLUMN document_events.ip_address IS 'Client IP address at the time of event';
COMMENT ON COLUMN document_events.user_agent IS 'Client user agent string (truncated to 500 chars)';
