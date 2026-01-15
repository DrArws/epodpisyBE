-- Migration: Add stamp_config column to workspaces table
-- Date: 2026-01-15
-- Description: Adds configurable verification stamp (doložka) settings per workspace

-- ============================================================================
-- Add stamp_config JSONB column
-- ============================================================================

ALTER TABLE workspaces
ADD COLUMN IF NOT EXISTS stamp_config JSONB DEFAULT '{}'::jsonb;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON COLUMN workspaces.stamp_config IS 'Verification stamp (doložka) configuration: position, size, colors, content settings';

-- ============================================================================
-- Example stamp_config values:
-- ============================================================================
-- Default (empty = use defaults):
-- {}
--
-- Custom position below signature with offset:
-- {
--   "position": "below_signature",
--   "offset_y": 10
-- }
--
-- Fixed position at bottom right:
-- {
--   "position": "bottom_right",
--   "width": 180,
--   "height": 60
-- }
--
-- Custom colors and content:
-- {
--   "position": "below_signature",
--   "border_color": "#003366",
--   "bg_color": "#f0f8ff",
--   "header_text": "DIGITÁLNĚ PODEPSÁNO",
--   "include_qr": true,
--   "show_warning": true
-- }
--
-- Full custom configuration:
-- {
--   "position": "fixed",
--   "page": "last",
--   "x": 350,
--   "y": 50,
--   "width": 200,
--   "height": 75,
--   "qr_size": 50,
--   "border_color": "#006633",
--   "bg_color": "#f5fff5",
--   "header_color": "#008040",
--   "text_color": "#333333",
--   "include_qr": true,
--   "header_text": "ELEKTRONICKY PODEPSANO",
--   "show_signer_name": true,
--   "show_date": true,
--   "show_verification_method": true,
--   "show_verification_id": true,
--   "show_warning": true,
--   "warning_text": "Zmena zneplatnuje podpis"
-- }
