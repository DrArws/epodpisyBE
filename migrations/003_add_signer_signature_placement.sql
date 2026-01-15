-- Migration: Add signature_placement column to document_signers table
-- Date: 2026-01-15
-- Description: Store signature placement per signer (set by frontend wizard/editor)

-- ============================================================================
-- Add signature_placement JSONB column to document_signers
-- ============================================================================

ALTER TABLE document_signers
ADD COLUMN IF NOT EXISTS signature_placement JSONB;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON COLUMN document_signers.signature_placement IS 'Signature placement from frontend: {page, x, y, w, h} in PDF points (pt)';

-- ============================================================================
-- Example signature_placement values:
-- ============================================================================
-- Frontend saves coordinates in PDF points (pt):
-- {
--   "page": 1,
--   "x": 350,       -- 350pt from left edge
--   "y": 700,       -- 700pt from top edge
--   "w": 180,       -- 180pt width
--   "h": 50         -- 50pt height
-- }
--
-- For A4 page: 595 x 842 points
-- Backend reads these values directly (no conversion needed)
