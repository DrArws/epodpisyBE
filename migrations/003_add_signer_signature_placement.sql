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

COMMENT ON COLUMN document_signers.signature_placement IS 'Signature placement from frontend: {page, x, y, width, height} in percentages (0-100)';

-- ============================================================================
-- Example signature_placement values:
-- ============================================================================
-- Frontend saves percentages (0-100 range):
-- {
--   "page": 1,
--   "x": 10.5,      -- 10.5% from left edge
--   "y": 80.0,      -- 80% from top edge
--   "width": 25.0,  -- 25% of page width
--   "height": 8.0   -- 8% of page height
-- }
--
-- Backend converts to PDF points using page dimensions:
-- For A4 (595 x 842 points):
--   x_points = 595 * 0.105 = 62.5
--   y_points = 842 * 0.80 = 673.6
--   width_points = 595 * 0.25 = 148.75
--   height_points = 842 * 0.08 = 67.36
