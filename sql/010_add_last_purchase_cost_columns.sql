-- ============================================================================
-- Migration: Add Last Purchase Cost Columns to stock_movement_summary
-- ============================================================================
-- Purpose: Track actual last purchased cost from receipt transactions
--          for accurate PO generation instead of weighted average
-- ============================================================================

-- Add columns for last purchase cost tracking
ALTER TABLE wms.stock_movement_summary
ADD COLUMN IF NOT EXISTS last_purchase_cost NUMERIC(19,4),
ADD COLUMN IF NOT EXISTS last_purchase_date DATE,
ADD COLUMN IF NOT EXISTS last_purchase_doc VARCHAR(50);

-- Add index for querying items with/without last purchase cost
CREATE INDEX IF NOT EXISTS idx_sms_last_purchase_cost
ON wms.stock_movement_summary (last_purchase_cost)
WHERE last_purchase_cost IS NOT NULL;

-- ============================================================================
-- Initial Population: Derive last_purchase_cost from supplier invoice history
-- ============================================================================
-- Run this once after adding columns to populate historical data
-- The L2 sync will handle real-time updates going forward

WITH last_purchase AS (
    SELECT DISTINCT ON (d."AcStockID", d."AcStockUOMID")
        d."AcStockID" as stock_id,
        d."AcStockUOMID" as uom_id,
        d."ItemUnitPrice" as last_cost,
        m."DocumentDate" as last_date,
        m."AcSupInvoiceMID" as last_doc
    FROM "AcSupInvoiceD" d
    JOIN "AcSupInvoiceM" m ON d."AcSupInvoiceMID" = m."AcSupInvoiceMID"
    WHERE d."ItemUnitPrice" > 0
    ORDER BY d."AcStockID", d."AcStockUOMID", m."DocumentDate" DESC
)
UPDATE wms.stock_movement_summary sms
SET
    last_purchase_cost = lp.last_cost,
    last_purchase_date = lp.last_date,
    last_purchase_doc = lp.last_doc
FROM last_purchase lp
WHERE sms.stock_id = lp.stock_id
  AND sms.order_uom = lp.uom_id;

-- ============================================================================
-- Update unit_cost with Fallback Chain
-- ============================================================================
-- Cost Priority:
--   1. last_purchase_cost (from AcStockReceiveD) - PRIMARY: Actual price paid
--   2. StockReferenceCost (manually maintained)  - SECONDARY: Reference price
--   3. StockCost (weighted average)              - LAST RESORT: Fallback

UPDATE wms.stock_movement_summary sms
SET unit_cost = COALESCE(
    sms.last_purchase_cost,                    -- 1. Last purchase cost (PRIMARY)
    (SELECT sc."StockReferenceCost"
     FROM "AcStockCompany" sc
     WHERE sc."AcStockID" = sms.stock_id
       AND sc."AcStockUOMID" = sms.order_uom
       AND sc."StockReferenceCost" > 0
     LIMIT 1),                                  -- 2. Reference cost (SECONDARY)
    sms.unit_cost                              -- 3. Weighted average (LAST RESORT)
)
WHERE sms.is_active = true;

-- ============================================================================
-- Comments
-- ============================================================================
COMMENT ON COLUMN wms.stock_movement_summary.last_purchase_cost IS 'Last actual purchase price from AcSupInvoiceD (PRIMARY cost source for PO)';
COMMENT ON COLUMN wms.stock_movement_summary.last_purchase_date IS 'Date of last supplier invoice';
COMMENT ON COLUMN wms.stock_movement_summary.last_purchase_doc IS 'Document ID of last supplier invoice';

-- ============================================================================
-- Verification Queries
-- ============================================================================
-- Run these after migration to verify data:

-- 1. Check sync is working:
-- SELECT COUNT(*), MAX("DocumentDate") FROM "AcStockReceiveM";
-- SELECT COUNT(*), MAX("DocumentDate") FROM "AcStockReceiveD";

-- 2. Check last_purchase_cost coverage:
-- SELECT
--     COUNT(*) as total,
--     COUNT(last_purchase_cost) as has_last_cost,
--     COUNT(CASE WHEN unit_cost = last_purchase_cost THEN 1 END) as using_last_cost
-- FROM wms.stock_movement_summary
-- WHERE current_balance > 0;

-- 3. Compare inventory values:
-- SELECT
--     SUM(current_balance * unit_cost) as old_value,
--     SUM(current_balance * COALESCE(last_purchase_cost, unit_cost)) as new_value
-- FROM wms.stock_movement_summary
-- WHERE current_balance > 0;
