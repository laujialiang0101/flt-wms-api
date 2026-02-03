-- ============================================================================
-- WMS Stock Movement Summary Table
-- ============================================================================
-- Purpose: Real-time stock movement tracking with ABC-XYZ auto-classification
-- Location: Cloud PostgreSQL only (not synced to Dynamod)
-- Update: Refreshed by sync service or API on demand
-- ============================================================================

-- Create WMS schema if not exists
CREATE SCHEMA IF NOT EXISTS wms;

-- Drop existing table if exists (for development)
-- DROP TABLE IF EXISTS wms.stock_movement_summary;

CREATE TABLE IF NOT EXISTS wms.stock_movement_summary (
    -- Primary Key
    stock_id VARCHAR(50) NOT NULL,

    -- ========================================================================
    -- PRODUCT MASTER DATA (from AcStockCompany)
    -- ========================================================================
    stock_name VARCHAR(200),
    barcode VARCHAR(50),
    category VARCHAR(100),
    brand VARCHAR(100),

    -- UD1 = Stock Type (FLT codes + status)
    -- Values: FLTHB, FLTF1, FLTF2, FLTF3, FLTMH, FLTSC,
    --         SPECIAL REQUEST, SLOW MOVER, DISCONTINUED, NEW LIST-IN, NA
    ud1_code VARCHAR(50),

    -- Therapeutic grouping (from AcStockColorID)
    -- Example: "VITAMIN C", "PARACETAMOL", "OMEGA 3"
    therapeutic_group VARCHAR(100),

    -- Active ingredient (from StockDescription2)
    active_ingredient TEXT,

    -- ========================================================================
    -- MOVEMENT METRICS (Rolling Windows)
    -- ========================================================================
    -- Quantity sold in each period
    qty_last_7d NUMERIC DEFAULT 0,
    qty_last_14d NUMERIC DEFAULT 0,
    qty_last_30d NUMERIC DEFAULT 0,
    qty_last_90d NUMERIC DEFAULT 0,
    qty_last_365d NUMERIC DEFAULT 0,

    -- Daily averages (for trend comparison)
    avg_daily_7d NUMERIC DEFAULT 0,
    avg_daily_14d NUMERIC DEFAULT 0,
    avg_daily_30d NUMERIC DEFAULT 0,
    avg_daily_90d NUMERIC DEFAULT 0,

    -- Active selling days (days with at least 1 sale)
    selling_days_30d INTEGER DEFAULT 0,
    selling_days_90d INTEGER DEFAULT 0,

    -- ========================================================================
    -- TREND DETECTION
    -- ========================================================================
    -- % change: 7-day avg vs 30-day avg
    -- Positive = accelerating, Negative = decelerating
    trend_7d_vs_30d NUMERIC,

    -- Trend status for quick filtering
    -- SPIKE_UP (>50%), ACCELERATING (>20%), STABLE, DECELERATING (<-20%), SPIKE_DOWN (<-50%), DEAD (no sales)
    trend_status VARCHAR(20) DEFAULT 'UNKNOWN',

    -- ========================================================================
    -- ABC-XYZ CLASSIFICATION
    -- ========================================================================
    -- ABC: Revenue contribution (Pareto)
    -- A = Top 80% revenue, B = Next 15%, C = Bottom 5%
    abc_class CHAR(1),

    -- XYZ: Demand variability (Coefficient of Variation)
    -- X = CV < 0.5 (stable), Y = CV 0.5-1.0 (moderate), Z = CV > 1.0 (erratic)
    xyz_class CHAR(1),
    cv_value NUMERIC,  -- Actual CV for reference

    -- Combined classification
    abc_xyz_class VARCHAR(2),

    -- ========================================================================
    -- PRODUCT HEALTH SCORE (Multi-Factor, 0-100)
    -- ========================================================================
    -- Weighted: 25% profitability, 20% volume, 20% revenue, 15% stability, 10% DOI, 10% strategic
    health_score NUMERIC,

    -- Component scores (each 0-100)
    profitability_score NUMERIC,  -- Based on GP margin
    volume_score NUMERIC,         -- Based on qty vs max
    revenue_score NUMERIC,        -- Based on revenue contribution
    stability_score NUMERIC,      -- Inverse of CV
    doi_score NUMERIC,            -- Days of inventory (lower is better)
    strategic_score NUMERIC,      -- FLTHB/FLTF1 = 100, FLTMH = 80, others = 50

    -- ========================================================================
    -- REVENUE & PROFITABILITY
    -- ========================================================================
    revenue_last_30d NUMERIC DEFAULT 0,
    revenue_last_90d NUMERIC DEFAULT 0,
    revenue_last_365d NUMERIC DEFAULT 0,

    gp_last_30d NUMERIC DEFAULT 0,
    gp_last_90d NUMERIC DEFAULT 0,
    gp_last_365d NUMERIC DEFAULT 0,

    gp_margin_pct NUMERIC,  -- Gross profit margin %

    -- Cost (for inventory valuation)
    unit_cost NUMERIC,

    -- Last purchase cost (from receipt history - PRIMARY cost source for PO)
    last_purchase_cost NUMERIC(19,4),
    last_purchase_date DATE,
    last_purchase_doc VARCHAR(50),

    -- ========================================================================
    -- UOM INFORMATION (for purchasing)
    -- ========================================================================
    base_uom VARCHAR(20),              -- Base UOM (e.g., PCKT, PCS, BOT)
    order_uom VARCHAR(20),             -- Ordering UOM - largest available (e.g., BOX)
    order_uom_rate NUMERIC DEFAULT 1,  -- How many base units per order unit
    balance_in_order_uom NUMERIC,      -- Balance converted to order UOM

    -- ========================================================================
    -- INVENTORY STATUS
    -- ========================================================================
    current_balance NUMERIC DEFAULT 0,  -- Balance in BASE UOM
    inventory_value NUMERIC DEFAULT 0,

    -- Days of inventory = balance / avg_daily_30d
    days_of_inventory NUMERIC,

    -- Stockout risk based on days_of_inventory
    -- CRITICAL (<7 days), WARNING (<14 days), OK (<45 days), OVERSTOCKED (>90 days)
    stockout_risk VARCHAR(20) DEFAULT 'UNKNOWN',

    -- Reorder point suggestion = avg_daily_30d * lead_time_days * safety_factor
    suggested_reorder_point NUMERIC,
    suggested_reorder_qty NUMERIC,

    -- ========================================================================
    -- GENERIC ALTERNATIVES (for margin optimization)
    -- ========================================================================
    -- Does a house brand alternative exist in same therapeutic group?
    has_house_brand_alt BOOLEAN DEFAULT FALSE,

    -- ========================================================================
    -- TIMESTAMPS
    -- ========================================================================
    last_sale_date DATE,
    first_sale_date DATE,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- ========================================================================
    -- CONSTRAINTS
    -- ========================================================================
    PRIMARY KEY (stock_id)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- For filtering by classification
CREATE INDEX IF NOT EXISTS idx_sms_ud1 ON wms.stock_movement_summary (ud1_code);
CREATE INDEX IF NOT EXISTS idx_sms_abc_xyz ON wms.stock_movement_summary (abc_xyz_class);
CREATE INDEX IF NOT EXISTS idx_sms_abc ON wms.stock_movement_summary (abc_class);

-- For trend monitoring
CREATE INDEX IF NOT EXISTS idx_sms_trend ON wms.stock_movement_summary (trend_status);
CREATE INDEX IF NOT EXISTS idx_sms_stockout ON wms.stock_movement_summary (stockout_risk);

-- For therapeutic grouping (generic alternatives)
CREATE INDEX IF NOT EXISTS idx_sms_therapeutic ON wms.stock_movement_summary (therapeutic_group);

-- For health score ranking
CREATE INDEX IF NOT EXISTS idx_sms_health ON wms.stock_movement_summary (health_score DESC NULLS LAST);

-- For margin opportunity (column dropped - index kept for backwards compat)
-- CREATE INDEX IF NOT EXISTS idx_sms_margin_opp ON wms.stock_movement_summary (margin_opportunity_monthly DESC NULLS LAST)
--     WHERE margin_opportunity_monthly > 0;

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE wms.stock_movement_summary IS 'Real-time stock movement tracking with ABC-XYZ classification. Updated by sync service.';

COMMENT ON COLUMN wms.stock_movement_summary.ud1_code IS 'Stock Type from Dynamod (FLTHB, FLTF1-3, FLTMH, FLTSC, SPECIAL REQUEST, SLOW MOVER, etc.)';
-- ud2_suggested column dropped (was never populated)
COMMENT ON COLUMN wms.stock_movement_summary.trend_status IS 'SPIKE_UP (>50%), ACCELERATING (>20%), STABLE, DECELERATING (<-20%), SPIKE_DOWN (<-50%), DEAD';
COMMENT ON COLUMN wms.stock_movement_summary.health_score IS 'Multi-factor product health score 0-100 (higher = healthier)';
COMMENT ON COLUMN wms.stock_movement_summary.margin_opportunity_monthly IS 'Potential monthly GP gain if switched to house brand alternative';
