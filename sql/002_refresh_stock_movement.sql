-- ============================================================================
-- Refresh Stock Movement Summary
-- ============================================================================
-- Run this periodically (recommended: every 60 seconds with sync service)
-- or on-demand via API
-- ============================================================================

-- Truncate and reload (full refresh for simplicity)
-- For production, consider incremental updates for better performance

TRUNCATE TABLE wms.stock_movement_summary;

INSERT INTO wms.stock_movement_summary (
    stock_id,
    stock_name,
    barcode,
    category,
    brand,
    ud1_code,
    therapeutic_group,
    active_ingredient,
    unit_cost,

    -- Movement metrics
    qty_last_7d,
    qty_last_14d,
    qty_last_30d,
    qty_last_90d,
    qty_last_365d,
    avg_daily_7d,
    avg_daily_14d,
    avg_daily_30d,
    avg_daily_90d,
    selling_days_30d,
    selling_days_90d,

    -- Trend
    trend_7d_vs_30d,
    trend_status,

    -- ABC-XYZ
    abc_class,
    xyz_class,
    cv_value,
    abc_xyz_class,

    -- Scores
    health_score,
    profitability_score,
    volume_score,
    revenue_score,
    stability_score,
    doi_score,
    strategic_score,

    -- Revenue
    revenue_last_30d,
    revenue_last_90d,
    revenue_last_365d,
    gp_last_30d,
    gp_last_90d,
    gp_last_365d,
    gp_margin_pct,

    -- Inventory
    current_balance,
    inventory_value,
    days_of_inventory,
    stockout_risk,
    suggested_reorder_point,
    suggested_reorder_qty,

    -- Dates
    last_sale_date,
    first_sale_date,
    last_updated
)
WITH
-- ========================================================================
-- Sales data by period
-- ========================================================================
sales_7d AS (
    SELECT d."AcStockID" as stock_id,
           SUM(d."ItemQuantity") as qty,
           SUM(d."ItemTotal") as revenue,
           SUM(d."ItemTotal" - d."ItemQuantity" * d."ItemCost") as gp
    FROM "AcCSD" d
    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
    WHERE m."DocumentDate" >= CURRENT_DATE - 7
    GROUP BY d."AcStockID"
),
sales_14d AS (
    SELECT d."AcStockID" as stock_id,
           SUM(d."ItemQuantity") as qty,
           SUM(d."ItemTotal") as revenue
    FROM "AcCSD" d
    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
    WHERE m."DocumentDate" >= CURRENT_DATE - 14
    GROUP BY d."AcStockID"
),
sales_30d AS (
    SELECT d."AcStockID" as stock_id,
           SUM(d."ItemQuantity") as qty,
           SUM(d."ItemTotal") as revenue,
           SUM(d."ItemTotal" - d."ItemQuantity" * d."ItemCost") as gp,
           COUNT(DISTINCT m."DocumentDate"::date) as selling_days
    FROM "AcCSD" d
    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
    WHERE m."DocumentDate" >= CURRENT_DATE - 30
    GROUP BY d."AcStockID"
),
sales_90d AS (
    SELECT d."AcStockID" as stock_id,
           SUM(d."ItemQuantity") as qty,
           SUM(d."ItemTotal") as revenue,
           SUM(d."ItemTotal" - d."ItemQuantity" * d."ItemCost") as gp,
           COUNT(DISTINCT m."DocumentDate"::date) as selling_days
    FROM "AcCSD" d
    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
    WHERE m."DocumentDate" >= CURRENT_DATE - 90
    GROUP BY d."AcStockID"
),
sales_365d AS (
    SELECT d."AcStockID" as stock_id,
           SUM(d."ItemQuantity") as qty,
           SUM(d."ItemTotal") as revenue,
           SUM(d."ItemTotal" - d."ItemQuantity" * d."ItemCost") as gp,
           MIN(m."DocumentDate"::date) as first_sale,
           MAX(m."DocumentDate"::date) as last_sale
    FROM "AcCSD" d
    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
    WHERE m."DocumentDate" >= CURRENT_DATE - 365
    GROUP BY d."AcStockID"
),

-- ========================================================================
-- Monthly sales for CV calculation
-- ========================================================================
monthly_sales AS (
    SELECT d."AcStockID" as stock_id,
           DATE_TRUNC('month', m."DocumentDate")::date as month,
           SUM(d."ItemQuantity") as monthly_qty
    FROM "AcCSD" d
    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
    WHERE m."DocumentDate" >= CURRENT_DATE - 365
    GROUP BY d."AcStockID", DATE_TRUNC('month', m."DocumentDate")
),
cv_calc AS (
    SELECT stock_id,
           AVG(monthly_qty) as avg_monthly,
           STDDEV(monthly_qty) as stddev_monthly,
           CASE WHEN AVG(monthly_qty) > 0 THEN STDDEV(monthly_qty) / AVG(monthly_qty) ELSE NULL END as cv
    FROM monthly_sales
    GROUP BY stock_id
    HAVING COUNT(*) >= 3  -- Need at least 3 months for CV
),

-- ========================================================================
-- Stock balance
-- ========================================================================
stock_balance AS (
    SELECT "AcStockID" as stock_id,
           SUM("BalanceQuantity") as balance
    FROM "AcStockBalanceLocation"
    GROUP BY "AcStockID"
),

-- ========================================================================
-- ABC classification (revenue-based Pareto)
-- ========================================================================
revenue_ranked AS (
    SELECT stock_id,
           revenue,
           SUM(revenue) OVER () as total_revenue,
           SUM(revenue) OVER (ORDER BY revenue DESC) as cumulative_revenue
    FROM sales_365d
    WHERE revenue > 0
),
abc_class AS (
    SELECT stock_id,
           CASE
               WHEN cumulative_revenue / NULLIF(total_revenue, 0) <= 0.80 THEN 'A'
               WHEN cumulative_revenue / NULLIF(total_revenue, 0) <= 0.95 THEN 'B'
               ELSE 'C'
           END as abc
    FROM revenue_ranked
),

-- ========================================================================
-- Max values for normalization
-- ========================================================================
max_vals AS (
    SELECT
        MAX(s365.qty) as max_qty,
        MAX(s365.revenue) as max_revenue
    FROM sales_365d s365
),

-- ========================================================================
-- House brand alternatives (same therapeutic group)
-- ========================================================================
house_brands AS (
    SELECT sc."AcStockColorID" as therapeutic_group,
           sc."AcStockID" as stock_id,
           sc."StockDescription1" as stock_name,
           CASE WHEN s365.revenue > 0 THEN (s365.gp / s365.revenue * 100) ELSE 0 END as gp_margin
    FROM "AcStockCompany" sc
    LEFT JOIN sales_365d s365 ON sc."AcStockID" = s365.stock_id
    WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
      AND sc."StockIsActive" = 'Y'
      AND sc."AcStockUDGroup1ID" = 'FLTHB'
)

-- ========================================================================
-- Main query
-- ========================================================================
SELECT
    sc."AcStockID" as stock_id,
    sc."StockDescription1" as stock_name,
    sc."StockBarcode" as barcode,
    cat."AcStockCategoryDesc" as category,
    brand."AcStockBrandDesc" as brand,
    sc."AcStockUDGroup1ID" as ud1_code,
    sc."AcStockColorID" as therapeutic_group,
    sc."StockDescription2" as active_ingredient,
    sc."StockCost" as unit_cost,

    -- Movement metrics
    COALESCE(s7.qty, 0) as qty_last_7d,
    COALESCE(s14.qty, 0) as qty_last_14d,
    COALESCE(s30.qty, 0) as qty_last_30d,
    COALESCE(s90.qty, 0) as qty_last_90d,
    COALESCE(s365.qty, 0) as qty_last_365d,

    ROUND(COALESCE(s7.qty, 0) / 7.0, 2) as avg_daily_7d,
    ROUND(COALESCE(s14.qty, 0) / 14.0, 2) as avg_daily_14d,
    ROUND(COALESCE(s30.qty, 0) / 30.0, 2) as avg_daily_30d,
    ROUND(COALESCE(s90.qty, 0) / 90.0, 2) as avg_daily_90d,

    COALESCE(s30.selling_days, 0) as selling_days_30d,
    COALESCE(s90.selling_days, 0) as selling_days_90d,

    -- Trend calculation
    CASE
        WHEN COALESCE(s30.qty, 0) > 0 THEN
            ROUND(((COALESCE(s7.qty, 0) / 7.0) - (COALESCE(s30.qty, 0) / 30.0)) / (COALESCE(s30.qty, 0) / 30.0) * 100, 1)
        ELSE NULL
    END as trend_7d_vs_30d,

    CASE
        WHEN COALESCE(s30.qty, 0) = 0 AND COALESCE(s90.qty, 0) = 0 THEN 'DEAD'
        WHEN COALESCE(s7.qty, 0) / 7.0 > COALESCE(s30.qty, 0) / 30.0 * 1.5 THEN 'SPIKE_UP'
        WHEN COALESCE(s7.qty, 0) / 7.0 > COALESCE(s30.qty, 0) / 30.0 * 1.2 THEN 'ACCELERATING'
        WHEN COALESCE(s7.qty, 0) / 7.0 < COALESCE(s30.qty, 0) / 30.0 * 0.5 THEN 'SPIKE_DOWN'
        WHEN COALESCE(s7.qty, 0) / 7.0 < COALESCE(s30.qty, 0) / 30.0 * 0.8 THEN 'DECELERATING'
        ELSE 'STABLE'
    END as trend_status,

    -- ABC-XYZ
    abc.abc as abc_class,
    CASE
        WHEN cv.cv < 0.5 THEN 'X'
        WHEN cv.cv <= 1.0 THEN 'Y'
        ELSE 'Z'
    END as xyz_class,
    ROUND(cv.cv::numeric, 2) as cv_value,
    CONCAT(abc.abc, CASE WHEN cv.cv < 0.5 THEN 'X' WHEN cv.cv <= 1.0 THEN 'Y' ELSE 'Z' END) as abc_xyz_class,

    -- Health Score components
    -- Profitability (25%): GP margin / 60 * 100, max 100
    ROUND(LEAST(CASE WHEN COALESCE(s365.revenue, 0) > 0 THEN COALESCE(s365.gp, 0) / s365.revenue * 100 / 60 * 100 ELSE 0 END, 100), 1) as profitability_score,
    -- Volume (20%): qty / max_qty * 100
    ROUND(COALESCE(s365.qty, 0) / NULLIF(mv.max_qty, 0) * 100, 1) as volume_score,
    -- Revenue (20%): revenue / max_revenue * 100
    ROUND(COALESCE(s365.revenue, 0) / NULLIF(mv.max_revenue, 0) * 100, 1) as revenue_score,
    -- Stability (15%): (1 - CV) * 100, max 100
    ROUND(LEAST((1 - COALESCE(cv.cv, 1)) * 100, 100), 1) as stability_score,
    -- DOI (10%): 100 - (days_of_inventory / 90 * 100), min 0
    ROUND(GREATEST(100 - COALESCE(sb.balance, 0) / NULLIF(COALESCE(s30.qty, 0) / 30.0, 0) / 90 * 100, 0), 1) as doi_score,
    -- Strategic (10%): FLTHB/FLTF1=100, FLTMH=80, FLTF2=70, FLTF3=60, others=50
    CASE
        WHEN sc."AcStockUDGroup1ID" IN ('FLTHB', 'FLTF1') THEN 100
        WHEN sc."AcStockUDGroup1ID" = 'FLTMH' THEN 80
        WHEN sc."AcStockUDGroup1ID" = 'FLTF2' THEN 70
        WHEN sc."AcStockUDGroup1ID" = 'FLTF3' THEN 60
        ELSE 50
    END as strategic_score,

    -- Combined health score
    ROUND((
        0.25 * LEAST(CASE WHEN COALESCE(s365.revenue, 0) > 0 THEN COALESCE(s365.gp, 0) / s365.revenue * 100 / 60 * 100 ELSE 0 END, 100) +
        0.20 * COALESCE(s365.qty, 0) / NULLIF(mv.max_qty, 0) * 100 +
        0.20 * COALESCE(s365.revenue, 0) / NULLIF(mv.max_revenue, 0) * 100 +
        0.15 * LEAST((1 - COALESCE(cv.cv, 1)) * 100, 100) +
        0.10 * GREATEST(100 - COALESCE(sb.balance, 0) / NULLIF(COALESCE(s30.qty, 0) / 30.0, 0) / 90 * 100, 0) +
        0.10 * CASE WHEN sc."AcStockUDGroup1ID" IN ('FLTHB', 'FLTF1') THEN 100 WHEN sc."AcStockUDGroup1ID" = 'FLTMH' THEN 80 WHEN sc."AcStockUDGroup1ID" = 'FLTF2' THEN 70 WHEN sc."AcStockUDGroup1ID" = 'FLTF3' THEN 60 ELSE 50 END
    )::numeric, 1) as health_score,

    -- Revenue & GP
    ROUND(COALESCE(s30.revenue, 0)::numeric, 2) as revenue_last_30d,
    ROUND(COALESCE(s90.revenue, 0)::numeric, 2) as revenue_last_90d,
    ROUND(COALESCE(s365.revenue, 0)::numeric, 2) as revenue_last_365d,
    ROUND(COALESCE(s30.gp, 0)::numeric, 2) as gp_last_30d,
    ROUND(COALESCE(s90.gp, 0)::numeric, 2) as gp_last_90d,
    ROUND(COALESCE(s365.gp, 0)::numeric, 2) as gp_last_365d,
    ROUND(CASE WHEN COALESCE(s365.revenue, 0) > 0 THEN COALESCE(s365.gp, 0) / s365.revenue * 100 ELSE 0 END::numeric, 1) as gp_margin_pct,

    -- Inventory
    COALESCE(sb.balance, 0) as current_balance,
    ROUND((COALESCE(sb.balance, 0) * COALESCE(sc."StockCost", 0))::numeric, 2) as inventory_value,
    ROUND(CASE WHEN COALESCE(s30.qty, 0) / 30.0 > 0 THEN COALESCE(sb.balance, 0) / (COALESCE(s30.qty, 0) / 30.0) ELSE 9999 END::numeric, 0) as days_of_inventory,

    -- Stockout risk
    CASE
        WHEN COALESCE(sb.balance, 0) <= 0 THEN 'STOCKOUT'
        WHEN COALESCE(s30.qty, 0) / 30.0 > 0 AND COALESCE(sb.balance, 0) / (COALESCE(s30.qty, 0) / 30.0) <= 7 THEN 'CRITICAL'
        WHEN COALESCE(s30.qty, 0) / 30.0 > 0 AND COALESCE(sb.balance, 0) / (COALESCE(s30.qty, 0) / 30.0) <= 14 THEN 'WARNING'
        WHEN COALESCE(s30.qty, 0) / 30.0 > 0 AND COALESCE(sb.balance, 0) / (COALESCE(s30.qty, 0) / 30.0) <= 45 THEN 'OK'
        WHEN COALESCE(s30.qty, 0) / 30.0 > 0 AND COALESCE(sb.balance, 0) / (COALESCE(s30.qty, 0) / 30.0) > 90 THEN 'OVERSTOCKED'
        ELSE 'UNKNOWN'
    END as stockout_risk,

    -- Reorder suggestions (14-day lead time, 1.5x safety factor)
    ROUND((COALESCE(s30.qty, 0) / 30.0 * 14 * 1.5)::numeric, 0) as suggested_reorder_point,
    ROUND((COALESCE(s30.qty, 0) / 30.0 * 30)::numeric, 0) as suggested_reorder_qty,  -- 30 days supply

    -- Dates
    s365.last_sale as last_sale_date,
    s365.first_sale as first_sale_date,
    CURRENT_TIMESTAMP as last_updated

FROM "AcStockCompany" sc
LEFT JOIN sales_7d s7 ON sc."AcStockID" = s7.stock_id
LEFT JOIN sales_14d s14 ON sc."AcStockID" = s14.stock_id
LEFT JOIN sales_30d s30 ON sc."AcStockID" = s30.stock_id
LEFT JOIN sales_90d s90 ON sc."AcStockID" = s90.stock_id
LEFT JOIN sales_365d s365 ON sc."AcStockID" = s365.stock_id
LEFT JOIN cv_calc cv ON sc."AcStockID" = cv.stock_id
LEFT JOIN stock_balance sb ON sc."AcStockID" = sb.stock_id
LEFT JOIN abc_class abc ON sc."AcStockID" = abc.stock_id
LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
LEFT JOIN "AcStockBrand" brand ON sc."AcStockBrandID" = brand."AcStockBrandID"
CROSS JOIN max_vals mv

WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"  -- Base UOM only
  AND sc."StockIsActive" = 'Y';

-- ========================================================================
-- Post-processing: House brand alternatives (DISABLED)
-- Columns house_brand_stock_id, house_brand_name, house_brand_gp_margin,
-- margin_opportunity_monthly were dropped as orphaned columns.
-- ========================================================================

-- ========================================================================
-- Summary Statistics
-- ========================================================================
-- SELECT
--     COUNT(*) as total_skus,
--     COUNT(*) FILTER (WHERE trend_status = 'SPIKE_UP') as spike_up,
--     COUNT(*) FILTER (WHERE trend_status = 'SPIKE_DOWN') as spike_down,
--     COUNT(*) FILTER (WHERE stockout_risk = 'CRITICAL') as stockout_critical,
--     SUM(margin_opportunity_monthly) FILTER (WHERE margin_opportunity_monthly > 0) as total_margin_opportunity
-- FROM wms.stock_movement_summary;
