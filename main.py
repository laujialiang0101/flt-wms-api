"""
Farmasi Lautan - Warehouse Management System API
================================================
Separate WMS application sharing the same PostgreSQL database as KPI Tracker.

Features planned:
- Stock allocation to outlets
- Batch and expiry tracking
- Movement analysis for purchasing
- Automated replenishment suggestions
"""

import os
import asyncio
from datetime import datetime, date, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import asyncpg

# Database configuration (same as KPI Tracker - external hostname)
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'dpg-d4pr99je5dus73eb5730-a.singapore-postgres.render.com'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'flt_sales_commission_db'),
    'user': os.getenv('DB_USER', 'flt_sales_commission_db_user'),
    'password': os.getenv('DB_PASSWORD', ''),
    'ssl': 'require'
}

pool: asyncpg.Pool = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage database connection pool lifecycle."""
    global pool
    pool = await asyncpg.create_pool(**DB_CONFIG, min_size=2, max_size=10)
    print("Database pool created")
    yield
    if pool:
        await pool.close()
        print("Database pool closed")


app = FastAPI(
    title="FLT WMS API",
    description="Warehouse Management System for Farmasi Lautan",
    version="0.1.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Health Check
# ============================================================================

@app.get("/")
async def root():
    return {"app": "FLT WMS API", "version": "0.1.0", "status": "running"}


@app.get("/health")
async def health_check():
    """Check API and database health."""
    db_status = "disconnected"
    if pool:
        try:
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
                db_status = "connected"
        except Exception as e:
            db_status = f"error: {str(e)[:50]}"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "timestamp": datetime.now().isoformat()
    }


# ============================================================================
# Data Exploration (for WMS planning)
# ============================================================================

def verify_api_key(api_key: str):
    """Verify API key for admin endpoints."""
    expected = os.getenv('WMS_API_KEY', 'flt-wms-2024')
    if api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/api/v1/admin/tables")
async def list_all_tables(api_key: str = Query(...)):
    """List all tables in the database with row counts."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            tables = await conn.fetch("""
                SELECT
                    t.table_name,
                    (SELECT COUNT(*) FROM information_schema.columns c
                     WHERE c.table_name = t.table_name AND c.table_schema = 'public') as column_count
                FROM information_schema.tables t
                WHERE t.table_schema = 'public' AND t.table_type = 'BASE TABLE'
                ORDER BY t.table_name
            """)

            result = []
            for t in tables:
                count_result = await conn.fetchrow(
                    "SELECT reltuples::bigint as approx_count FROM pg_class WHERE relname = $1",
                    t['table_name']
                )
                result.append({
                    "table": t['table_name'],
                    "columns": t['column_count'],
                    "approx_rows": count_result['approx_count'] if count_result else 0
                })

            return {"tables": result, "total": len(result)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/admin/table-schema")
async def get_table_schema(
    table_name: str = Query(...),
    api_key: str = Query(...)
):
    """Get schema details for a specific table."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            columns = await conn.fetch("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = $1 AND table_schema = 'public'
                ORDER BY ordinal_position
            """, table_name)

            sample = await conn.fetch(f'SELECT * FROM "{table_name}" LIMIT 5')

            return {
                "table": table_name,
                "columns": [dict(c) for c in columns],
                "sample_data": [dict(s) for s in sample]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/admin/inventory-tables")
async def get_inventory_tables(api_key: str = Query(...)):
    """Get overview of inventory-related tables."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            inv_tables = await conn.fetch("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_type = 'BASE TABLE'
                  AND (table_name ILIKE '%stock%'
                       OR table_name ILIKE '%inv%'
                       OR table_name ILIKE '%batch%'
                       OR table_name ILIKE '%expir%'
                       OR table_name ILIKE '%transfer%'
                       OR table_name ILIKE '%po%'
                       OR table_name ILIKE '%grn%'
                       OR table_name ILIKE '%purchase%'
                       OR table_name ILIKE '%location%')
                ORDER BY table_name
            """)

            result = []
            for t in inv_tables:
                tbl = t['table_name']
                col_count = await conn.fetchval("""
                    SELECT COUNT(*) FROM information_schema.columns
                    WHERE table_name = $1 AND table_schema = 'public'
                """, tbl)

                row_count = await conn.fetchval(
                    "SELECT reltuples::bigint FROM pg_class WHERE relname = $1", tbl
                )

                result.append({
                    "table": tbl,
                    "columns": col_count,
                    "approx_rows": row_count or 0
                })

            return {"inventory_tables": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Stock Balance Endpoints
# ============================================================================

@app.get("/api/v1/stock/locations")
async def get_locations(api_key: str = Query(...)):
    """Get all outlet/warehouse locations."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            locations = await conn.fetch("""
                SELECT
                    "AcLocationID" as id,
                    "AcLocationDesc" as name,
                    "AcLocationAddress1" as address
                FROM "AcLocation"
                WHERE "ActiveStatus" = 'Active'
                ORDER BY "AcLocationDesc"
            """)
            return {"locations": [dict(l) for l in locations]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock/balance-summary")
async def get_stock_balance_summary(
    location_id: Optional[str] = Query(None),
    api_key: str = Query(...)
):
    """Get stock balance summary by location."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # Check if AcStockBalanceLocation table exists
            exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'AcStockBalanceLocation'
                )
            """)

            if not exists:
                return {"error": "Stock balance table not synced yet"}

            # Get balance summary
            if location_id:
                balance = await conn.fetch("""
                    SELECT
                        b."AcLocationID" as location_id,
                        l."AcLocationDesc" as location_name,
                        COUNT(DISTINCT b."AcStockID") as sku_count,
                        SUM(COALESCE(b."BalanceQuantity", 0)) as total_qty,
                        SUM(COALESCE(b."BalanceQuantity", 0) * COALESCE(s."StockCost", 0)) as total_value
                    FROM "AcStockBalanceLocation" b
                    LEFT JOIN "AcLocation" l ON b."AcLocationID" = l."AcLocationID"
                    LEFT JOIN "AcStockCompany" s ON b."AcStockID" = s."AcStockID" AND b."AcStockUOMID" = s."AcStockUOMID"
                    WHERE b."AcLocationID" = $1
                    GROUP BY b."AcLocationID", l."AcLocationDesc"
                """, location_id)
            else:
                balance = await conn.fetch("""
                    SELECT
                        b."AcLocationID" as location_id,
                        l."AcLocationDesc" as location_name,
                        COUNT(DISTINCT b."AcStockID") as sku_count,
                        SUM(COALESCE(b."BalanceQuantity", 0)) as total_qty,
                        SUM(COALESCE(b."BalanceQuantity", 0) * COALESCE(s."StockCost", 0)) as total_value
                    FROM "AcStockBalanceLocation" b
                    LEFT JOIN "AcLocation" l ON b."AcLocationID" = l."AcLocationID"
                    LEFT JOIN "AcStockCompany" s ON b."AcStockID" = s."AcStockID" AND b."AcStockUOMID" = s."AcStockUOMID"
                    GROUP BY b."AcLocationID", l."AcLocationDesc"
                    ORDER BY total_value DESC
                """)

            return {"balance_summary": [dict(b) for b in balance]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock/movement-analysis")
async def get_movement_analysis(
    location_id: str = Query(...),
    days: int = Query(90, description="Analysis period in days"),
    api_key: str = Query(...)
):
    """Analyze stock movement for a location to calculate days-on-hand."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # Get sales data from AcCSD (Cash Sales Detail)
            start_date = date.today() - timedelta(days=days)

            movement = await conn.fetch("""
                WITH daily_sales AS (
                    SELECT
                        d."AcStockID" as stock_id,
                        SUM(d."ItemQuantity") as qty_sold
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."AcLocationID" = $1
                      AND m."DocumentDate"::date >= $2
                    GROUP BY d."AcStockID"
                ),
                current_balance AS (
                    SELECT
                        "AcStockID" as stock_id,
                        SUM(COALESCE("BalanceQuantity", 0)) as balance_qty
                    FROM "AcStockBalanceLocation"
                    WHERE "AcLocationID" = $1
                    GROUP BY "AcStockID"
                )
                SELECT
                    cb.stock_id,
                    s."AcStockName" as stock_name,
                    cb.balance_qty,
                    COALESCE(ds.qty_sold, 0) as qty_sold_period,
                    CASE
                        WHEN COALESCE(ds.qty_sold, 0) > 0
                        THEN ROUND((cb.balance_qty / (ds.qty_sold / $3::numeric))::numeric, 1)
                        ELSE 999
                    END as days_on_hand
                FROM current_balance cb
                LEFT JOIN daily_sales ds ON cb.stock_id = ds.stock_id
                LEFT JOIN "AcStock" s ON cb.stock_id = s."AcStockID"
                WHERE cb.balance_qty > 0
                ORDER BY days_on_hand DESC
                LIMIT 100
            """, location_id, start_date, days)

            return {
                "location_id": location_id,
                "analysis_period_days": days,
                "items": [dict(m) for m in movement]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Stock Days Analysis (Company-wide)
# ============================================================================

@app.get("/api/v1/stock/days-analysis")
async def get_stock_days_analysis(
    days: int = Query(90, description="Analysis period"),
    api_key: str = Query(...)
):
    """Calculate stock days holding across all locations."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            start_date = date.today() - timedelta(days=days)

            # Company-wide analysis
            analysis = await conn.fetch("""
                WITH period_sales AS (
                    SELECT
                        m."AcLocationID" as location_id,
                        SUM(d."ItemTotal") as total_sales,
                        SUM(d."ItemCost" * d."ItemQuantity") as total_cogs
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate"::date >= $1
                    GROUP BY m."AcLocationID"
                ),
                current_stock AS (
                    SELECT
                        b."AcLocationID" as location_id,
                        SUM(COALESCE(b."BalanceQuantity", 0) * COALESCE(s."StockCost", 0)) as stock_value
                    FROM "AcStockBalanceLocation" b
                    LEFT JOIN "AcStockCompany" s ON b."AcStockID" = s."AcStockID" AND b."AcStockUOMID" = s."AcStockUOMID"
                    GROUP BY b."AcLocationID"
                )
                SELECT
                    cs.location_id,
                    l."AcLocationDesc" as location_name,
                    ROUND(cs.stock_value::numeric, 2) as stock_value,
                    ROUND(COALESCE(ps.total_cogs, 0)::numeric, 2) as cogs_period,
                    CASE
                        WHEN COALESCE(ps.total_cogs, 0) > 0
                        THEN ROUND((cs.stock_value / (ps.total_cogs / $2::numeric))::numeric, 1)
                        ELSE 999
                    END as stock_days
                FROM current_stock cs
                LEFT JOIN period_sales ps ON cs.location_id = ps.location_id
                LEFT JOIN "AcLocation" l ON cs.location_id = l."AcLocationID"
                WHERE cs.stock_value > 0
                ORDER BY stock_days DESC
            """, start_date, days)

            # Calculate company total
            totals = await conn.fetchrow("""
                WITH period_cogs AS (
                    SELECT SUM(d."ItemCost" * d."ItemQuantity") as total_cogs
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate"::date >= $1
                ),
                total_stock AS (
                    SELECT SUM(COALESCE(b."BalanceQuantity", 0) * COALESCE(s."StockCost", 0)) as stock_value
                    FROM "AcStockBalanceLocation" b
                    LEFT JOIN "AcStockCompany" s ON b."AcStockID" = s."AcStockID" AND b."AcStockUOMID" = s."AcStockUOMID"
                )
                SELECT
                    ts.stock_value,
                    pc.total_cogs,
                    CASE
                        WHEN pc.total_cogs > 0
                        THEN ROUND((ts.stock_value / (pc.total_cogs / $2::numeric))::numeric, 1)
                        ELSE 0
                    END as company_stock_days
                FROM total_stock ts, period_cogs pc
            """, start_date, days)

            return {
                "analysis_period_days": days,
                "company_summary": {
                    "total_stock_value": float(totals['stock_value'] or 0),
                    "period_cogs": float(totals['total_cogs'] or 0),
                    "stock_days": float(totals['company_stock_days'] or 0)
                },
                "by_location": [dict(a) for a in analysis]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
