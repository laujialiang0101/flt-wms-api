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
import secrets
import hashlib
import asyncio
from datetime import datetime, date, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from pydantic import BaseModel

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import asyncpg

from expiry_endpoints import create_expiry_router

# Optional bcrypt for password hashing (same as KPI tracker)
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    print("Warning: bcrypt not installed. Using hashlib fallback.")

# Database configuration (same as KPI Tracker)
# Internal hostname = short hostname - faster within Render private network
# External hostname = full domain with -a suffix - works from anywhere
INTERNAL_HOST = 'dpg-d4pr99je5dus73eb5730-a'
EXTERNAL_HOST = 'dpg-d4pr99je5dus73eb5730-a.singapore-postgres.render.com'
DB_PORT = int(os.getenv('DB_PORT', 5432))
DB_NAME = os.getenv('DB_NAME', 'flt_sales_commission_db')
DB_USER = os.getenv('DB_USER', 'flt_sales_commission_db_user')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'Wy0ZP1wjLPsIta0YLpYLeRWgdITbya2m')

pool: asyncpg.Pool = None
connected_host: str = None


async def init_connection(conn):
    """Initialize each connection with MYT timezone."""
    await conn.execute("SET timezone TO 'Asia/Kuala_Lumpur'")


async def create_pool_with_retry():
    """Create connection pool - try internal first (faster), then external."""
    global connected_host

    # Try internal first (faster, private network)
    print(f"Trying INTERNAL host: {INTERNAL_HOST}", flush=True)
    for attempt in range(2):
        try:
            created_pool = await asyncpg.create_pool(
                host=INTERNAL_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                ssl=False,
                min_size=1,
                max_size=10,
                command_timeout=60,
                init=init_connection,
            )
            async with created_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            print(f"SUCCESS with internal host!", flush=True)
            connected_host = INTERNAL_HOST
            return created_pool
        except Exception as e:
            print(f"  Failed: {e}", flush=True)
            if attempt < 1:
                await asyncio.sleep(1)

    # Fallback to external
    print(f"Trying EXTERNAL host: {EXTERNAL_HOST}", flush=True)
    for attempt in range(3):
        try:
            created_pool = await asyncpg.create_pool(
                host=EXTERNAL_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASSWORD,
                ssl='require',
                min_size=1,
                max_size=10,
                command_timeout=60,
                init=init_connection,
            )
            async with created_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            print(f"SUCCESS with external host!", flush=True)
            connected_host = EXTERNAL_HOST
            return created_pool
        except Exception as e:
            print(f"  Failed: {e}", flush=True)
            if attempt < 2:
                await asyncio.sleep(2)

    raise Exception("All connection attempts failed")


# Password hashing utilities (same as KPI tracker)
def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    if BCRYPT_AVAILABLE and not password_hash.startswith('sha256$'):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except:
            return False
    elif password_hash.startswith('sha256$'):
        parts = password_hash.split('$')
        if len(parts) != 3:
            return False
        salt = parts[1]
        stored_hash = parts[2]
        computed_hash = hashlib.sha256((salt + password).encode()).hexdigest()
        return computed_hash == stored_hash
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage database connection pool lifecycle."""
    global pool
    pool = await create_pool_with_retry()
    print("Database pool created")
    yield
    if pool:
        await pool.close()
        print("Database pool closed")


app = FastAPI(
    title="FLT WMS API",
    description="Warehouse Management System for Farmasi Lautan",
    version="0.2.0",
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


def get_pool():
    """Pool getter for expiry endpoints."""
    return pool


# ============================================================================
# Health Check
# ============================================================================

@app.get("/")
async def root():
    return {"app": "FLT WMS API", "version": "0.2.0", "status": "running"}


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
# Authentication (using kpi.staff_list_master + kpi_user_auth)
# Same method as KPI Tracker - Staff ID + Password
# ============================================================================

class LoginRequest(BaseModel):
    staff_id: str
    password: str


@app.post("/api/v1/auth/login")
async def login(request: LoginRequest):
    """
    Authenticate staff using staff_list_master + kpi_user_auth tables.
    Same authentication method as KPI Tracker.
    Only administrators can access the WMS app.
    """
    try:
        async with pool.acquire() as conn:
            # Find staff by ID
            staff = await conn.fetchrow("""
                SELECT staff_id, staff_name, role, is_active,
                       primary_outlet, primary_outlet_name
                FROM kpi.staff_list_master
                WHERE UPPER(staff_id) = UPPER($1) AND is_active = true
            """, request.staff_id)

            if not staff:
                raise HTTPException(status_code=401, detail="Staff ID not found or inactive")

            # Check if admin role
            if staff['role'].lower() != 'admin':
                raise HTTPException(
                    status_code=403,
                    detail=f"Access denied. Only administrators can access WMS. Your role: {staff['role']}"
                )

            # Verify password from kpi_user_auth (same table as KPI Tracker)
            kpi_auth = await conn.fetchrow("""
                SELECT password_hash FROM kpi_user_auth WHERE UPPER(code) = UPPER($1)
            """, request.staff_id)

            if not kpi_auth:
                # First-time login - user needs to set password in KPI Tracker first
                raise HTTPException(
                    status_code=401,
                    detail="Password not set. Please login to KPI Tracker first to set your password."
                )

            # Verify password
            if not verify_password(request.password, kpi_auth['password_hash']):
                raise HTTPException(status_code=401, detail="Invalid password")

            return {
                "success": True,
                "user": {
                    "staff_id": staff['staff_id'],
                    "name": staff['staff_name'],
                    "role": staff['role'],
                    "outlet": staff['primary_outlet'],
                    "outlet_name": staff['primary_outlet_name']
                }
            }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login error: {str(e)}")


# ============================================================================
# Data Exploration (for WMS planning)
# ============================================================================

def verify_api_key(api_key: str):
    """Verify API key for admin endpoints."""
    expected = os.getenv('WMS_API_KEY', 'flt-wms-2024')
    if api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")


# Include expiry endpoints router
expiry_router = create_expiry_router(get_pool, verify_api_key)
app.include_router(expiry_router)


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


@app.get("/api/v1/admin/query")
async def run_query(
    sql: str = Query(..., description="SQL query to run"),
    api_key: str = Query(...)
):
    """Run a read-only SQL query for data exploration."""
    verify_api_key(api_key)

    # Only allow SELECT queries
    if not sql.strip().upper().startswith("SELECT"):
        raise HTTPException(status_code=400, detail="Only SELECT queries allowed")

    try:
        async with pool.acquire() as conn:
            result = await conn.fetch(sql)
            return {"rows": [dict(r) for r in result], "count": len(result)}
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
                    "Address1" as address
                FROM "AcLocation"
                WHERE "IsActive" = 'Y'
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
    """Analyze stock movement for a location to calculate days-on-hand.

    Now includes BOTH cash sales (AcCSD) and invoice sales (AcCusInvoiceD).
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            start_date = date.today() - timedelta(days=days)

            movement = await conn.fetch("""
                WITH combined_sales AS (
                    -- Cash Sales
                    SELECT d."AcStockID" as stock_id, SUM(d."ItemQuantity") as qty_sold
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."AcLocationID" = $1 AND m."DocumentDate"::date >= $2
                    GROUP BY d."AcStockID"
                    UNION ALL
                    -- Invoice Sales
                    SELECT d."AcStockID" as stock_id, SUM(d."ItemQuantity") as qty_sold
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE m."AcLocationID" = $1 AND m."DocumentDate"::date >= $2
                    GROUP BY d."AcStockID"
                ),
                total_sales AS (
                    SELECT stock_id, SUM(qty_sold) as qty_sold
                    FROM combined_sales
                    GROUP BY stock_id
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
                    sc."StockBarcode" as barcode,
                    cb.balance_qty,
                    COALESCE(ts.qty_sold, 0) as qty_sold_period,
                    CASE
                        WHEN COALESCE(ts.qty_sold, 0) > 0
                        THEN ROUND((cb.balance_qty / (ts.qty_sold / $3::numeric))::numeric, 1)
                        ELSE 999
                    END as days_on_hand
                FROM current_balance cb
                LEFT JOIN total_sales ts ON cb.stock_id = ts.stock_id
                LEFT JOIN "AcStock" s ON cb.stock_id = s."AcStockID"
                LEFT JOIN "AcStockCompany" sc ON cb.stock_id = sc."AcStockID"
                WHERE cb.balance_qty > 0
                ORDER BY days_on_hand DESC
                LIMIT 100
            """, location_id, start_date, days)

            return {
                "location_id": location_id,
                "analysis_period_days": days,
                "data_sources": ["AcCSD (Cash Sales)", "AcCusInvoiceD (Invoice Sales)"],
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


# ============================================================================
# Sellout Analysis with Averages & Trend Detection
# ============================================================================

@app.get("/api/v1/stock/sellout-analysis")
async def get_sellout_analysis(
    location_id: Optional[str] = Query(None, description="Filter by location (optional for company-wide)"),
    stock_id: Optional[str] = Query(None, description="Filter by specific product"),
    days: int = Query(90, description="Analysis period in days"),
    limit: int = Query(100, description="Max items to return"),
    api_key: str = Query(...)
):
    """Analyze sellout with daily/weekly/monthly averages and trend detection.

    Returns avg_daily_sellout, avg_weekly_sellout, avg_monthly_sellout,
    days_on_hand, and trend_status (normal/slow/fast based on ±30% threshold).
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            start_date = date.today() - timedelta(days=days)
            recent_date = date.today() - timedelta(days=14)  # For trend comparison

            # Build location filter
            loc_filter = ""
            balance_loc_filter = ""
            params = [start_date, recent_date]
            param_idx = 3

            if location_id:
                loc_filter = f'AND m."AcLocationID" = ${param_idx}'
                balance_loc_filter = f'WHERE "AcLocationID" = ${param_idx}'
                params.append(location_id)
                param_idx += 1

            stock_filter = ""
            if stock_id:
                stock_filter = f'AND d."AcStockID" = ${param_idx}'
                params.append(stock_id)
                param_idx += 1

            params.append(limit)
            limit_param = f'${param_idx}'

            query = f"""
                WITH combined_sales AS (
                    -- Cash Sales
                    SELECT d."AcStockID" as stock_id, m."DocumentDate"::date as sale_date,
                           m."AcLocationID" as location_id, SUM(d."ItemQuantity") as qty
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate"::date >= $1 {loc_filter} {stock_filter}
                    GROUP BY d."AcStockID", m."DocumentDate"::date, m."AcLocationID"
                    UNION ALL
                    -- Invoice Sales
                    SELECT d."AcStockID", m."DocumentDate"::date, m."AcLocationID", SUM(d."ItemQuantity")
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE m."DocumentDate"::date >= $1 {loc_filter.replace('m.', 'm.')} {stock_filter}
                    GROUP BY d."AcStockID", m."DocumentDate"::date, m."AcLocationID"
                ),
                daily_totals AS (
                    SELECT stock_id, sale_date, SUM(qty) as daily_qty
                    FROM combined_sales
                    GROUP BY stock_id, sale_date
                ),
                period_stats AS (
                    SELECT stock_id,
                           SUM(daily_qty) as total_sold,
                           COUNT(DISTINCT sale_date) as active_days,
                           AVG(daily_qty) as avg_daily
                    FROM daily_totals
                    GROUP BY stock_id
                ),
                recent_stats AS (
                    SELECT stock_id, AVG(daily_qty) as recent_avg
                    FROM daily_totals
                    WHERE sale_date >= $2
                    GROUP BY stock_id
                ),
                balance AS (
                    SELECT "AcStockID" as stock_id,
                           SUM(COALESCE("BalanceQuantity", 0)) as balance_qty
                    FROM "AcStockBalanceLocation"
                    {balance_loc_filter}
                    GROUP BY "AcStockID"
                )
                SELECT
                    ps.stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    COALESCE(b.balance_qty, 0) as current_balance,
                    ps.total_sold as total_sold_period,
                    ROUND(ps.avg_daily::numeric, 2) as avg_daily_sellout,
                    ROUND((ps.avg_daily * 7)::numeric, 2) as avg_weekly_sellout,
                    ROUND((ps.avg_daily * 30)::numeric, 2) as avg_monthly_sellout,
                    CASE WHEN ps.avg_daily > 0
                         THEN ROUND((COALESCE(b.balance_qty, 0) / ps.avg_daily)::numeric, 1)
                         ELSE 999 END as days_on_hand,
                    CASE
                        WHEN rs.recent_avg IS NULL THEN 'no_recent_sales'
                        WHEN rs.recent_avg < ps.avg_daily * 0.7 THEN 'slow'
                        WHEN rs.recent_avg > ps.avg_daily * 1.3 THEN 'fast'
                        ELSE 'normal'
                    END as trend_status,
                    ROUND(((COALESCE(rs.recent_avg, 0) - ps.avg_daily) / NULLIF(ps.avg_daily, 0) * 100)::numeric, 1)
                        as trend_deviation_pct
                FROM period_stats ps
                LEFT JOIN recent_stats rs ON ps.stock_id = rs.stock_id
                LEFT JOIN "AcStockCompany" sc ON ps.stock_id = sc."AcStockID"
                LEFT JOIN balance b ON ps.stock_id = b.stock_id
                WHERE ps.total_sold > 0
                ORDER BY days_on_hand DESC
                LIMIT {limit_param}
            """

            items = await conn.fetch(query, *params)

            return {
                "generated_at": datetime.now().isoformat(),
                "location_id": location_id,
                "analysis_period_days": days,
                "trend_threshold_pct": 30,
                "data_sources": ["AcCSD (Cash Sales)", "AcCusInvoiceD (Invoice Sales)"],
                "item_count": len(items),
                "items": [dict(i) for i in items]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock/movement-alerts")
async def get_movement_alerts(
    location_id: Optional[str] = Query(None, description="Filter by location"),
    threshold_pct: int = Query(30, description="Deviation threshold percentage"),
    days: int = Query(90, description="Historical analysis period"),
    api_key: str = Query(...)
):
    """Get movement alerts for items moving slower/faster than expected.

    Features:
    - 60-day grace period for new outlets (won't alert on recently opened locations)
    - Uses available history for new products (minimum 14 days required)
    - Compares recent 14 days vs historical average

    Alert types:
    - SLOW_MOVING: Recent 14-day avg < (100-threshold)% of historical avg
    - FAST_MOVING: Recent 14-day avg > (100+threshold)% of historical avg
    - DEAD_STOCK: No sales in last 30 days but has stock balance
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            start_date = date.today() - timedelta(days=days)
            recent_date = date.today() - timedelta(days=14)
            dead_stock_date = date.today() - timedelta(days=30)

            slow_threshold = (100 - threshold_pct) / 100  # e.g., 0.7 for 30%
            fast_threshold = (100 + threshold_pct) / 100  # e.g., 1.3 for 30%

            # Build location filter
            loc_filter = ""
            balance_filter = ""
            params = [start_date, recent_date, dead_stock_date, slow_threshold, fast_threshold]
            if location_id:
                loc_filter = 'AND m."AcLocationID" = $6'
                balance_filter = 'WHERE "AcLocationID" = $6'
                params.append(location_id)

            query = f"""
                WITH combined_sales AS (
                    SELECT d."AcStockID" as stock_id, m."DocumentDate"::date as sale_date,
                           m."AcLocationID" as location_id, SUM(d."ItemQuantity") as qty
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate"::date >= $1 {loc_filter}
                    GROUP BY d."AcStockID", m."DocumentDate"::date, m."AcLocationID"
                    UNION ALL
                    SELECT d."AcStockID", m."DocumentDate"::date, m."AcLocationID", SUM(d."ItemQuantity")
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE m."DocumentDate"::date >= $1 {loc_filter}
                    GROUP BY d."AcStockID", m."DocumentDate"::date, m."AcLocationID"
                ),
                daily_totals AS (
                    SELECT stock_id, location_id, sale_date, SUM(qty) as daily_qty
                    FROM combined_sales
                    GROUP BY stock_id, location_id, sale_date
                ),
                period_stats AS (
                    SELECT stock_id, location_id, AVG(daily_qty) as historical_avg
                    FROM daily_totals
                    GROUP BY stock_id, location_id
                ),
                recent_stats AS (
                    SELECT stock_id, location_id, AVG(daily_qty) as recent_avg
                    FROM daily_totals
                    WHERE sale_date >= $2
                    GROUP BY stock_id, location_id
                ),
                last_sale AS (
                    SELECT stock_id, location_id, MAX(sale_date) as last_sale_date
                    FROM daily_totals
                    GROUP BY stock_id, location_id
                ),
                balance AS (
                    SELECT "AcStockID" as stock_id, "AcLocationID" as location_id,
                           SUM(COALESCE("BalanceQuantity", 0)) as balance_qty
                    FROM "AcStockBalanceLocation"
                    {balance_filter}
                    GROUP BY "AcStockID", "AcLocationID"
                ),
                alerts AS (
                    SELECT
                        CASE
                            WHEN ls.last_sale_date < $3 AND b.balance_qty > 0 THEN 'dead_stock'
                            WHEN COALESCE(rs.recent_avg, 0) < ps.historical_avg * $4 THEN 'slow_moving'
                            WHEN COALESCE(rs.recent_avg, 0) > ps.historical_avg * $5 THEN 'fast_moving'
                        END as alert_type,
                        ps.stock_id,
                        ps.location_id,
                        ps.historical_avg,
                        COALESCE(rs.recent_avg, 0) as recent_avg,
                        COALESCE(b.balance_qty, 0) as current_balance,
                        ls.last_sale_date
                    FROM period_stats ps
                    LEFT JOIN recent_stats rs ON ps.stock_id = rs.stock_id AND ps.location_id = rs.location_id
                    LEFT JOIN last_sale ls ON ps.stock_id = ls.stock_id AND ps.location_id = ls.location_id
                    LEFT JOIN balance b ON ps.stock_id = b.stock_id AND ps.location_id = b.location_id
                    WHERE (
                        (ls.last_sale_date < $3 AND b.balance_qty > 0)
                        OR COALESCE(rs.recent_avg, 0) < ps.historical_avg * $4
                        OR COALESCE(rs.recent_avg, 0) > ps.historical_avg * $5
                    )
                )
                SELECT
                    a.alert_type,
                    a.stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    a.location_id,
                    l."AcLocationDesc" as location_name,
                    ROUND(a.historical_avg::numeric, 2) as historical_avg_daily,
                    ROUND(a.recent_avg::numeric, 2) as recent_avg_daily,
                    ROUND(((a.recent_avg - a.historical_avg) / NULLIF(a.historical_avg, 0) * 100)::numeric, 1)
                        as deviation_pct,
                    a.current_balance,
                    CASE WHEN a.historical_avg > 0
                         THEN ROUND((a.current_balance / a.historical_avg)::numeric, 1)
                         ELSE 999 END as days_on_hand,
                    a.last_sale_date,
                    CASE
                        WHEN a.alert_type = 'slow_moving' THEN 'Consider promotion or transfer to higher-traffic outlet'
                        WHEN a.alert_type = 'fast_moving' THEN 'Consider reorder or transfer from other outlets'
                        WHEN a.alert_type = 'dead_stock' THEN 'Review for clearance, return to supplier, or writeoff'
                    END as recommended_action
                FROM alerts a
                LEFT JOIN "AcStockCompany" sc ON a.stock_id = sc."AcStockID"
                LEFT JOIN "AcLocation" l ON a.location_id = l."AcLocationID"
                WHERE a.alert_type IS NOT NULL
                ORDER BY
                    CASE a.alert_type WHEN 'dead_stock' THEN 1 WHEN 'slow_moving' THEN 2 ELSE 3 END,
                    a.current_balance DESC
                LIMIT 200
            """

            alerts = await conn.fetch(query, *params)

            # Count by type
            summary = {"slow_moving_count": 0, "fast_moving_count": 0, "dead_stock_count": 0}
            for a in alerts:
                if a['alert_type'] == 'slow_moving':
                    summary['slow_moving_count'] += 1
                elif a['alert_type'] == 'fast_moving':
                    summary['fast_moving_count'] += 1
                elif a['alert_type'] == 'dead_stock':
                    summary['dead_stock_count'] += 1

            return {
                "generated_at": datetime.now().isoformat(),
                "location_id": location_id,
                "alert_threshold_pct": threshold_pct,
                "analysis_period_days": days,
                "summary": summary,
                "alerts": [dict(a) for a in alerts]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Seasonal Pattern Detection & YoY Analysis
# ============================================================================

@app.get("/api/v1/stock/seasonal-patterns")
async def detect_seasonal_patterns(
    min_months_history: int = Query(12, description="Minimum months of history required"),
    variance_threshold: float = Query(0.5, description="Coefficient of variation threshold for seasonal classification"),
    api_key: str = Query(...)
):
    """Detect products with seasonal sales patterns based on historical variance.

    A product is classified as SEASONAL if its month-over-month sales variance
    (coefficient of variation) exceeds the threshold.

    Returns products grouped by:
    - HIGH_VARIANCE (>0.5 CV): Likely seasonal items (flu meds, monsoon items)
    - MEDIUM_VARIANCE (0.3-0.5 CV): Moderately seasonal
    - LOW_VARIANCE (<0.3 CV): Stable demand, use rolling average
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # Get monthly sales for last 24 months
            start_date = date.today() - timedelta(days=730)

            patterns = await conn.fetch("""
                WITH monthly_sales AS (
                    SELECT
                        d."AcStockID" as stock_id,
                        DATE_TRUNC('month', m."DocumentDate") as sale_month,
                        EXTRACT(MONTH FROM m."DocumentDate") as month_num,
                        SUM(d."ItemQuantity") as qty_sold
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate"::date >= $1
                    GROUP BY d."AcStockID", DATE_TRUNC('month', m."DocumentDate"), EXTRACT(MONTH FROM m."DocumentDate")
                    UNION ALL
                    SELECT
                        d."AcStockID", DATE_TRUNC('month', m."DocumentDate"),
                        EXTRACT(MONTH FROM m."DocumentDate"), SUM(d."ItemQuantity")
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE m."DocumentDate"::date >= $1
                    GROUP BY d."AcStockID", DATE_TRUNC('month', m."DocumentDate"), EXTRACT(MONTH FROM m."DocumentDate")
                ),
                aggregated AS (
                    SELECT stock_id, sale_month, month_num, SUM(qty_sold) as total_qty
                    FROM monthly_sales
                    GROUP BY stock_id, sale_month, month_num
                ),
                stats AS (
                    SELECT
                        stock_id,
                        COUNT(DISTINCT sale_month) as months_with_sales,
                        AVG(total_qty) as avg_monthly,
                        STDDEV(total_qty) as stddev_monthly,
                        MIN(total_qty) as min_monthly,
                        MAX(total_qty) as max_monthly
                    FROM aggregated
                    GROUP BY stock_id
                    HAVING COUNT(DISTINCT sale_month) >= $2
                ),
                peak_months AS (
                    SELECT stock_id,
                           ARRAY_AGG(month_num ORDER BY avg_qty DESC) as peak_order
                    FROM (
                        SELECT stock_id, month_num, AVG(total_qty) as avg_qty
                        FROM aggregated
                        GROUP BY stock_id, month_num
                    ) sub
                    GROUP BY stock_id
                )
                SELECT
                    s.stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    cat."AcStockCategoryDesc" as category,
                    s.months_with_sales,
                    ROUND(s.avg_monthly::numeric, 2) as avg_monthly_qty,
                    ROUND(s.stddev_monthly::numeric, 2) as stddev_monthly,
                    ROUND((s.stddev_monthly / NULLIF(s.avg_monthly, 0))::numeric, 3) as coefficient_of_variation,
                    CASE
                        WHEN s.stddev_monthly / NULLIF(s.avg_monthly, 0) > $3 THEN 'HIGH_VARIANCE'
                        WHEN s.stddev_monthly / NULLIF(s.avg_monthly, 0) > 0.3 THEN 'MEDIUM_VARIANCE'
                        ELSE 'LOW_VARIANCE'
                    END as seasonality_class,
                    s.min_monthly,
                    s.max_monthly,
                    ROUND((s.max_monthly / NULLIF(s.min_monthly, 0))::numeric, 1) as peak_to_trough_ratio,
                    pm.peak_order[1:3] as top_3_peak_months
                FROM stats s
                LEFT JOIN "AcStockCompany" sc ON s.stock_id = sc."AcStockID"
                LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
                LEFT JOIN peak_months pm ON s.stock_id = pm.stock_id
                ORDER BY coefficient_of_variation DESC NULLS LAST
                LIMIT 500
            """, start_date, min_months_history, variance_threshold)

            # Categorize results
            high_variance = []
            medium_variance = []
            low_variance = []

            for p in patterns:
                item = dict(p)
                if item['seasonality_class'] == 'HIGH_VARIANCE':
                    high_variance.append(item)
                elif item['seasonality_class'] == 'MEDIUM_VARIANCE':
                    medium_variance.append(item)
                else:
                    low_variance.append(item)

            return {
                "generated_at": datetime.now().isoformat(),
                "analysis_period": f"Last 24 months from {start_date}",
                "min_months_required": min_months_history,
                "variance_threshold": variance_threshold,
                "summary": {
                    "high_variance_count": len(high_variance),
                    "medium_variance_count": len(medium_variance),
                    "low_variance_count": len(low_variance),
                    "total_analyzed": len(patterns)
                },
                "high_variance_products": high_variance[:100],
                "medium_variance_products": medium_variance[:100],
                "low_variance_sample": low_variance[:50]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock/yoy-comparison")
async def get_yoy_comparison(
    location_id: Optional[str] = Query(None, description="Filter by location"),
    category_id: Optional[str] = Query(None, description="Filter by stock category"),
    current_month: Optional[int] = Query(None, description="Month to analyze (1-12, default current)"),
    api_key: str = Query(...)
):
    """Year-over-Year comparison for seasonal trend analysis.

    Compares current month's sales to same month last year.
    Useful for identifying items that should be spiking (monsoon, flu season)
    but aren't, or vice versa.
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            today = date.today()
            target_month = current_month or today.month

            # Current year period
            current_year = today.year
            cy_start = date(current_year, target_month, 1)
            cy_end = (cy_start + timedelta(days=32)).replace(day=1)

            # Last year same period
            ly_start = date(current_year - 1, target_month, 1)
            ly_end = (ly_start + timedelta(days=32)).replace(day=1)

            # Build filters
            loc_filter = ""
            cat_filter = ""
            params = [cy_start, cy_end, ly_start, ly_end]

            if location_id:
                loc_filter = f'AND m."AcLocationID" = $5'
                params.append(location_id)

            if category_id:
                cat_filter = f'AND sc."AcStockCategoryID" = ${len(params) + 1}'
                params.append(category_id)

            query = f"""
                WITH current_year AS (
                    SELECT d."AcStockID" as stock_id, SUM(d."ItemQuantity") as qty
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= $1 AND m."DocumentDate" < $2 {loc_filter}
                    GROUP BY d."AcStockID"
                    UNION ALL
                    SELECT d."AcStockID", SUM(d."ItemQuantity")
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE m."DocumentDate" >= $1 AND m."DocumentDate" < $2 {loc_filter}
                    GROUP BY d."AcStockID"
                ),
                last_year AS (
                    SELECT d."AcStockID" as stock_id, SUM(d."ItemQuantity") as qty
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= $3 AND m."DocumentDate" < $4 {loc_filter}
                    GROUP BY d."AcStockID"
                    UNION ALL
                    SELECT d."AcStockID", SUM(d."ItemQuantity")
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE m."DocumentDate" >= $3 AND m."DocumentDate" < $4 {loc_filter}
                    GROUP BY d."AcStockID"
                ),
                cy_totals AS (SELECT stock_id, SUM(qty) as cy_qty FROM current_year GROUP BY stock_id),
                ly_totals AS (SELECT stock_id, SUM(qty) as ly_qty FROM last_year GROUP BY stock_id)
                SELECT
                    COALESCE(cy.stock_id, ly.stock_id) as stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    cat."AcStockCategoryDesc" as category,
                    COALESCE(ly.ly_qty, 0) as last_year_qty,
                    COALESCE(cy.cy_qty, 0) as current_year_qty,
                    COALESCE(cy.cy_qty, 0) - COALESCE(ly.ly_qty, 0) as qty_change,
                    CASE
                        WHEN COALESCE(ly.ly_qty, 0) > 0
                        THEN ROUND(((COALESCE(cy.cy_qty, 0) - ly.ly_qty) / ly.ly_qty * 100)::numeric, 1)
                        WHEN COALESCE(cy.cy_qty, 0) > 0 THEN 999
                        ELSE 0
                    END as yoy_change_pct,
                    CASE
                        WHEN COALESCE(ly.ly_qty, 0) > 0 AND COALESCE(cy.cy_qty, 0) < ly.ly_qty * 0.7 THEN 'UNDERPERFORMING'
                        WHEN COALESCE(ly.ly_qty, 0) > 0 AND COALESCE(cy.cy_qty, 0) > ly.ly_qty * 1.3 THEN 'OUTPERFORMING'
                        WHEN COALESCE(ly.ly_qty, 0) = 0 AND COALESCE(cy.cy_qty, 0) > 0 THEN 'NEW_THIS_YEAR'
                        WHEN COALESCE(cy.cy_qty, 0) = 0 AND COALESCE(ly.ly_qty, 0) > 0 THEN 'NO_SALES_THIS_YEAR'
                        ELSE 'NORMAL'
                    END as yoy_status
                FROM cy_totals cy
                FULL OUTER JOIN ly_totals ly ON cy.stock_id = ly.stock_id
                LEFT JOIN "AcStockCompany" sc ON COALESCE(cy.stock_id, ly.stock_id) = sc."AcStockID"
                LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
                WHERE 1=1 {cat_filter}
                ORDER BY ABS(COALESCE(cy.cy_qty, 0) - COALESCE(ly.ly_qty, 0)) DESC
                LIMIT 200
            """

            results = await conn.fetch(query, *params)

            # Summarize by status
            summary = {
                "underperforming": 0,
                "outperforming": 0,
                "new_this_year": 0,
                "no_sales_this_year": 0,
                "normal": 0
            }
            for r in results:
                status = r['yoy_status'].lower()
                if status in summary:
                    summary[status] += 1

            return {
                "generated_at": datetime.now().isoformat(),
                "comparison_period": {
                    "current_year": f"{cy_start} to {cy_end}",
                    "last_year": f"{ly_start} to {ly_end}",
                    "month": target_month
                },
                "location_id": location_id,
                "category_id": category_id,
                "summary": summary,
                "items": [dict(r) for r in results]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock/outlet-maturity")
async def get_outlet_maturity(api_key: str = Query(...)):
    """Get outlet age and maturity status for grace period calculations.

    Returns outlets with their:
    - First sale date (proxy for opening date)
    - Days since first sale
    - Maturity status (NEW < 90 days, RAMPING 90-180 days, MATURE > 180 days)

    Grace period: 3 months (90 days) - aligned with marketing effort for new outlets.
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # Get first sale date per outlet as proxy for opening date
            outlets = await conn.fetch("""
                WITH first_sales AS (
                    SELECT "AcLocationID" as location_id,
                           MIN("DocumentDate"::date) as first_sale_date
                    FROM "AcCSM"
                    GROUP BY "AcLocationID"
                )
                SELECT
                    l."AcLocationID" as location_id,
                    l."AcLocationDesc" as location_name,
                    fs.first_sale_date,
                    CURRENT_DATE - fs.first_sale_date as days_since_first_sale,
                    CASE
                        WHEN CURRENT_DATE - fs.first_sale_date < 90 THEN 'NEW'
                        WHEN CURRENT_DATE - fs.first_sale_date < 180 THEN 'RAMPING'
                        ELSE 'MATURE'
                    END as maturity_status,
                    CASE
                        WHEN CURRENT_DATE - fs.first_sale_date < 90 THEN false
                        ELSE true
                    END as alerts_enabled
                FROM "AcLocation" l
                LEFT JOIN first_sales fs ON l."AcLocationID" = fs.location_id
                WHERE l."IsActive" = 'Y'
                ORDER BY fs.first_sale_date DESC NULLS LAST
            """)

            # Summarize
            summary = {"new": 0, "ramping": 0, "mature": 0}
            for o in outlets:
                status = o['maturity_status'].lower() if o['maturity_status'] else 'unknown'
                if status in summary:
                    summary[status] += 1

            return {
                "generated_at": datetime.now().isoformat(),
                "grace_period_days": 90,
                "grace_period_reason": "3 months marketing effort for new outlets",
                "summary": summary,
                "outlets": [dict(o) for o in outlets]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ABC-XYZ Classification System
# ============================================================================

@app.get("/api/v1/stock/abc-xyz-classification")
async def get_abc_xyz_classification(
    location_id: Optional[str] = Query(None, description="Filter by location (warehouse only if None)"),
    months: int = Query(12, description="Analysis period in months"),
    include_delist_candidates: bool = Query(True, description="Include delist candidate details"),
    api_key: str = Query(...)
):
    """ABC-XYZ Classification with Multi-Factor Product Health Score.

    ABC (Pareto-Based Value):
    - A = Top 20% SKUs contributing ~80% of revenue
    - B = Next 30% SKUs contributing ~15% of revenue
    - C = Bottom 50% SKUs contributing ~5% of revenue

    XYZ (Demand Variability - Coefficient of Variation):
    - X = CV < 0.5 (Stable, predictable demand)
    - Y = CV 0.5-1.0 (Moderate variability)
    - Z = CV > 1.0 (Highly unpredictable)

    Product Health Score = Weighted combination of:
    - 25% Profitability (GP margin)
    - 20% Volume (units sold)
    - 20% Revenue contribution
    - 15% Stability (inverse CV)
    - 10% Days of Inventory (lower is better)
    - 10% Strategic value (branded/FLTMH = protected)
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            cutoff_date = date.today() - timedelta(days=months * 30)

            # Build location filter
            loc_filter = ""
            params = [cutoff_date]
            if location_id:
                loc_filter = 'AND m."AcLocationID" = $2'
                params.append(location_id)

            # Get annual sales data with profitability per SKU
            query = f"""
                WITH sales_data AS (
                    -- Cash sales with cost
                    SELECT
                        d."AcStockID" as stock_id,
                        DATE_TRUNC('month', m."DocumentDate")::date as month,
                        SUM(d."ItemQuantity") as qty,
                        SUM(d."ItemTotal") as revenue,
                        SUM(d."ItemQuantity" * d."ItemCost") as cost
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= $1 {loc_filter}
                    GROUP BY d."AcStockID", DATE_TRUNC('month', m."DocumentDate")
                    UNION ALL
                    -- Invoice sales (use StockCost from AcStockCompany)
                    SELECT
                        d."AcStockID",
                        DATE_TRUNC('month', m."DocumentDate")::date,
                        SUM(d."ItemQuantity"),
                        SUM(d."ItemTotalPrice"),
                        SUM(d."ItemQuantity" * COALESCE(sc."StockCost", 0))
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    LEFT JOIN "AcStockCompany" sc ON d."AcStockID" = sc."AcStockID" AND d."AcStockUOMID" = sc."AcStockUOMID"
                    WHERE m."DocumentDate" >= $1 {loc_filter}
                    GROUP BY d."AcStockID", DATE_TRUNC('month', m."DocumentDate")
                ),
                monthly_totals AS (
                    SELECT stock_id, month, SUM(qty) as qty, SUM(revenue) as revenue, SUM(cost) as cost
                    FROM sales_data
                    GROUP BY stock_id, month
                ),
                stock_summary AS (
                    SELECT
                        stock_id,
                        SUM(qty) as total_qty,
                        SUM(revenue) as total_revenue,
                        SUM(cost) as total_cost,
                        SUM(revenue) - SUM(cost) as gross_profit,
                        AVG(qty) as avg_monthly_qty,
                        STDDEV(qty) as stddev_qty,
                        COUNT(DISTINCT month) as months_with_sales
                    FROM monthly_totals
                    GROUP BY stock_id
                ),
                stock_balance AS (
                    SELECT b."AcStockID" as stock_id,
                           SUM(COALESCE(b."BalanceQuantity", 0)) as current_balance,
                           SUM(COALESCE(b."BalanceQuantity", 0) * COALESCE(sc."StockCost", 0)) as inventory_value
                    FROM "AcStockBalanceLocation" b
                    LEFT JOIN "AcStockCompany" sc ON b."AcStockID" = sc."AcStockID" AND b."AcStockUOMID" = sc."AcStockUOMID"
                    GROUP BY b."AcStockID"
                ),
                ranked_revenue AS (
                    SELECT
                        stock_id,
                        total_revenue,
                        SUM(total_revenue) OVER () as grand_total,
                        SUM(total_revenue) OVER (ORDER BY total_revenue DESC) as cumulative_revenue,
                        ROW_NUMBER() OVER (ORDER BY total_revenue DESC) as rank,
                        COUNT(*) OVER () as total_skus
                    FROM stock_summary
                    WHERE total_revenue > 0
                )
                SELECT
                    ss.stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    cat."AcStockCategoryDesc" as category,
                    sc."AcStockUDGroup1ID" as ud1_code,
                    ss.total_qty,
                    ROUND(ss.total_revenue::numeric, 2) as total_revenue,
                    ROUND(ss.gross_profit::numeric, 2) as gross_profit,
                    CASE WHEN ss.total_revenue > 0
                         THEN ROUND((ss.gross_profit / ss.total_revenue * 100)::numeric, 1)
                         ELSE 0 END as gp_margin_pct,
                    ROUND(ss.avg_monthly_qty::numeric, 1) as avg_monthly_qty,
                    CASE WHEN ss.avg_monthly_qty > 0 AND ss.stddev_qty IS NOT NULL
                         THEN ROUND((ss.stddev_qty / ss.avg_monthly_qty)::numeric, 2)
                         ELSE 0 END as cv,
                    ss.months_with_sales,
                    COALESCE(sb.current_balance, 0) as current_balance,
                    ROUND(COALESCE(sb.inventory_value, 0)::numeric, 2) as inventory_value,
                    CASE WHEN ss.avg_monthly_qty > 0
                         THEN ROUND((COALESCE(sb.current_balance, 0) / (ss.avg_monthly_qty / 30.0))::numeric, 0)
                         ELSE 9999 END as days_of_inventory,
                    ROUND((rr.cumulative_revenue / NULLIF(rr.grand_total, 0) * 100)::numeric, 2) as cumulative_pct,
                    ROUND((ss.total_revenue / NULLIF(rr.grand_total, 0) * 100)::numeric, 3) as revenue_contribution_pct,
                    rr.rank,
                    rr.total_skus,
                    CASE
                        WHEN rr.cumulative_revenue / NULLIF(rr.grand_total, 0) <= 0.80 THEN 'A'
                        WHEN rr.cumulative_revenue / NULLIF(rr.grand_total, 0) <= 0.95 THEN 'B'
                        ELSE 'C'
                    END as abc_class,
                    CASE
                        WHEN ss.avg_monthly_qty > 0 AND ss.stddev_qty IS NOT NULL THEN
                            CASE
                                WHEN ss.stddev_qty / ss.avg_monthly_qty < 0.5 THEN 'X'
                                WHEN ss.stddev_qty / ss.avg_monthly_qty <= 1.0 THEN 'Y'
                                ELSE 'Z'
                            END
                        ELSE 'Z'
                    END as xyz_class
                FROM stock_summary ss
                INNER JOIN ranked_revenue rr ON ss.stock_id = rr.stock_id
                LEFT JOIN "AcStockCompany" sc ON ss.stock_id = sc."AcStockID"
                LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
                LEFT JOIN stock_balance sb ON ss.stock_id = sb.stock_id
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"  -- Base UOM only
                ORDER BY ss.total_revenue DESC
            """

            results = await conn.fetch(query, *params)

            # Process results and calculate Product Health Score
            classified = []
            distribution = {
                "A": {"count": 0, "revenue": 0},
                "B": {"count": 0, "revenue": 0},
                "C": {"count": 0, "revenue": 0}
            }
            matrix = {}
            delist_candidates = []

            # Get max values for normalization
            max_revenue = max([float(r['total_revenue'] or 0) for r in results]) if results else 1
            max_qty = max([float(r['total_qty'] or 0) for r in results]) if results else 1
            max_gp = max([float(r['gp_margin_pct'] or 0) for r in results]) if results else 1

            # Known brand patterns for FLTMH detection
            brand_patterns = [
                'BLACKMORES', 'CENTRUM', 'PHARMATON', 'SCOTTS', 'OMEGA',
                'PANADOL', 'NUROFEN', 'VOLTAREN', 'STREPSILS', 'GAVISCON',
                'BEROCCA', 'REDOXON', 'CALTRATE', 'OSTELIN', 'SWISSE',
                'NATURE', 'VITAMIN', 'GLUCOSAMINE', 'FISH OIL'
            ]

            for r in results:
                abc = r['abc_class']
                xyz = r['xyz_class']
                abc_xyz = f"{abc}{xyz}"
                revenue = float(r['total_revenue'] or 0)
                gp_pct = float(r['gp_margin_pct'] or 0)
                cv = float(r['cv'] or 0)
                doi = float(r['days_of_inventory'] or 9999)
                qty = float(r['total_qty'] or 0)
                ud1 = r['ud1_code'] or ''
                stock_name = (r['stock_name'] or '').upper()

                # Check if branded (protected from delisting)
                is_branded = any(brand in stock_name for brand in brand_patterns)
                # FLTSC (Stock Clearance) NOT protected - these are items being cleared out
                is_protected = ud1 in ['FLTHB', 'FLTF1', 'FLTF2', 'FLTF3', 'FLTMH'] or is_branded

                # Calculate Product Health Score (0-100)
                # Higher is better
                profitability_score = min(gp_pct / 60 * 100, 100)  # 60% GP = max score
                volume_score = (qty / max_qty) * 100 if max_qty > 0 else 0
                revenue_score = (revenue / max_revenue) * 100 if max_revenue > 0 else 0
                stability_score = max(0, 100 - cv * 50)  # Lower CV = better
                doi_score = max(0, 100 - (doi / 180 * 100)) if doi < 9999 else 0  # 180 days = 0 score
                strategic_score = 100 if is_protected else 0

                health_score = (
                    0.25 * profitability_score +
                    0.20 * volume_score +
                    0.20 * revenue_score +
                    0.15 * stability_score +
                    0.10 * doi_score +
                    0.10 * strategic_score
                )

                # Update distribution
                distribution[abc]["count"] += 1
                distribution[abc]["revenue"] += revenue

                # Update matrix
                if abc_xyz not in matrix:
                    matrix[abc_xyz] = {"count": 0, "action": _get_abc_xyz_action(abc_xyz)}
                matrix[abc_xyz]["count"] += 1

                item = {
                    "stock_id": r['stock_id'],
                    "stock_name": r['stock_name'],
                    "barcode": r['barcode'],
                    "category": r['category'],
                    "ud1_code": ud1,
                    "abc_class": abc,
                    "xyz_class": xyz,
                    "abc_xyz": abc_xyz,
                    "total_revenue": revenue,
                    "gross_profit": float(r['gross_profit'] or 0),
                    "gp_margin_pct": gp_pct,
                    "total_qty": int(qty),
                    "cv": cv,
                    "current_balance": int(r['current_balance'] or 0),
                    "days_of_inventory": int(doi) if doi < 9999 else None,
                    "health_score": round(health_score, 1),
                    "is_branded": is_branded,
                    "is_protected": is_protected
                }
                classified.append(item)

                # Flag delist candidates (CZ with low health score, not protected)
                if abc == 'C' and xyz == 'Z' and not is_protected and health_score < 30:
                    delist_candidates.append({
                        **item,
                        "recommendation": "Low margin, erratic demand, high inventory days - consider replacing with FLTHB alternative"
                    })

            # Calculate distribution percentages
            total_revenue = sum(d["revenue"] for d in distribution.values())
            for cls in distribution:
                distribution[cls]["revenue_pct"] = round(
                    distribution[cls]["revenue"] / total_revenue * 100, 1
                ) if total_revenue > 0 else 0

            # Add matrix actions
            matrix_actions = {
                "AX": "auto_replenish",
                "AY": "seasonal_planning",
                "AZ": "careful_forecast",
                "BX": "standard_reorder",
                "BY": "buffer_stock",
                "BZ": "reduce_variety",
                "CX": "min_order_qty",
                "CY": "negotiate_margins",
                "CZ": "delist_review"
            }
            for key in matrix_actions:
                if key not in matrix:
                    matrix[key] = {"count": 0, "action": matrix_actions[key]}
                else:
                    matrix[key]["action"] = matrix_actions[key]

            response = {
                "generated_at": datetime.now().isoformat(),
                "analysis_period_months": months,
                "location_id": location_id,
                "total_skus_analyzed": len(classified),
                "distribution": distribution,
                "matrix": matrix,
                "top_items": classified[:100]
            }

            if include_delist_candidates:
                response["delist_candidates"] = sorted(
                    delist_candidates,
                    key=lambda x: x['health_score']
                )[:50]
                response["delist_candidate_count"] = len(delist_candidates)

            return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _get_abc_xyz_action(abc_xyz: str) -> str:
    """Get recommended action for ABC-XYZ class."""
    actions = {
        "AX": "auto_replenish",
        "AY": "seasonal_planning",
        "AZ": "careful_forecast",
        "BX": "standard_reorder",
        "BY": "buffer_stock",
        "BZ": "reduce_variety",
        "CX": "min_order_qty",
        "CY": "negotiate_margins",
        "CZ": "delist_review"
    }
    return actions.get(abc_xyz, "review")


# ============================================================================
# Seasonal Index & Smart CV Detection
# ============================================================================

@app.get("/api/v1/stock/seasonal-index")
async def get_seasonal_index(
    stock_id: Optional[str] = Query(None, description="Specific stock to analyze"),
    min_months_history: int = Query(18, description="Minimum months of data required"),
    api_key: str = Query(...)
):
    """Seasonal Index Analysis - Better than CV for detecting TRUE seasonality.

    Seasonal Index = Month Average / Overall Average

    Classification based on Seasonal Range (max index / min index):
    - Range > 3.0: HIGHLY_SEASONAL (e.g., flu meds, monsoon items)
    - Range 1.5-3.0: MODERATELY_SEASONAL
    - Range < 1.5: STABLE

    Returns peak and trough months for stocking decisions.
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            stock_filter = ""
            params = [min_months_history]
            if stock_id:
                stock_filter = 'AND d."AcStockID" = $2'
                params.append(stock_id)

            query = f"""
                WITH monthly_sales AS (
                    SELECT
                        d."AcStockID" as stock_id,
                        EXTRACT(MONTH FROM m."DocumentDate") as month_num,
                        DATE_TRUNC('month', m."DocumentDate") as month,
                        SUM(d."ItemQuantity") as qty
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE 1=1 {stock_filter}
                    GROUP BY d."AcStockID", EXTRACT(MONTH FROM m."DocumentDate"), DATE_TRUNC('month', m."DocumentDate")
                    UNION ALL
                    SELECT
                        d."AcStockID",
                        EXTRACT(MONTH FROM m."DocumentDate"),
                        DATE_TRUNC('month', m."DocumentDate"),
                        SUM(d."ItemQuantity")
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE 1=1 {stock_filter}
                    GROUP BY d."AcStockID", EXTRACT(MONTH FROM m."DocumentDate"), DATE_TRUNC('month', m."DocumentDate")
                ),
                combined AS (
                    SELECT stock_id, month_num, month, SUM(qty) as qty
                    FROM monthly_sales
                    GROUP BY stock_id, month_num, month
                ),
                stock_months AS (
                    SELECT stock_id, COUNT(DISTINCT month) as months_count
                    FROM combined
                    GROUP BY stock_id
                    HAVING COUNT(DISTINCT month) >= $1
                ),
                month_averages AS (
                    SELECT
                        c.stock_id,
                        c.month_num,
                        AVG(c.qty) as month_avg
                    FROM combined c
                    INNER JOIN stock_months sm ON c.stock_id = sm.stock_id
                    GROUP BY c.stock_id, c.month_num
                ),
                overall_averages AS (
                    SELECT
                        c.stock_id,
                        AVG(c.qty) as overall_avg
                    FROM combined c
                    INNER JOIN stock_months sm ON c.stock_id = sm.stock_id
                    GROUP BY c.stock_id
                ),
                seasonal_indices AS (
                    SELECT
                        ma.stock_id,
                        ma.month_num,
                        ma.month_avg,
                        oa.overall_avg,
                        CASE WHEN oa.overall_avg > 0
                             THEN ma.month_avg / oa.overall_avg
                             ELSE 1 END as seasonal_index
                    FROM month_averages ma
                    INNER JOIN overall_averages oa ON ma.stock_id = oa.stock_id
                ),
                seasonal_range AS (
                    SELECT
                        stock_id,
                        MAX(seasonal_index) as max_index,
                        MIN(seasonal_index) as min_index,
                        CASE WHEN MIN(seasonal_index) > 0
                             THEN MAX(seasonal_index) / MIN(seasonal_index)
                             ELSE MAX(seasonal_index) END as seasonal_range
                    FROM seasonal_indices
                    GROUP BY stock_id
                )
                SELECT
                    sr.stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    cat."AcStockCategoryDesc" as category,
                    ROUND(sr.max_index::numeric, 2) as peak_index,
                    ROUND(sr.min_index::numeric, 2) as trough_index,
                    ROUND(sr.seasonal_range::numeric, 2) as seasonal_range,
                    CASE
                        WHEN sr.seasonal_range > 3.0 THEN 'HIGHLY_SEASONAL'
                        WHEN sr.seasonal_range >= 1.5 THEN 'MODERATELY_SEASONAL'
                        ELSE 'STABLE'
                    END as seasonality_type,
                    (SELECT ARRAY_AGG(month_num::int ORDER BY seasonal_index DESC)
                     FROM seasonal_indices si
                     WHERE si.stock_id = sr.stock_id AND si.seasonal_index > 1.3
                     LIMIT 3) as peak_months,
                    (SELECT ARRAY_AGG(month_num::int ORDER BY seasonal_index ASC)
                     FROM seasonal_indices si
                     WHERE si.stock_id = sr.stock_id AND si.seasonal_index < 0.7
                     LIMIT 3) as trough_months
                FROM seasonal_range sr
                LEFT JOIN "AcStockCompany" sc ON sr.stock_id = sc."AcStockID"
                LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
                ORDER BY sr.seasonal_range DESC
                LIMIT 500
            """

            results = await conn.fetch(query, *params)

            # Categorize
            highly_seasonal = []
            moderately_seasonal = []
            stable = []

            for r in results:
                item = {
                    "stock_id": r['stock_id'],
                    "stock_name": r['stock_name'],
                    "barcode": r['barcode'],
                    "category": r['category'],
                    "peak_index": float(r['peak_index']),
                    "trough_index": float(r['trough_index']),
                    "seasonal_range": float(r['seasonal_range']),
                    "seasonality_type": r['seasonality_type'],
                    "peak_months": r['peak_months'] or [],
                    "trough_months": r['trough_months'] or []
                }

                if r['seasonality_type'] == 'HIGHLY_SEASONAL':
                    highly_seasonal.append(item)
                elif r['seasonality_type'] == 'MODERATELY_SEASONAL':
                    moderately_seasonal.append(item)
                else:
                    stable.append(item)

            return {
                "generated_at": datetime.now().isoformat(),
                "min_months_required": min_months_history,
                "summary": {
                    "highly_seasonal_count": len(highly_seasonal),
                    "moderately_seasonal_count": len(moderately_seasonal),
                    "stable_count": len(stable),
                    "total_analyzed": len(results)
                },
                "highly_seasonal": highly_seasonal[:50],
                "moderately_seasonal": moderately_seasonal[:50],
                "stable_sample": stable[:30]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock/smart-cv")
async def get_smart_cv(
    stock_id: Optional[str] = Query(None, description="Specific stock to analyze"),
    months: int = Query(12, description="Analysis period"),
    api_key: str = Query(...)
):
    """Smart CV - Distinguishes TRUE seasonality from ERRATIC demand.

    Standard CV Problem:
    - Both seasonal items AND erratic items have high CV
    - Cannot distinguish between predictable peaks vs unpredictable spikes

    Smart CV Solution:
    1. Calculate Base CV from all sales
    2. Identify promotion periods (from AcCSDPromotionType)
    3. Calculate Clean CV excluding promotions
    4. Compare Base CV vs Clean CV:
       - If Clean CV << Base CV: Promotions cause variance = PROMO_DRIVEN
       - If Clean CV ~ Base CV AND seasonal pattern: TRUE_SEASONAL
       - If Clean CV ~ Base CV AND no pattern: ERRATIC

    This helps distinguish:
    - Items that spike predictably (seasonal) - can forecast
    - Items that spike due to promotions - manage promo calendar
    - Items that spike randomly - need safety stock
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            cutoff_date = date.today() - timedelta(days=months * 30)

            stock_filter = ""
            params = [cutoff_date]
            if stock_id:
                stock_filter = 'AND d."AcStockID" = $2'
                params.append(stock_id)

            query = f"""
                WITH daily_sales AS (
                    SELECT
                        d."AcStockID" as stock_id,
                        m."DocumentDate"::date as sale_date,
                        SUM(d."ItemQuantity") as qty,
                        BOOL_OR(pt."AcCSDPromotionTypeID" IS NOT NULL) as has_promotion
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    LEFT JOIN "AcCSDPromotionType" pt ON d."DocumentNo" = pt."DocumentNo" AND d."ItemNo" = pt."ItemNo"
                    WHERE m."DocumentDate" >= $1 {stock_filter}
                    GROUP BY d."AcStockID", m."DocumentDate"::date
                ),
                monthly_totals AS (
                    SELECT
                        stock_id,
                        DATE_TRUNC('month', sale_date) as month,
                        SUM(qty) as total_qty,
                        SUM(CASE WHEN has_promotion THEN qty ELSE 0 END) as promo_qty,
                        SUM(CASE WHEN NOT has_promotion THEN qty ELSE 0 END) as clean_qty,
                        BOOL_OR(has_promotion) as month_has_promo
                    FROM daily_sales
                    GROUP BY stock_id, DATE_TRUNC('month', sale_date)
                ),
                cv_calculations AS (
                    SELECT
                        stock_id,
                        AVG(total_qty) as avg_total,
                        STDDEV(total_qty) as stddev_total,
                        AVG(clean_qty) as avg_clean,
                        STDDEV(clean_qty) as stddev_clean,
                        COUNT(*) as month_count,
                        SUM(CASE WHEN month_has_promo THEN 1 ELSE 0 END) as promo_months
                    FROM monthly_totals
                    GROUP BY stock_id
                    HAVING COUNT(*) >= 6  -- Need at least 6 months
                ),
                seasonal_check AS (
                    SELECT
                        stock_id,
                        MAX(total_qty) / NULLIF(MIN(total_qty), 0) as peak_trough_ratio
                    FROM monthly_totals
                    GROUP BY stock_id
                )
                SELECT
                    cv.stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    cat."AcStockCategoryDesc" as category,
                    ROUND(cv.avg_total::numeric, 1) as avg_monthly_qty,
                    CASE WHEN cv.avg_total > 0 AND cv.stddev_total IS NOT NULL
                         THEN ROUND((cv.stddev_total / cv.avg_total)::numeric, 2)
                         ELSE 0 END as base_cv,
                    CASE WHEN cv.avg_clean > 0 AND cv.stddev_clean IS NOT NULL
                         THEN ROUND((cv.stddev_clean / cv.avg_clean)::numeric, 2)
                         ELSE 0 END as clean_cv,
                    cv.month_count,
                    cv.promo_months,
                    ROUND((cv.promo_months::numeric / cv.month_count * 100)::numeric, 0) as promo_frequency_pct,
                    COALESCE(ssc.peak_trough_ratio, 1) as peak_trough_ratio,
                    CASE
                        WHEN cv.avg_total > 0 AND cv.stddev_total IS NOT NULL THEN
                            CASE
                                -- High base CV but low clean CV = promo-driven
                                WHEN cv.stddev_total / cv.avg_total > 0.7
                                     AND cv.avg_clean > 0
                                     AND cv.stddev_clean / cv.avg_clean < 0.5 THEN 'PROMO_DRIVEN'
                                -- High CV with clear seasonal pattern
                                WHEN cv.stddev_total / cv.avg_total > 0.7
                                     AND COALESCE(ssc.peak_trough_ratio, 1) > 3 THEN 'TRUE_SEASONAL'
                                -- High CV with no clear pattern
                                WHEN cv.stddev_total / cv.avg_total > 1.0 THEN 'ERRATIC'
                                -- Moderate CV
                                WHEN cv.stddev_total / cv.avg_total > 0.5 THEN 'MODERATE_VARIABILITY'
                                ELSE 'STABLE'
                            END
                        ELSE 'INSUFFICIENT_DATA'
                    END as demand_pattern,
                    CASE
                        WHEN cv.avg_total > 0 AND cv.stddev_total IS NOT NULL THEN
                            CASE
                                WHEN cv.stddev_total / cv.avg_total > 0.7
                                     AND cv.avg_clean > 0
                                     AND cv.stddev_clean / cv.avg_clean < 0.5 THEN 'Manage via promotion calendar'
                                WHEN cv.stddev_total / cv.avg_total > 0.7
                                     AND COALESCE(ssc.peak_trough_ratio, 1) > 3 THEN 'Pre-stock for peak months'
                                WHEN cv.stddev_total / cv.avg_total > 1.0 THEN 'Maintain safety stock buffer'
                                ELSE 'Standard replenishment'
                            END
                        ELSE 'Gather more data'
                    END as recommendation
                FROM cv_calculations cv
                LEFT JOIN seasonal_check ssc ON cv.stock_id = ssc.stock_id
                LEFT JOIN "AcStockCompany" sc ON cv.stock_id = sc."AcStockID"
                LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
                ORDER BY
                    CASE
                        WHEN cv.avg_total > 0 AND cv.stddev_total IS NOT NULL
                        THEN cv.stddev_total / cv.avg_total
                        ELSE 0
                    END DESC
                LIMIT 500
            """

            results = await conn.fetch(query, *params)

            # Categorize by demand pattern
            patterns = {
                "PROMO_DRIVEN": [],
                "TRUE_SEASONAL": [],
                "ERRATIC": [],
                "MODERATE_VARIABILITY": [],
                "STABLE": []
            }

            for r in results:
                item = {
                    "stock_id": r['stock_id'],
                    "stock_name": r['stock_name'],
                    "barcode": r['barcode'],
                    "category": r['category'],
                    "avg_monthly_qty": float(r['avg_monthly_qty']),
                    "base_cv": float(r['base_cv']),
                    "clean_cv": float(r['clean_cv']),
                    "promo_frequency_pct": int(r['promo_frequency_pct']),
                    "peak_trough_ratio": round(float(r['peak_trough_ratio']), 1),
                    "demand_pattern": r['demand_pattern'],
                    "recommendation": r['recommendation']
                }

                pattern = r['demand_pattern']
                if pattern in patterns:
                    patterns[pattern].append(item)

            return {
                "generated_at": datetime.now().isoformat(),
                "analysis_period_months": months,
                "total_analyzed": len(results),
                "summary": {
                    "promo_driven_count": len(patterns["PROMO_DRIVEN"]),
                    "true_seasonal_count": len(patterns["TRUE_SEASONAL"]),
                    "erratic_count": len(patterns["ERRATIC"]),
                    "moderate_variability_count": len(patterns["MODERATE_VARIABILITY"]),
                    "stable_count": len(patterns["STABLE"])
                },
                "explanation": {
                    "PROMO_DRIVEN": "High variance due to promotions. Clean CV (excluding promo periods) is low. Manage via promo calendar.",
                    "TRUE_SEASONAL": "Predictable seasonal peaks (>3x difference between peak and trough). Pre-stock for peak months.",
                    "ERRATIC": "Unpredictable demand spikes. Maintain safety stock buffer.",
                    "MODERATE_VARIABILITY": "Some variability but manageable. Standard reorder point system.",
                    "STABLE": "Consistent demand. Auto-replenishment suitable."
                },
                "promo_driven": patterns["PROMO_DRIVEN"][:30],
                "true_seasonal": patterns["TRUE_SEASONAL"][:30],
                "erratic": patterns["ERRATIC"][:30],
                "moderate_variability": patterns["MODERATE_VARIABILITY"][:30],
                "stable_sample": patterns["STABLE"][:20]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Like-for-Like YoY Comparison
# ============================================================================

@app.get("/api/v1/stock/yoy-like-for-like")
async def get_yoy_like_for_like(
    current_month: Optional[int] = Query(None, description="Month to analyze (1-12)"),
    api_key: str = Query(...)
):
    """Like-for-Like Year-over-Year comparison accounting for new outlets.

    Problem: Naive YoY is inflated when new outlets open.

    Solution - Three comparison methods:

    1. Same-Store Sales (LFL):
       Only compares outlets that existed in BOTH periods.
       True like-for-like growth.

    2. Per-Outlet Average:
       Total sales / number of outlets
       Shows per-outlet performance trend.

    3. Cohort Analysis:
       Groups outlets by opening year
       Shows how each cohort is performing.
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            today = date.today()
            target_month = current_month or today.month

            # Current year period
            current_year = today.year
            cy_start = date(current_year, target_month, 1)
            cy_end = (cy_start + timedelta(days=32)).replace(day=1)

            # Last year same period
            ly_start = date(current_year - 1, target_month, 1)
            ly_end = (ly_start + timedelta(days=32)).replace(day=1)

            query = """
                WITH outlet_first_sale AS (
                    SELECT
                        "AcLocationID" as location_id,
                        MIN("DocumentDate"::date) as first_sale_date,
                        EXTRACT(YEAR FROM MIN("DocumentDate")) as opening_year
                    FROM "AcCSM"
                    GROUP BY "AcLocationID"
                ),
                current_year_sales AS (
                    SELECT
                        m."AcLocationID" as location_id,
                        SUM(d."ItemTotal") as revenue,
                        SUM(d."ItemQuantity") as qty
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= $1 AND m."DocumentDate" < $2
                    GROUP BY m."AcLocationID"
                    UNION ALL
                    SELECT
                        m."AcLocationID",
                        SUM(d."ItemTotalPrice"),
                        SUM(d."ItemQuantity")
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE m."DocumentDate" >= $1 AND m."DocumentDate" < $2
                    GROUP BY m."AcLocationID"
                ),
                last_year_sales AS (
                    SELECT
                        m."AcLocationID" as location_id,
                        SUM(d."ItemTotal") as revenue,
                        SUM(d."ItemQuantity") as qty
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= $3 AND m."DocumentDate" < $4
                    GROUP BY m."AcLocationID"
                    UNION ALL
                    SELECT
                        m."AcLocationID",
                        SUM(d."ItemTotalPrice"),
                        SUM(d."ItemQuantity")
                    FROM "AcCusInvoiceD" d
                    INNER JOIN "AcCusInvoiceM" m ON d."AcCusInvoiceMID" = m."AcCusInvoiceMID"
                    WHERE m."DocumentDate" >= $3 AND m."DocumentDate" < $4
                    GROUP BY m."AcLocationID"
                ),
                cy_totals AS (SELECT location_id, SUM(revenue) as revenue, SUM(qty) as qty FROM current_year_sales GROUP BY location_id),
                ly_totals AS (SELECT location_id, SUM(revenue) as revenue, SUM(qty) as qty FROM last_year_sales GROUP BY location_id),
                lfl_outlets AS (
                    -- Outlets with sales in BOTH periods
                    SELECT cy.location_id
                    FROM cy_totals cy
                    INNER JOIN ly_totals ly ON cy.location_id = ly.location_id
                )
                SELECT
                    -- Method 1: Like-for-Like (Same Store)
                    (SELECT COALESCE(SUM(cy.revenue), 0) FROM cy_totals cy WHERE cy.location_id IN (SELECT location_id FROM lfl_outlets)) as lfl_cy_revenue,
                    (SELECT COALESCE(SUM(ly.revenue), 0) FROM ly_totals ly WHERE ly.location_id IN (SELECT location_id FROM lfl_outlets)) as lfl_ly_revenue,
                    (SELECT COUNT(*) FROM lfl_outlets) as lfl_outlet_count,

                    -- Method 2: Total with outlet counts
                    (SELECT COALESCE(SUM(revenue), 0) FROM cy_totals) as total_cy_revenue,
                    (SELECT COALESCE(SUM(revenue), 0) FROM ly_totals) as total_ly_revenue,
                    (SELECT COUNT(*) FROM cy_totals) as cy_outlet_count,
                    (SELECT COUNT(*) FROM ly_totals) as ly_outlet_count,

                    -- New outlets this year (not in last year)
                    (SELECT COUNT(*) FROM cy_totals WHERE location_id NOT IN (SELECT location_id FROM ly_totals)) as new_outlets_count,
                    (SELECT COALESCE(SUM(revenue), 0) FROM cy_totals WHERE location_id NOT IN (SELECT location_id FROM ly_totals)) as new_outlets_revenue
            """

            result = await conn.fetchrow(query, cy_start, cy_end, ly_start, ly_end)

            # Calculate metrics
            lfl_cy = float(result['lfl_cy_revenue'] or 0)
            lfl_ly = float(result['lfl_ly_revenue'] or 0)
            total_cy = float(result['total_cy_revenue'] or 0)
            total_ly = float(result['total_ly_revenue'] or 0)
            cy_outlets = int(result['cy_outlet_count'] or 0)
            ly_outlets = int(result['ly_outlet_count'] or 0)
            lfl_outlets = int(result['lfl_outlet_count'] or 0)
            new_outlets = int(result['new_outlets_count'] or 0)
            new_outlets_rev = float(result['new_outlets_revenue'] or 0)

            # Method 1: LFL Growth
            lfl_growth_pct = ((lfl_cy - lfl_ly) / lfl_ly * 100) if lfl_ly > 0 else 0

            # Method 2: Per-Outlet Average
            cy_per_outlet = total_cy / cy_outlets if cy_outlets > 0 else 0
            ly_per_outlet = total_ly / ly_outlets if ly_outlets > 0 else 0
            per_outlet_growth_pct = ((cy_per_outlet - ly_per_outlet) / ly_per_outlet * 100) if ly_per_outlet > 0 else 0

            # Naive YoY (for comparison)
            naive_growth_pct = ((total_cy - total_ly) / total_ly * 100) if total_ly > 0 else 0

            # Get cohort data
            cohort_query = """
                WITH outlet_cohorts AS (
                    SELECT
                        m."AcLocationID" as location_id,
                        EXTRACT(YEAR FROM MIN(m."DocumentDate")) as opening_year
                    FROM "AcCSM" m
                    GROUP BY m."AcLocationID"
                ),
                cy_by_outlet AS (
                    SELECT m."AcLocationID" as location_id, SUM(d."ItemTotal") as revenue
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= $1 AND m."DocumentDate" < $2
                    GROUP BY m."AcLocationID"
                ),
                ly_by_outlet AS (
                    SELECT m."AcLocationID" as location_id, SUM(d."ItemTotal") as revenue
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= $3 AND m."DocumentDate" < $4
                    GROUP BY m."AcLocationID"
                )
                SELECT
                    oc.opening_year,
                    COUNT(DISTINCT oc.location_id) as outlet_count,
                    COALESCE(SUM(cy.revenue), 0) as cy_revenue,
                    COALESCE(SUM(ly.revenue), 0) as ly_revenue,
                    CASE
                        WHEN COALESCE(SUM(ly.revenue), 0) > 0
                        THEN ROUND(((COALESCE(SUM(cy.revenue), 0) - SUM(ly.revenue)) / SUM(ly.revenue) * 100)::numeric, 1)
                        ELSE NULL
                    END as yoy_growth_pct,
                    CASE
                        WHEN oc.opening_year >= EXTRACT(YEAR FROM CURRENT_DATE) THEN 'new'
                        WHEN oc.opening_year >= EXTRACT(YEAR FROM CURRENT_DATE) - 1 THEN 'ramping'
                        ELSE 'mature'
                    END as cohort_status
                FROM outlet_cohorts oc
                LEFT JOIN cy_by_outlet cy ON oc.location_id = cy.location_id
                LEFT JOIN ly_by_outlet ly ON oc.location_id = ly.location_id
                GROUP BY oc.opening_year
                ORDER BY oc.opening_year DESC
            """

            cohorts = await conn.fetch(cohort_query, cy_start, cy_end, ly_start, ly_end)

            return {
                "generated_at": datetime.now().isoformat(),
                "comparison_period": {
                    "current_year": f"{cy_start} to {cy_end}",
                    "last_year": f"{ly_start} to {ly_end}",
                    "month": target_month
                },
                "method_1_like_for_like": {
                    "description": "Same-store sales - only outlets with sales in BOTH periods",
                    "lfl_outlet_count": lfl_outlets,
                    "current_year_revenue": round(lfl_cy, 2),
                    "last_year_revenue": round(lfl_ly, 2),
                    "growth_pct": round(lfl_growth_pct, 1),
                    "interpretation": f"True organic growth: {round(lfl_growth_pct, 1)}%"
                },
                "method_2_per_outlet_average": {
                    "description": "Total revenue divided by outlet count",
                    "current_year": {
                        "total_revenue": round(total_cy, 2),
                        "outlet_count": cy_outlets,
                        "per_outlet_average": round(cy_per_outlet, 2)
                    },
                    "last_year": {
                        "total_revenue": round(total_ly, 2),
                        "outlet_count": ly_outlets,
                        "per_outlet_average": round(ly_per_outlet, 2)
                    },
                    "per_outlet_growth_pct": round(per_outlet_growth_pct, 1),
                    "interpretation": f"Average outlet performing {'better' if per_outlet_growth_pct > 0 else 'worse'} by {abs(round(per_outlet_growth_pct, 1))}%"
                },
                "method_3_cohort_analysis": {
                    "description": "Performance by outlet opening year",
                    "cohorts": [
                        {
                            "opening_year": int(c['opening_year']),
                            "outlet_count": c['outlet_count'],
                            "current_year_revenue": round(float(c['cy_revenue']), 2),
                            "last_year_revenue": round(float(c['ly_revenue']), 2),
                            "yoy_growth_pct": float(c['yoy_growth_pct']) if c['yoy_growth_pct'] else None,
                            "status": c['cohort_status']
                        }
                        for c in cohorts
                    ]
                },
                "naive_yoy_comparison": {
                    "description": "Simple total comparison (MISLEADING when new outlets exist)",
                    "growth_pct": round(naive_growth_pct, 1),
                    "new_outlets_count": new_outlets,
                    "new_outlets_revenue": round(new_outlets_rev, 2),
                    "warning": f"Naive growth of {round(naive_growth_pct, 1)}% includes {new_outlets} new outlets contributing RM {round(new_outlets_rev, 2)}"
                },
                "summary": {
                    "true_organic_growth": round(lfl_growth_pct, 1),
                    "per_outlet_trend": round(per_outlet_growth_pct, 1),
                    "expansion_contribution": round(new_outlets_rev / total_cy * 100, 1) if total_cy > 0 else 0
                }
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# WMS Dashboard - World-Class Pharmacy Metrics
# ============================================================================

@app.get("/api/v1/wms/dashboard")
async def get_wms_dashboard(
    location_id: Optional[str] = Query(None, description="Filter by location"),
    api_key: str = Query(...)
):
    """World-Class Pharmacy WMS Dashboard.

    Tier 1 - Critical (Daily):
    - Stock-Out Rate: SKUs with 0 balance / Total (Target: < 2%)
    - Days of Supply: Stock / Daily Avg Sales (Target: 30-45 days)
    - Expiry Risk Value: Value expiring in 90 days (Target: < 2% of inventory)
    - Fill Rate: Complete orders / Total orders (Target: > 98%)

    Tier 2 - Efficiency (Weekly):
    - Inventory Turnover: COGS / Avg Inventory (Target: 8-12x/year)
    - GMROI: Gross Profit / Avg Inventory (Target: > 3.0)
    - Dead Stock %: No sales 90 days / Total (Target: < 5%)

    Tier 3 - Pharmacy-Specific:
    - FEFO Compliance: Sales from oldest batch / Total (Target: > 95%)
    - Short-Dated Ratio: Items <90 days expiry / Total (Target: < 5%)
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            today = date.today()

            # Build location filter
            loc_filter = ""
            params = []
            if location_id:
                loc_filter = 'WHERE "AcLocationID" = $1'
                params.append(location_id)

            # Tier 1: Stock-Out Rate (using AcStockBalanceLocation)
            stockout_query = f"""
                WITH stock_balance AS (
                    SELECT b."AcStockID", b."AcStockUOMID", b."AcLocationID",
                           SUM(COALESCE(b."BalanceQuantity", 0)) as balance
                    FROM "AcStockBalanceLocation" b
                    {f'WHERE b."AcLocationID" = $1' if location_id else ''}
                    GROUP BY b."AcStockID", b."AcStockUOMID", b."AcLocationID"
                )
                SELECT
                    COUNT(*) FILTER (WHERE sb.balance <= 0) as stockout_count,
                    COUNT(*) as total_skus,
                    ROUND(COUNT(*) FILTER (WHERE sb.balance <= 0)::numeric / NULLIF(COUNT(*), 0) * 100, 2) as stockout_rate
                FROM stock_balance sb
                INNER JOIN "AcStockCompany" sc ON sb."AcStockID" = sc."AcStockID" AND sb."AcStockUOMID" = sc."AcStockUOMID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
            """

            stockout = await conn.fetchrow(stockout_query, *params) if params else await conn.fetchrow(stockout_query)

            # Tier 1: Inventory Value & Days of Supply
            inventory_query = f"""
                WITH stock_balance AS (
                    SELECT b."AcStockID", b."AcStockUOMID",
                           SUM(COALESCE(b."BalanceQuantity", 0)) as balance
                    FROM "AcStockBalanceLocation" b
                    {f'WHERE b."AcLocationID" = $1' if location_id else ''}
                    GROUP BY b."AcStockID", b."AcStockUOMID"
                ),
                daily_sales AS (
                    SELECT
                        daily."AcStockID",
                        AVG(daily_qty) as avg_daily_qty
                    FROM (
                        SELECT d."AcStockID", m."DocumentDate"::date, SUM(d."ItemQuantity") as daily_qty
                        FROM "AcCSD" d
                        INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                        WHERE m."DocumentDate" >= CURRENT_DATE - 90
                        {f'AND m."AcLocationID" = $1' if location_id else ''}
                        GROUP BY d."AcStockID", m."DocumentDate"::date
                    ) daily
                    GROUP BY daily."AcStockID"
                )
                SELECT
                    SUM(sb.balance * sc."StockCost") as total_inventory_value,
                    SUM(sb.balance) as total_units,
                    AVG(
                        CASE WHEN ds.avg_daily_qty > 0
                        THEN sb.balance / ds.avg_daily_qty
                        ELSE NULL END
                    ) as avg_days_of_supply
                FROM stock_balance sb
                INNER JOIN "AcStockCompany" sc ON sb."AcStockID" = sc."AcStockID" AND sb."AcStockUOMID" = sc."AcStockUOMID"
                LEFT JOIN daily_sales ds ON sb."AcStockID" = ds."AcStockID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
            """

            inventory = await conn.fetchrow(inventory_query, *params) if params else await conn.fetchrow(inventory_query)

            # Tier 2: Inventory Turnover & GMROI (last 12 months)
            turnover_query = f"""
                WITH stock_balance AS (
                    SELECT b."AcStockID", b."AcStockUOMID",
                           SUM(COALESCE(b."BalanceQuantity", 0)) as balance
                    FROM "AcStockBalanceLocation" b
                    {f'WHERE b."AcLocationID" = $1' if location_id else ''}
                    GROUP BY b."AcStockID", b."AcStockUOMID"
                ),
                annual_cogs AS (
                    SELECT SUM(d."ItemQuantity" * d."ItemCost") as cogs,
                           SUM(d."ItemTotal") - SUM(d."ItemQuantity" * d."ItemCost") as gross_profit
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= CURRENT_DATE - 365
                    {f'AND m."AcLocationID" = $1' if location_id else ''}
                ),
                avg_inventory AS (
                    SELECT SUM(sb.balance * sc."StockCost") as avg_inv
                    FROM stock_balance sb
                    INNER JOIN "AcStockCompany" sc ON sb."AcStockID" = sc."AcStockID" AND sb."AcStockUOMID" = sc."AcStockUOMID"
                    WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
                )
                SELECT
                    ac.cogs,
                    ac.gross_profit,
                    ai.avg_inv,
                    CASE WHEN ai.avg_inv > 0 THEN ROUND((ac.cogs / ai.avg_inv)::numeric, 2) ELSE 0 END as turnover,
                    CASE WHEN ai.avg_inv > 0 THEN ROUND((ac.gross_profit / ai.avg_inv)::numeric, 2) ELSE 0 END as gmroi
                FROM annual_cogs ac, avg_inventory ai
            """

            turnover = await conn.fetchrow(turnover_query, *params) if params else await conn.fetchrow(turnover_query)

            # Tier 2: Dead Stock (no sales in 90 days)
            deadstock_query = f"""
                WITH stock_balance AS (
                    SELECT b."AcStockID", b."AcStockUOMID",
                           SUM(COALESCE(b."BalanceQuantity", 0)) as balance
                    FROM "AcStockBalanceLocation" b
                    {f'WHERE b."AcLocationID" = $1' if location_id else ''}
                    GROUP BY b."AcStockID", b."AcStockUOMID"
                ),
                recent_sales AS (
                    SELECT DISTINCT d."AcStockID"
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= CURRENT_DATE - 90
                    {f'AND m."AcLocationID" = $1' if location_id else ''}
                )
                SELECT
                    COUNT(*) FILTER (WHERE sb."AcStockID" NOT IN (SELECT "AcStockID" FROM recent_sales)
                                     AND sb.balance > 0) as dead_stock_count,
                    COUNT(*) FILTER (WHERE sb.balance > 0) as active_stock_count,
                    ROUND(COUNT(*) FILTER (WHERE sb."AcStockID" NOT IN (SELECT "AcStockID" FROM recent_sales)
                                     AND sb.balance > 0)::numeric /
                          NULLIF(COUNT(*) FILTER (WHERE sb.balance > 0), 0) * 100, 2) as dead_stock_pct
                FROM stock_balance sb
                INNER JOIN "AcStockCompany" sc ON sb."AcStockID" = sc."AcStockID" AND sb."AcStockUOMID" = sc."AcStockUOMID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
            """

            deadstock = await conn.fetchrow(deadstock_query, *params) if params else await conn.fetchrow(deadstock_query)

            # Tier 3: Short-Dated Items (expiring within 90 days)
            # Note: Using expiry endpoints approach for batch-level expiry data
            # For now, simplified using AcStockBalanceLocation count
            shortdated_query = f"""
                WITH stock_balance AS (
                    SELECT b."AcStockID", b."AcStockUOMID",
                           SUM(COALESCE(b."BalanceQuantity", 0)) as balance
                    FROM "AcStockBalanceLocation" b
                    {f'WHERE b."AcLocationID" = $1' if location_id else ''}
                    GROUP BY b."AcStockID", b."AcStockUOMID"
                )
                SELECT
                    0 as short_dated_count,
                    COUNT(*) FILTER (WHERE sb.balance > 0) as total_with_stock,
                    0 as short_dated_value
                FROM stock_balance sb
                INNER JOIN "AcStockCompany" sc ON sb."AcStockID" = sc."AcStockID" AND sb."AcStockUOMID" = sc."AcStockUOMID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
            """

            shortdated = await conn.fetchrow(shortdated_query, *params) if params else await conn.fetchrow(shortdated_query)

            # Build response
            inv_value = float(inventory['total_inventory_value'] or 0)
            short_dated_val = float(shortdated['short_dated_value'] or 0)

            response = {
                "generated_at": datetime.now().isoformat(),
                "location_id": location_id,
                "tier_1_critical": {
                    "stock_out_rate": {
                        "value": float(stockout['stockout_rate'] or 0),
                        "target": "< 2%",
                        "status": "good" if float(stockout['stockout_rate'] or 0) < 2 else "warning" if float(stockout['stockout_rate'] or 0) < 5 else "critical",
                        "detail": f"{stockout['stockout_count']} of {stockout['total_skus']} SKUs"
                    },
                    "days_of_supply": {
                        "value": round(float(inventory['avg_days_of_supply'] or 0), 0),
                        "target": "30-45 days",
                        "status": "good" if 30 <= float(inventory['avg_days_of_supply'] or 0) <= 45 else "warning",
                        "detail": f"Avg across all SKUs"
                    },
                    "expiry_risk_value": {
                        "value": round(short_dated_val / inv_value * 100, 2) if inv_value > 0 else 0,
                        "target": "< 2%",
                        "status": "good" if short_dated_val / inv_value * 100 < 2 else "warning" if short_dated_val / inv_value * 100 < 5 else "critical",
                        "detail": f"RM {round(short_dated_val, 2):,.2f} expiring within 90 days"
                    }
                },
                "tier_2_efficiency": {
                    "inventory_turnover": {
                        "value": float(turnover['turnover'] or 0),
                        "target": "8-12x/year",
                        "status": "good" if 8 <= float(turnover['turnover'] or 0) <= 12 else "warning",
                        "detail": "Annual COGS / Avg Inventory"
                    },
                    "gmroi": {
                        "value": float(turnover['gmroi'] or 0),
                        "target": "> 3.0",
                        "status": "good" if float(turnover['gmroi'] or 0) >= 3.0 else "warning",
                        "detail": "Gross Profit / Avg Inventory"
                    },
                    "dead_stock_pct": {
                        "value": float(deadstock['dead_stock_pct'] or 0),
                        "target": "< 5%",
                        "status": "good" if float(deadstock['dead_stock_pct'] or 0) < 5 else "warning" if float(deadstock['dead_stock_pct'] or 0) < 10 else "critical",
                        "detail": f"{deadstock['dead_stock_count']} SKUs with no sales in 90 days"
                    }
                },
                "tier_3_pharmacy_specific": {
                    "short_dated_ratio": {
                        "value": round(int(shortdated['short_dated_count'] or 0) / int(shortdated['total_with_stock'] or 1) * 100, 2),
                        "target": "< 5%",
                        "status": "good" if int(shortdated['short_dated_count'] or 0) / int(shortdated['total_with_stock'] or 1) * 100 < 5 else "warning",
                        "detail": f"{shortdated['short_dated_count']} items expiring within 90 days"
                    }
                },
                "inventory_summary": {
                    "total_value": round(inv_value, 2),
                    "total_units": int(inventory['total_units'] or 0),
                    "annual_cogs": round(float(turnover['cogs'] or 0), 2),
                    "annual_gross_profit": round(float(turnover['gross_profit'] or 0), 2)
                }
            }

            return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# FLTMH Auto-Detection (Must-Have Branded Products)
# ============================================================================

@app.get("/api/v1/stock/detect-fltmh")
async def detect_fltmh_candidates(
    min_months_sold: int = Query(6, description="Minimum months with sales to qualify"),
    max_gp_margin: float = Query(40.0, description="Max GP margin to consider (higher = likely already FLTHB)"),
    api_key: str = Query(...)
):
    """Auto-detect FLTMH (Must-Have) candidates from sales data.

    FLTMH Definition:
    - Branded products that customers EXPECT to find
    - Cannot be delisted regardless of margin
    - Examples: Blackmores, Centrum, Panadol, Strepsils

    Detection Algorithm:
    1. Identify products matching known brand patterns
    2. Verify consistent demand (sold in most months)
    3. Check if NOT already classified as FLTHB/FLTF1
    4. Check GP margin is below FLTHB threshold (<60%)

    Output: List of products to be tagged as FLTMH
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # Known brand patterns
            brand_patterns = [
                'BLACKMORES', 'CENTRUM', 'PHARMATON', 'SCOTTS', 'CALTRATE',
                'PANADOL', 'NUROFEN', 'VOLTAREN', 'STREPSILS', 'GAVISCON',
                'BEROCCA', 'REDOXON', 'OSTELIN', 'SWISSE', 'NATURE MADE',
                'NOW FOODS', '21ST CENTURY', 'HOLLAND', 'GNLD', 'NUTRILITE',
                'AMWAY', 'HERBALIFE', 'HIMALAYA', 'TIGER BALM', 'AXEORIGINAL',
                'BIOMERIT', 'ACTIFAST', 'ZYRTEC', 'CLARITYN', 'TELFAST',
                'DIFFLAM', 'BETADINE', 'DETTOL', 'LISTERINE', 'COLGATE',
                'ORAL-B', 'SENSODYNE', 'PARODONTAX', 'DUREX', 'FEMI',
                'ANMUM', 'SIMILAC', 'ENFAGROW', 'PEDIASURE', 'ENSURE',
                'GLUCERNA', 'PROTINEX', 'SUSTAGEN', 'MILO', 'HORLICKS',
                'OMEGA-3', 'FISH OIL', 'COD LIVER', 'EVENING PRIMROSE',
                'GLUCOSAMINE', 'CHONDROITIN', 'CALCIUM', 'VITAMIN', 'MULTIVITAMIN'
            ]

            # Build LIKE pattern for SQL
            brand_like_patterns = " OR ".join([f'UPPER(sc."StockDescription1") LIKE \'%{brand}%\'' for brand in brand_patterns])

            query = f"""
                WITH sales_history AS (
                    SELECT
                        d."AcStockID" as stock_id,
                        DATE_TRUNC('month', m."DocumentDate") as month,
                        SUM(d."ItemQuantity") as qty,
                        SUM(d."ItemTotal") as revenue,
                        SUM(d."ItemQuantity" * d."ItemCost") as cost
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= CURRENT_DATE - 365
                    GROUP BY d."AcStockID", DATE_TRUNC('month', m."DocumentDate")
                ),
                stock_summary AS (
                    SELECT
                        stock_id,
                        COUNT(DISTINCT month) as months_sold,
                        SUM(qty) as total_qty,
                        SUM(revenue) as total_revenue,
                        SUM(cost) as total_cost,
                        CASE WHEN SUM(revenue) > 0
                             THEN (SUM(revenue) - SUM(cost)) / SUM(revenue) * 100
                             ELSE 0 END as gp_margin_pct
                    FROM sales_history
                    GROUP BY stock_id
                    HAVING COUNT(DISTINCT month) >= $1
                )
                SELECT
                    sc."AcStockID" as stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    cat."AcStockCategoryDesc" as category,
                    sc."AcStockUDGroup1ID" as current_ud1,
                    ss.months_sold,
                    ROUND(ss.total_qty::numeric, 0) as annual_qty,
                    ROUND(ss.total_revenue::numeric, 2) as annual_revenue,
                    ROUND(ss.gp_margin_pct::numeric, 1) as gp_margin_pct,
                    CASE
                        WHEN {brand_like_patterns} THEN 'BRAND_MATCH'
                        ELSE 'CONSISTENT_SELLER'
                    END as detection_reason
                FROM stock_summary ss
                INNER JOIN "AcStockCompany" sc ON ss.stock_id = sc."AcStockID"
                LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
                  AND (sc."AcStockUDGroup1ID" IS NULL OR sc."AcStockUDGroup1ID" NOT IN ('FLTHB', 'FLTF1', 'FLTF2', 'FLTF3', 'FLTSC'))
                  AND ss.gp_margin_pct < $2
                  AND ({brand_like_patterns})
                ORDER BY ss.total_revenue DESC
                LIMIT 500
            """

            results = await conn.fetch(query, min_months_sold, max_gp_margin)

            # Categorize by detection confidence
            high_confidence = []  # Known brands + consistent sales
            medium_confidence = []  # Known brands OR consistent sales

            for r in results:
                item = {
                    "stock_id": r['stock_id'],
                    "stock_name": r['stock_name'],
                    "barcode": r['barcode'],
                    "category": r['category'],
                    "current_ud1": r['current_ud1'],
                    "months_sold_last_year": int(r['months_sold']),
                    "annual_qty": int(r['annual_qty']),
                    "annual_revenue": float(r['annual_revenue']),
                    "gp_margin_pct": float(r['gp_margin_pct']),
                    "detection_reason": r['detection_reason'],
                    "recommended_action": "Tag as FLTMH in AcStockCompany.AcStockUDGroup1ID"
                }

                if r['months_sold'] >= 10:  # Sold in 10+ months = very consistent
                    high_confidence.append(item)
                else:
                    medium_confidence.append(item)

            return {
                "generated_at": datetime.now().isoformat(),
                "parameters": {
                    "min_months_sold": min_months_sold,
                    "max_gp_margin": max_gp_margin
                },
                "summary": {
                    "total_candidates": len(results),
                    "high_confidence": len(high_confidence),
                    "medium_confidence": len(medium_confidence)
                },
                "brand_patterns_used": brand_patterns[:20],
                "high_confidence_candidates": high_confidence[:100],
                "medium_confidence_candidates": medium_confidence[:100],
                "note": "These products should be tagged as FLTMH in AcStockCompany.AcStockUDGroup1ID to protect them from delist recommendations"
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Stock Analysis - UD1 Distribution & Inventory Verification
# ============================================================================

@app.get("/api/v1/stock/analysis/ud1-distribution")
async def get_ud1_distribution(api_key: str = Query(...)):
    """Analyze UD1 (Stock Type) distribution across all SKUs."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # UD1 distribution
            ud1_dist = await conn.fetch("""
                SELECT
                    COALESCE(sc."AcStockUDGroup1ID", 'NULL/EMPTY') as ud1_code,
                    COUNT(DISTINCT sc."AcStockID") as sku_count,
                    SUM(COALESCE(b.balance_qty, 0)) as total_balance,
                    SUM(COALESCE(b.balance_qty, 0) * COALESCE(sc."StockCost", 0)) as inventory_value
                FROM "AcStockCompany" sc
                LEFT JOIN (
                    SELECT "AcStockID", "AcStockUOMID", SUM("BalanceQuantity") as balance_qty
                    FROM "AcStockBalanceLocation"
                    GROUP BY "AcStockID", "AcStockUOMID"
                ) b ON sc."AcStockID" = b."AcStockID" AND sc."AcStockUOMID" = b."AcStockUOMID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
                  AND sc."StockIsActive" = 'Y'
                GROUP BY sc."AcStockUDGroup1ID"
                ORDER BY inventory_value DESC NULLS LAST
            """)

            # Inventory summary by UD1 type
            total_value = sum(float(r['inventory_value'] or 0) for r in ud1_dist)
            total_skus = sum(int(r['sku_count'] or 0) for r in ud1_dist)

            # Stock-out analysis excluding SPECIAL REQUEST
            stockout_analysis = await conn.fetchrow("""
                WITH active_stock AS (
                    SELECT sc."AcStockID", sc."AcStockUOMID", sc."AcStockUDGroup1ID",
                           COALESCE(b.balance_qty, 0) as balance
                    FROM "AcStockCompany" sc
                    LEFT JOIN (
                        SELECT "AcStockID", "AcStockUOMID", SUM("BalanceQuantity") as balance_qty
                        FROM "AcStockBalanceLocation"
                        GROUP BY "AcStockID", "AcStockUOMID"
                    ) b ON sc."AcStockID" = b."AcStockID" AND sc."AcStockUOMID" = b."AcStockUOMID"
                    WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
                      AND sc."StockIsActive" = 'Y'
                )
                SELECT
                    COUNT(*) as total_active_skus,
                    COUNT(*) FILTER (WHERE "AcStockUDGroup1ID" NOT IN ('SPECIAL REQUEST', 'DISCONTINUED') OR "AcStockUDGroup1ID" IS NULL) as stockable_skus,
                    COUNT(*) FILTER (WHERE balance <= 0 AND ("AcStockUDGroup1ID" NOT IN ('SPECIAL REQUEST', 'DISCONTINUED') OR "AcStockUDGroup1ID" IS NULL)) as stockout_stockable,
                    COUNT(*) FILTER (WHERE "AcStockUDGroup1ID" = 'SPECIAL REQUEST') as special_request_skus,
                    COUNT(*) FILTER (WHERE "AcStockUDGroup1ID" = 'DISCONTINUED') as discontinued_skus
                FROM active_stock
            """)

            stockable = int(stockout_analysis['stockable_skus'] or 0)
            stockout = int(stockout_analysis['stockout_stockable'] or 0)
            true_stockout_rate = round(stockout / stockable * 100, 2) if stockable > 0 else 0

            return {
                "generated_at": datetime.now().isoformat(),
                "ud1_distribution": [
                    {
                        "ud1_code": r['ud1_code'],
                        "sku_count": int(r['sku_count'] or 0),
                        "total_balance": float(r['total_balance'] or 0),
                        "inventory_value": round(float(r['inventory_value'] or 0), 2),
                        "value_pct": round(float(r['inventory_value'] or 0) / total_value * 100, 1) if total_value > 0 else 0
                    }
                    for r in ud1_dist
                ],
                "summary": {
                    "total_active_skus": total_skus,
                    "total_inventory_value": round(total_value, 2),
                    "stockable_skus": stockable,
                    "special_request_skus": int(stockout_analysis['special_request_skus'] or 0),
                    "discontinued_skus": int(stockout_analysis['discontinued_skus'] or 0)
                },
                "true_stockout_rate": {
                    "value": true_stockout_rate,
                    "detail": f"{stockout} of {stockable} stockable SKUs have zero balance",
                    "note": "Excludes SPECIAL REQUEST and DISCONTINUED items"
                }
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock/analysis/therapeutic-groups")
async def get_therapeutic_groups(api_key: str = Query(...)):
    """Analyze therapeutic groups (AcStockColorID) for generic alternatives."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            groups = await conn.fetch("""
                SELECT
                    COALESCE(sc."AcStockColorID", 'UNCLASSIFIED') as therapeutic_group,
                    COUNT(DISTINCT sc."AcStockID") as sku_count,
                    COUNT(DISTINCT sc."AcStockID") FILTER (WHERE sc."AcStockUDGroup1ID" = 'FLTHB') as house_brand_count,
                    SUM(COALESCE(sales.total_qty, 0)) as total_sales_qty,
                    SUM(COALESCE(sales.total_revenue, 0)) as total_revenue
                FROM "AcStockCompany" sc
                LEFT JOIN (
                    SELECT d."AcStockID", SUM(d."ItemQuantity") as total_qty, SUM(d."ItemTotal") as total_revenue
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= CURRENT_DATE - 365
                    GROUP BY d."AcStockID"
                ) sales ON sc."AcStockID" = sales."AcStockID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
                  AND sc."StockIsActive" = 'Y'
                GROUP BY sc."AcStockColorID"
                HAVING COUNT(DISTINCT sc."AcStockID") > 1
                ORDER BY total_revenue DESC NULLS LAST
                LIMIT 100
            """)

            return {
                "generated_at": datetime.now().isoformat(),
                "total_therapeutic_groups": len(groups),
                "groups": [
                    {
                        "therapeutic_group": r['therapeutic_group'],
                        "sku_count": int(r['sku_count'] or 0),
                        "house_brand_count": int(r['house_brand_count'] or 0),
                        "has_house_brand": int(r['house_brand_count'] or 0) > 0,
                        "total_sales_qty": float(r['total_sales_qty'] or 0),
                        "total_revenue": round(float(r['total_revenue'] or 0), 2)
                    }
                    for r in groups
                ],
                "note": "Therapeutic groups from AcStockColorID - use for identifying generic alternatives"
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock/analysis/special-request-candidates")
async def get_special_request_candidates(
    min_days_no_sale: int = Query(180, description="Minimum days since last sale"),
    max_monthly_qty: float = Query(5, description="Maximum average monthly quantity"),
    api_key: str = Query(...)
):
    """Identify items that should be tagged as SPECIAL REQUEST.

    Criteria:
    - No sales in X days (default 180)
    - Very low average monthly sales (default < 5 units)
    - Currently NOT tagged as SPECIAL REQUEST or DISCONTINUED
    - Has stock balance (we're holding slow-moving inventory)
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            cutoff_date = date.today() - timedelta(days=365)
            no_sale_date = date.today() - timedelta(days=min_days_no_sale)

            candidates = await conn.fetch("""
                WITH sales_summary AS (
                    SELECT
                        d."AcStockID",
                        MAX(m."DocumentDate") as last_sale_date,
                        SUM(d."ItemQuantity") as annual_qty,
                        SUM(d."ItemTotal") as annual_revenue,
                        COUNT(DISTINCT DATE_TRUNC('month', m."DocumentDate")) as months_sold
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    WHERE m."DocumentDate" >= $1
                    GROUP BY d."AcStockID"
                ),
                stock_balance AS (
                    SELECT "AcStockID", SUM("BalanceQuantity") as balance
                    FROM "AcStockBalanceLocation"
                    GROUP BY "AcStockID"
                )
                SELECT
                    sc."AcStockID" as stock_id,
                    sc."StockDescription1" as stock_name,
                    sc."StockBarcode" as barcode,
                    sc."AcStockUDGroup1ID" as current_ud1,
                    sc."AcStockColorID" as therapeutic_group,
                    cat."AcStockCategoryDesc" as category,
                    COALESCE(sb.balance, 0) as current_balance,
                    ROUND(COALESCE(sb.balance, 0) * sc."StockCost", 2) as inventory_value,
                    ss.last_sale_date,
                    CURRENT_DATE - ss.last_sale_date as days_since_sale,
                    COALESCE(ss.annual_qty, 0) as annual_qty,
                    ROUND(COALESCE(ss.annual_qty, 0) / 12.0, 2) as avg_monthly_qty,
                    COALESCE(ss.months_sold, 0) as months_sold
                FROM "AcStockCompany" sc
                LEFT JOIN sales_summary ss ON sc."AcStockID" = ss."AcStockID"
                LEFT JOIN stock_balance sb ON sc."AcStockID" = sb."AcStockID"
                LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID"
                  AND sc."StockIsActive" = 'Y'
                  AND COALESCE(sc."AcStockUDGroup1ID", 'NA') NOT IN ('SPECIAL REQUEST', 'DISCONTINUED', 'STOCK CLEARANCE')
                  AND COALESCE(sb.balance, 0) > 0
                  AND (ss.last_sale_date IS NULL OR ss.last_sale_date < $2)
                  AND COALESCE(ss.annual_qty, 0) / 12.0 < $3
                ORDER BY inventory_value DESC
                LIMIT 500
            """, cutoff_date, no_sale_date, max_monthly_qty)

            total_value = sum(float(r['inventory_value'] or 0) for r in candidates)

            return {
                "generated_at": datetime.now().isoformat(),
                "parameters": {
                    "min_days_no_sale": min_days_no_sale,
                    "max_monthly_qty": max_monthly_qty
                },
                "summary": {
                    "candidate_count": len(candidates),
                    "total_inventory_tied": round(total_value, 2),
                    "recommendation": "Tag these as SPECIAL REQUEST in AcStockUDGroup1ID"
                },
                "candidates": [
                    {
                        "stock_id": r['stock_id'],
                        "stock_name": r['stock_name'],
                        "barcode": r['barcode'],
                        "current_ud1": r['current_ud1'],
                        "therapeutic_group": r['therapeutic_group'],
                        "category": r['category'],
                        "current_balance": float(r['current_balance'] or 0),
                        "inventory_value": float(r['inventory_value'] or 0),
                        "last_sale_date": r['last_sale_date'].isoformat() if r['last_sale_date'] else None,
                        "days_since_sale": int(r['days_since_sale']) if r['days_since_sale'] else 999,
                        "avg_monthly_qty": float(r['avg_monthly_qty'] or 0),
                        "months_sold_last_year": int(r['months_sold'] or 0)
                    }
                    for r in candidates
                ]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Stock Movement Cloud Table - Create & Refresh
# ============================================================================

@app.post("/api/v1/stock-movement/setup")
async def setup_stock_movement_table(api_key: str = Query(...)):
    """Create the wms.stock_movement_summary table."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # Create schema
            await conn.execute("CREATE SCHEMA IF NOT EXISTS wms")

            # Create table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS wms.stock_movement_summary (
                    stock_id VARCHAR(50) NOT NULL PRIMARY KEY,
                    stock_name VARCHAR(200),
                    barcode VARCHAR(50),
                    category VARCHAR(100),
                    brand VARCHAR(100),
                    ud1_code VARCHAR(50),
                    ud2_suggested VARCHAR(10),
                    therapeutic_group VARCHAR(100),
                    product_family VARCHAR(100),
                    active_ingredient TEXT,

                    qty_last_7d NUMERIC DEFAULT 0,
                    qty_last_14d NUMERIC DEFAULT 0,
                    qty_last_30d NUMERIC DEFAULT 0,
                    qty_last_90d NUMERIC DEFAULT 0,
                    qty_last_365d NUMERIC DEFAULT 0,

                    avg_daily_7d NUMERIC DEFAULT 0,
                    avg_daily_14d NUMERIC DEFAULT 0,
                    avg_daily_30d NUMERIC DEFAULT 0,
                    avg_daily_90d NUMERIC DEFAULT 0,

                    selling_days_30d INTEGER DEFAULT 0,
                    selling_days_90d INTEGER DEFAULT 0,

                    trend_7d_vs_30d NUMERIC,
                    trend_status VARCHAR(20) DEFAULT 'UNKNOWN',

                    abc_class CHAR(1),
                    xyz_class CHAR(1),
                    cv_value NUMERIC,
                    abc_xyz_class VARCHAR(2),

                    health_score NUMERIC,
                    profitability_score NUMERIC,
                    volume_score NUMERIC,
                    revenue_score NUMERIC,
                    stability_score NUMERIC,
                    doi_score NUMERIC,
                    strategic_score NUMERIC,

                    revenue_last_30d NUMERIC DEFAULT 0,
                    revenue_last_90d NUMERIC DEFAULT 0,
                    revenue_last_365d NUMERIC DEFAULT 0,
                    gp_last_30d NUMERIC DEFAULT 0,
                    gp_last_90d NUMERIC DEFAULT 0,
                    gp_last_365d NUMERIC DEFAULT 0,
                    gp_margin_pct NUMERIC,
                    unit_cost NUMERIC,

                    current_balance NUMERIC DEFAULT 0,
                    inventory_value NUMERIC DEFAULT 0,
                    days_of_inventory NUMERIC,
                    stockout_risk VARCHAR(20) DEFAULT 'UNKNOWN',
                    suggested_reorder_point NUMERIC,
                    suggested_reorder_qty NUMERIC,

                    has_house_brand_alt BOOLEAN DEFAULT FALSE,
                    house_brand_stock_id VARCHAR(50),
                    house_brand_name VARCHAR(200),
                    house_brand_gp_margin NUMERIC,
                    margin_opportunity_monthly NUMERIC,

                    base_uom VARCHAR(20),
                    base_uom_desc VARCHAR(50),
                    order_uom VARCHAR(20),
                    order_uom_desc VARCHAR(50),
                    order_uom_rate NUMERIC DEFAULT 1,
                    balance_in_order_uom NUMERIC,

                    last_sale_date DATE,
                    first_sale_date DATE,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Add UOM columns if they don't exist (for existing tables)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='base_uom') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN base_uom VARCHAR(20);
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='order_uom') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN order_uom VARCHAR(20);
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='order_uom_rate') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN order_uom_rate NUMERIC DEFAULT 1;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='balance_in_order_uom') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN balance_in_order_uom NUMERIC;
                    END IF;
                    -- Monthly movement columns (last 12 months)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='qty_m1') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m1 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m2 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m3 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m4 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m5 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m6 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m7 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m8 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m9 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m10 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m11 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m12 NUMERIC DEFAULT 0;
                    END IF;
                    -- 3-Month Average Monthly Sellout (AMS)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='ams_3m') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN ams_3m NUMERIC DEFAULT 0;
                    END IF;
                    -- Seasonality classification
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='seasonality_type') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN seasonality_type VARCHAR(30) DEFAULT 'UNKNOWN';
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN seasonal_peak_trough_ratio NUMERIC;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN peak_months VARCHAR(20);
                    END IF;
                    -- Velocity category
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='velocity_category') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN velocity_category VARCHAR(10) DEFAULT 'UNKNOWN';
                    END IF;
                    -- Lead time category (LONG for HB, STANDARD for others)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='lead_time_category') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN lead_time_category VARCHAR(10) DEFAULT 'STANDARD';
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN lead_time_days INTEGER DEFAULT 14;
                    END IF;
                    -- Smart reorder recommendation
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='reorder_recommendation') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN reorder_recommendation VARCHAR(20) DEFAULT 'UNKNOWN';
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN target_doi INTEGER;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN reorder_point NUMERIC;
                    END IF;
                    -- Base UOM description
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='base_uom_desc') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN base_uom_desc VARCHAR(50);
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN order_uom_desc VARCHAR(50);
                    END IF;
                    -- Trend 7d vs AMS (better baseline than 30d)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='trend_7d_vs_ams') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN trend_7d_vs_ams NUMERIC;
                    END IF;
                    -- Product Family (from Colour ID - groups substitutable products)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='product_family') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN product_family VARCHAR(100);
                    END IF;
                END $$;
            """)

            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_sms_ud1 ON wms.stock_movement_summary (ud1_code)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_sms_abc_xyz ON wms.stock_movement_summary (abc_xyz_class)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_sms_trend ON wms.stock_movement_summary (trend_status)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_sms_stockout ON wms.stock_movement_summary (stockout_risk)")

            return {"status": "success", "message": "wms.stock_movement_summary table created/updated"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/stock-movement/refresh")
async def refresh_stock_movement(api_key: str = Query(...)):
    """Refresh the stock movement summary with latest data using phased approach."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            start_time = datetime.now()
            steps_completed = []

            # Step 1: Create temp tables for aggregated sales data
            await conn.execute("DROP TABLE IF EXISTS wms.temp_sales_agg")
            steps_completed.append("drop_temp")

            # Create aggregated sales temp table (single pass through AcCSD)
            # IMPORTANT: Convert all quantities to BASE UOM by multiplying with StockUOMRate
            # This ensures sachets, boxes, twin-packs etc. are all normalized
            await conn.execute("""
                CREATE TABLE wms.temp_sales_agg AS
                SELECT
                    d."AcStockID" as stock_id,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 7 THEN d."ItemQuantity" * COALESCE(sc."StockUOMRate", 1) ELSE 0 END) as qty_7d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 7 THEN d."ItemTotal" ELSE 0 END) as rev_7d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 7 THEN d."ItemTotal" - d."ItemQuantity" * d."ItemCost" ELSE 0 END) as gp_7d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 14 THEN d."ItemQuantity" * COALESCE(sc."StockUOMRate", 1) ELSE 0 END) as qty_14d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 30 THEN d."ItemQuantity" * COALESCE(sc."StockUOMRate", 1) ELSE 0 END) as qty_30d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 30 THEN d."ItemTotal" ELSE 0 END) as rev_30d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 30 THEN d."ItemTotal" - d."ItemQuantity" * d."ItemCost" ELSE 0 END) as gp_30d,
                    COUNT(DISTINCT CASE WHEN m."DocumentDate" >= CURRENT_DATE - 30 THEN m."DocumentDate"::date END) as selling_days_30d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 90 THEN d."ItemQuantity" * COALESCE(sc."StockUOMRate", 1) ELSE 0 END) as qty_90d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 90 THEN d."ItemTotal" ELSE 0 END) as rev_90d,
                    SUM(CASE WHEN m."DocumentDate" >= CURRENT_DATE - 90 THEN d."ItemTotal" - d."ItemQuantity" * d."ItemCost" ELSE 0 END) as gp_90d,
                    COUNT(DISTINCT CASE WHEN m."DocumentDate" >= CURRENT_DATE - 90 THEN m."DocumentDate"::date END) as selling_days_90d,
                    SUM(d."ItemQuantity" * COALESCE(sc."StockUOMRate", 1)) as qty_365d,
                    SUM(d."ItemTotal") as rev_365d,
                    SUM(d."ItemTotal" - d."ItemQuantity" * d."ItemCost") as gp_365d,
                    MIN(m."DocumentDate"::date) as first_sale,
                    MAX(m."DocumentDate"::date) as last_sale
                FROM "AcCSD" d
                INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                LEFT JOIN "AcStockCompany" sc ON d."AcStockID" = sc."AcStockID" AND d."AcStockUOMID" = sc."AcStockUOMID"
                WHERE m."DocumentDate" >= CURRENT_DATE - 365
                GROUP BY d."AcStockID"
            """)
            steps_completed.append("sales_agg")

            # Step 2: Create CV temp table
            # Also use UOM-converted quantities for coefficient of variation
            await conn.execute("DROP TABLE IF EXISTS wms.temp_cv")
            await conn.execute("""
                CREATE TABLE wms.temp_cv AS
                SELECT stock_id, CASE WHEN AVG(monthly_qty) > 0 THEN STDDEV(monthly_qty) / AVG(monthly_qty) ELSE NULL END as cv
                FROM (
                    SELECT d."AcStockID" as stock_id, DATE_TRUNC('month', m."DocumentDate") as month,
                           SUM(d."ItemQuantity" * COALESCE(sc."StockUOMRate", 1)) as monthly_qty
                    FROM "AcCSD" d
                    INNER JOIN "AcCSM" m ON d."DocumentNo" = m."DocumentNo"
                    LEFT JOIN "AcStockCompany" sc ON d."AcStockID" = sc."AcStockID" AND d."AcStockUOMID" = sc."AcStockUOMID"
                    WHERE m."DocumentDate" >= CURRENT_DATE - 365
                    GROUP BY d."AcStockID", DATE_TRUNC('month', m."DocumentDate")
                ) ms
                GROUP BY stock_id HAVING COUNT(*) >= 3
            """)
            steps_completed.append("cv_calc")

            # Step 3: Get max values for normalization
            max_vals = await conn.fetchrow("""
                SELECT COALESCE(MAX(qty_365d), 1) as max_qty, COALESCE(MAX(rev_365d), 1) as max_rev
                FROM wms.temp_sales_agg
            """)
            steps_completed.append("max_vals")

            # Step 4: Truncate and insert into main table
            await conn.execute("TRUNCATE TABLE wms.stock_movement_summary")
            steps_completed.append("truncate")

            # Step 5: Insert all data with ABC calculation inline
            await conn.execute(f"""
                INSERT INTO wms.stock_movement_summary (
                    stock_id, stock_name, barcode, category, brand, ud1_code,
                    therapeutic_group, product_family, active_ingredient, unit_cost,
                    qty_last_7d, qty_last_14d, qty_last_30d, qty_last_90d, qty_last_365d,
                    avg_daily_7d, avg_daily_14d, avg_daily_30d, avg_daily_90d,
                    selling_days_30d, selling_days_90d,
                    trend_7d_vs_30d, trend_status,
                    abc_class, xyz_class, cv_value, abc_xyz_class,
                    health_score, profitability_score, volume_score, revenue_score,
                    stability_score, doi_score, strategic_score,
                    revenue_last_30d, revenue_last_90d, revenue_last_365d,
                    gp_last_30d, gp_last_90d, gp_last_365d, gp_margin_pct,
                    base_uom, base_uom_desc, order_uom, order_uom_desc, order_uom_rate, balance_in_order_uom,
                    current_balance, inventory_value, days_of_inventory, stockout_risk,
                    suggested_reorder_point, suggested_reorder_qty,
                    last_sale_date, first_sale_date, last_updated
                )
                WITH
                stock_balance AS (
                    SELECT sb."AcStockID" as stock_id,
                           SUM(sb."BalanceQuantity" * COALESCE(sc."StockUOMRate", 1)) as balance
                    FROM "AcStockBalanceLocation" sb
                    JOIN "AcStockCompany" sc ON sb."AcStockID" = sc."AcStockID"
                        AND sb."AcStockUOMID" = sc."AcStockUOMID"
                    GROUP BY sb."AcStockID"
                ),
                purchase_uom AS (
                    -- Get actual purchase UOM from PO history (most frequent)
                    SELECT DISTINCT ON (d."AcStockID")
                           d."AcStockID" as stock_id,
                           d."AcStockUOMID" as purchase_uom
                    FROM "AcSupPurchaseOrderD" d
                    GROUP BY d."AcStockID", d."AcStockUOMID"
                    ORDER BY d."AcStockID", COUNT(*) DESC
                ),
                purchase_uom_inv AS (
                    -- Fallback: Get from Supplier Invoice if no PO
                    SELECT DISTINCT ON (d."AcStockID")
                           d."AcStockID" as stock_id,
                           d."AcStockUOMID" as purchase_uom
                    FROM "AcSupInvoiceD" d
                    WHERE d."AcStockID" NOT IN (SELECT stock_id FROM purchase_uom)
                    GROUP BY d."AcStockID", d."AcStockUOMID"
                    ORDER BY d."AcStockID", COUNT(*) DESC
                ),
                order_uom AS (
                    -- Combine: PO history > Invoice history > Largest UOM
                    SELECT sc."AcStockID" as stock_id,
                           COALESCE(pu.purchase_uom, pui.purchase_uom, sc_max."AcStockUOMID") as order_uom,
                           COALESCE(sc_pu."StockUOMRate", sc_pui."StockUOMRate", sc_max."StockUOMRate", 1) as order_uom_rate,
                           COALESCE(sc_pu."StockDescription1", sc_pui."StockDescription1", sc_max."StockDescription1") as order_uom_desc
                    FROM "AcStockCompany" sc
                    LEFT JOIN purchase_uom pu ON sc."AcStockID" = pu.stock_id
                    LEFT JOIN purchase_uom_inv pui ON sc."AcStockID" = pui.stock_id
                    LEFT JOIN "AcStockCompany" sc_pu ON sc."AcStockID" = sc_pu."AcStockID" AND pu.purchase_uom = sc_pu."AcStockUOMID"
                    LEFT JOIN "AcStockCompany" sc_pui ON sc."AcStockID" = sc_pui."AcStockID" AND pui.purchase_uom = sc_pui."AcStockUOMID"
                    LEFT JOIN LATERAL (
                        SELECT "AcStockUOMID", "StockUOMRate", "StockDescription1"
                        FROM "AcStockCompany" sc2
                        WHERE sc2."AcStockID" = sc."AcStockID" AND sc2."StockIsActive" = 'Y'
                        ORDER BY "StockUOMRate" DESC LIMIT 1
                    ) sc_max ON TRUE
                    WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID" AND sc."StockIsActive" = 'Y'
                ),
                revenue_ranked AS (
                    SELECT stock_id, rev_365d,
                           SUM(rev_365d) OVER () as total_revenue,
                           SUM(rev_365d) OVER (ORDER BY rev_365d DESC) as cumulative_revenue
                    FROM wms.temp_sales_agg WHERE rev_365d > 0
                ),
                abc_class AS (
                    SELECT stock_id,
                           CASE WHEN cumulative_revenue / NULLIF(total_revenue, 0) <= 0.80 THEN 'A'
                                WHEN cumulative_revenue / NULLIF(total_revenue, 0) <= 0.95 THEN 'B' ELSE 'C' END as abc
                    FROM revenue_ranked
                )
                SELECT
                    sc."AcStockID", sc."StockDescription1", sc."StockBarcode",
                    cat."AcStockCategoryDesc", brand."AcStockBrandDesc", sc."AcStockUDGroup1ID",
                    sc."AcStockColorID", sc."AcStockColorID", sc."StockDescription2", sc."StockCost",
                    COALESCE(s.qty_7d, 0), COALESCE(s.qty_14d, 0), COALESCE(s.qty_30d, 0), COALESCE(s.qty_90d, 0), COALESCE(s.qty_365d, 0),
                    ROUND(COALESCE(s.qty_7d, 0) / 7.0, 2), ROUND(COALESCE(s.qty_14d, 0) / 14.0, 2),
                    ROUND(COALESCE(s.qty_30d, 0) / 30.0, 2), ROUND(COALESCE(s.qty_90d, 0) / 90.0, 2),
                    COALESCE(s.selling_days_30d, 0), COALESCE(s.selling_days_90d, 0),
                    CASE WHEN COALESCE(s.qty_30d, 0) > 0 THEN ROUND(((COALESCE(s.qty_7d, 0) / 7.0) - (COALESCE(s.qty_30d, 0) / 30.0)) / (COALESCE(s.qty_30d, 0) / 30.0) * 100, 1) ELSE NULL END,
                    CASE
                        WHEN COALESCE(s.qty_30d, 0) = 0 AND COALESCE(s.qty_90d, 0) = 0 THEN 'DEAD'
                        WHEN COALESCE(s.qty_7d, 0) / 7.0 > COALESCE(s.qty_30d, 0) / 30.0 * 1.5 THEN 'SPIKE_UP'
                        WHEN COALESCE(s.qty_7d, 0) / 7.0 > COALESCE(s.qty_30d, 0) / 30.0 * 1.2 THEN 'ACCELERATING'
                        WHEN COALESCE(s.qty_7d, 0) / 7.0 < COALESCE(s.qty_30d, 0) / 30.0 * 0.5 THEN 'SPIKE_DOWN'
                        WHEN COALESCE(s.qty_7d, 0) / 7.0 < COALESCE(s.qty_30d, 0) / 30.0 * 0.8 THEN 'DECELERATING'
                        ELSE 'STABLE'
                    END,
                    abc.abc,
                    CASE WHEN cv.cv < 0.5 THEN 'X' WHEN cv.cv <= 1.0 THEN 'Y' ELSE 'Z' END,
                    ROUND(cv.cv::numeric, 2),
                    CONCAT(abc.abc, CASE WHEN cv.cv < 0.5 THEN 'X' WHEN cv.cv <= 1.0 THEN 'Y' ELSE 'Z' END),
                    -- Health score
                    ROUND((
                        0.25 * LEAST(CASE WHEN COALESCE(s.rev_365d, 0) > 0 THEN COALESCE(s.gp_365d, 0) / s.rev_365d * 100 / 60 * 100 ELSE 0 END, 100) +
                        0.20 * COALESCE(s.qty_365d, 0) / {max_vals['max_qty']} * 100 +
                        0.20 * COALESCE(s.rev_365d, 0) / {max_vals['max_rev']} * 100 +
                        0.15 * LEAST((1 - COALESCE(cv.cv, 1)) * 100, 100) +
                        0.10 * GREATEST(100 - COALESCE(sb.balance, 0) / NULLIF(COALESCE(s.qty_30d, 0) / 30.0, 0) / 90 * 100, 0) +
                        0.10 * CASE WHEN sc."AcStockUDGroup1ID" IN ('FLTHB', 'FLTF1') THEN 100 WHEN sc."AcStockUDGroup1ID" = 'FLTMH' THEN 80 WHEN sc."AcStockUDGroup1ID" = 'FLTF2' THEN 70 WHEN sc."AcStockUDGroup1ID" = 'FLTF3' THEN 60 ELSE 50 END
                    )::numeric, 1),
                    -- Component scores
                    ROUND(LEAST(CASE WHEN COALESCE(s.rev_365d, 0) > 0 THEN COALESCE(s.gp_365d, 0) / s.rev_365d * 100 / 60 * 100 ELSE 0 END, 100), 1),
                    ROUND(COALESCE(s.qty_365d, 0) / {max_vals['max_qty']} * 100, 1),
                    ROUND(COALESCE(s.rev_365d, 0) / {max_vals['max_rev']} * 100, 1),
                    ROUND(LEAST((1 - COALESCE(cv.cv, 1)) * 100, 100), 1),
                    ROUND(GREATEST(100 - COALESCE(sb.balance, 0) / NULLIF(COALESCE(s.qty_30d, 0) / 30.0, 0) / 90 * 100, 0), 1),
                    CASE WHEN sc."AcStockUDGroup1ID" IN ('FLTHB', 'FLTF1') THEN 100 WHEN sc."AcStockUDGroup1ID" = 'FLTMH' THEN 80 WHEN sc."AcStockUDGroup1ID" = 'FLTF2' THEN 70 WHEN sc."AcStockUDGroup1ID" = 'FLTF3' THEN 60 ELSE 50 END,
                    -- Revenue & GP
                    ROUND(COALESCE(s.rev_30d, 0)::numeric, 2), ROUND(COALESCE(s.rev_90d, 0)::numeric, 2), ROUND(COALESCE(s.rev_365d, 0)::numeric, 2),
                    ROUND(COALESCE(s.gp_30d, 0)::numeric, 2), ROUND(COALESCE(s.gp_90d, 0)::numeric, 2), ROUND(COALESCE(s.gp_365d, 0)::numeric, 2),
                    ROUND(CASE WHEN COALESCE(s.rev_365d, 0) > 0 THEN COALESCE(s.gp_365d, 0) / s.rev_365d * 100 ELSE 0 END::numeric, 1),
                    -- UOM info for purchasing
                    sc."AcStockUOMIDBaseID",
                    sc."StockDescription1",
                    COALESCE(ou.order_uom, sc."AcStockUOMIDBaseID"),
                    COALESCE(ou.order_uom_desc, sc."StockDescription1"),
                    COALESCE(ou.order_uom_rate, 1),
                    ROUND(COALESCE(sb.balance, 0) / COALESCE(ou.order_uom_rate, 1), 0),
                    -- Inventory
                    COALESCE(sb.balance, 0), ROUND((COALESCE(sb.balance, 0) * COALESCE(sc."StockCost", 0))::numeric, 2),
                    ROUND(CASE WHEN COALESCE(s.qty_30d, 0) / 30.0 > 0 THEN COALESCE(sb.balance, 0) / (COALESCE(s.qty_30d, 0) / 30.0) ELSE 9999 END::numeric, 0),
                    CASE
                        WHEN COALESCE(sb.balance, 0) <= 0 THEN 'STOCKOUT'
                        WHEN COALESCE(s.qty_30d, 0) / 30.0 > 0 AND COALESCE(sb.balance, 0) / (COALESCE(s.qty_30d, 0) / 30.0) <= 7 THEN 'CRITICAL'
                        WHEN COALESCE(s.qty_30d, 0) / 30.0 > 0 AND COALESCE(sb.balance, 0) / (COALESCE(s.qty_30d, 0) / 30.0) <= 14 THEN 'WARNING'
                        WHEN COALESCE(s.qty_30d, 0) / 30.0 > 0 AND COALESCE(sb.balance, 0) / (COALESCE(s.qty_30d, 0) / 30.0) <= 45 THEN 'OK'
                        WHEN COALESCE(s.qty_30d, 0) / 30.0 > 0 AND COALESCE(sb.balance, 0) / (COALESCE(s.qty_30d, 0) / 30.0) > 90 THEN 'OVERSTOCKED'
                        ELSE 'UNKNOWN'
                    END,
                    -- Reorder suggestions (in ordering UOM)
                    ROUND((COALESCE(s.qty_30d, 0) / 30.0 * 14 * 1.5) / COALESCE(ou.order_uom_rate, 1), 0),
                    ROUND((COALESCE(s.qty_30d, 0) / 30.0 * 30) / COALESCE(ou.order_uom_rate, 1), 0),
                    s.last_sale, s.first_sale, CURRENT_TIMESTAMP
                FROM "AcStockCompany" sc
                LEFT JOIN wms.temp_sales_agg s ON sc."AcStockID" = s.stock_id
                LEFT JOIN wms.temp_cv cv ON sc."AcStockID" = cv.stock_id
                LEFT JOIN stock_balance sb ON sc."AcStockID" = sb.stock_id
                LEFT JOIN order_uom ou ON sc."AcStockID" = ou.stock_id
                LEFT JOIN abc_class abc ON sc."AcStockID" = abc.stock_id
                LEFT JOIN "AcStockCategory" cat ON sc."AcStockCategoryID" = cat."AcStockCategoryID"
                LEFT JOIN "AcStockBrand" brand ON sc."AcStockBrandID" = brand."AcStockBrandID"
                WHERE sc."AcStockUOMID" = sc."AcStockUOMIDBaseID" AND sc."StockIsActive" = 'Y'
            """)
            steps_completed.append("insert")

            # Get summary
            summary = await conn.fetchrow("""
                SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE trend_status = 'SPIKE_UP') as spike_up,
                       COUNT(*) FILTER (WHERE trend_status = 'SPIKE_DOWN') as spike_down,
                       COUNT(*) FILTER (WHERE stockout_risk = 'CRITICAL') as critical,
                       COUNT(*) FILTER (WHERE stockout_risk = 'WARNING') as warning
                FROM wms.stock_movement_summary
            """)

            elapsed = (datetime.now() - start_time).total_seconds()

            return {
                "status": "success",
                "refresh_time_seconds": round(elapsed, 2),
                "summary": {
                    "total_skus": summary['total'],
                    "spike_up": summary['spike_up'],
                    "spike_down": summary['spike_down'],
                    "stockout_critical": summary['critical'],
                    "stockout_warning": summary['warning']
                }
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stock-movement/view")
async def view_stock_movement(
    trend_status: Optional[str] = Query(None, description="Filter by trend: SPIKE_UP, SPIKE_DOWN, ACCELERATING, DECELERATING, STABLE, DEAD"),
    stockout_risk: Optional[str] = Query(None, description="Filter by risk: CRITICAL, WARNING, OK, OVERSTOCKED, STOCKOUT"),
    abc_class: Optional[str] = Query(None, description="Filter by ABC class: A, B, C"),
    ud1_code: Optional[str] = Query(None, description="Filter by UD1 code"),
    limit: int = Query(50),
    api_key: str = Query(...)
):
    """View stock movement summary data."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            filters = []
            params = []
            param_idx = 1

            if trend_status:
                filters.append(f"trend_status = ${param_idx}")
                params.append(trend_status)
                param_idx += 1
            if stockout_risk:
                filters.append(f"stockout_risk = ${param_idx}")
                params.append(stockout_risk)
                param_idx += 1
            if abc_class:
                filters.append(f"abc_class = ${param_idx}")
                params.append(abc_class)
                param_idx += 1
            if ud1_code:
                filters.append(f"ud1_code = ${param_idx}")
                params.append(ud1_code)
                param_idx += 1

            where_clause = " AND ".join(filters) if filters else "1=1"
            params.append(limit)

            query = f"""
                SELECT stock_id, stock_name, barcode, ud1_code, abc_xyz_class,
                       qty_last_7d, qty_last_30d, avg_daily_30d, trend_status, trend_7d_vs_30d,
                       health_score, gp_margin_pct,
                       base_uom, base_uom_desc, order_uom, order_uom_desc, order_uom_rate, balance_in_order_uom,
                       current_balance, days_of_inventory, stockout_risk,
                       suggested_reorder_qty, reorder_point, target_doi,
                       revenue_last_30d, therapeutic_group,
                       ams_3m, velocity_category, lead_time_category, lead_time_days,
                       seasonality_type, seasonal_peak_trough_ratio, peak_months,
                       reorder_recommendation,
                       qty_m1, qty_m2, qty_m3, qty_m4, qty_m5, qty_m6,
                       qty_m7, qty_m8, qty_m9, qty_m10, qty_m11, qty_m12
                FROM wms.stock_movement_summary
                WHERE {where_clause}
                ORDER BY revenue_last_30d DESC NULLS LAST
                LIMIT ${param_idx}
            """

            rows = await conn.fetch(query, *params)

            return {
                "generated_at": datetime.now().isoformat(),
                "filters": {"trend_status": trend_status, "stockout_risk": stockout_risk, "abc_class": abc_class, "ud1_code": ud1_code},
                "count": len(rows),
                "data": [dict(r) for r in rows]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/stock-movement/analyze-monthly")
async def analyze_monthly_movement(api_key: str = Query(...)):
    """Analyze monthly movement patterns, calculate seasonality, and update recommendations.

    This endpoint:
    1. Calculates monthly sales for each SKU (last 12 months)
    2. Calculates 3-month AMS (Average Monthly Sellout)
    3. Identifies seasonality based on peak/trough ratio
    4. Sets velocity category (FAST/MEDIUM/SLOW/DEAD)
    5. Sets lead time category (LONG for HB, STANDARD for others)
    6. Calculates smart reorder recommendations
    """
    verify_api_key(api_key)

    try:
        start_time = datetime.now()

        async with pool.acquire() as conn:
            # Step 1: Calculate monthly sales for last 12 months
            # Use AcStockBalanceDetail (already indexed) instead of raw AcCSD/AcCusInvoiceD tables
            # M1 = current month, M12 = 12 months ago
            # IMPORTANT: Use RootUomQuantityOut which is already converted to BASE UOM
            # This ensures all UOMs (sachets, boxes, twin-packs) are normalized
            # Set 5 minute timeout for this heavy query
            await conn.execute("""
                WITH monthly_sales AS (
                    SELECT
                        "AcStockID" as stock_id,
                        DATE_TRUNC('month', "DocumentDate") as sale_month,
                        SUM("RootUomQuantityOut") as qty
                    FROM "AcStockBalanceDetail"
                    WHERE "DocumentDate" >= DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '12 months'
                      AND "DocumentType" IN ('CUS_CASH_SALES', 'CUS_INVOICE')
                    GROUP BY "AcStockID", DATE_TRUNC('month', "DocumentDate")
                ),
                pivoted AS (
                    SELECT
                        stock_id,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) THEN qty ELSE 0 END) as m1,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '1 month' THEN qty ELSE 0 END) as m2,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '2 months' THEN qty ELSE 0 END) as m3,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '3 months' THEN qty ELSE 0 END) as m4,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '4 months' THEN qty ELSE 0 END) as m5,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '5 months' THEN qty ELSE 0 END) as m6,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '6 months' THEN qty ELSE 0 END) as m7,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '7 months' THEN qty ELSE 0 END) as m8,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '8 months' THEN qty ELSE 0 END) as m9,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '9 months' THEN qty ELSE 0 END) as m10,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '10 months' THEN qty ELSE 0 END) as m11,
                        MAX(CASE WHEN sale_month = DATE_TRUNC('month', CURRENT_DATE) - INTERVAL '11 months' THEN qty ELSE 0 END) as m12
                    FROM monthly_sales
                    GROUP BY stock_id
                )
                UPDATE wms.stock_movement_summary sms
                SET
                    qty_m1 = COALESCE(p.m1, 0),
                    qty_m2 = COALESCE(p.m2, 0),
                    qty_m3 = COALESCE(p.m3, 0),
                    qty_m4 = COALESCE(p.m4, 0),
                    qty_m5 = COALESCE(p.m5, 0),
                    qty_m6 = COALESCE(p.m6, 0),
                    qty_m7 = COALESCE(p.m7, 0),
                    qty_m8 = COALESCE(p.m8, 0),
                    qty_m9 = COALESCE(p.m9, 0),
                    qty_m10 = COALESCE(p.m10, 0),
                    qty_m11 = COALESCE(p.m11, 0),
                    qty_m12 = COALESCE(p.m12, 0),
                    -- 3-Month AMS (use M2, M3, M4 to avoid partial current month)
                    ams_3m = ROUND((COALESCE(p.m2, 0) + COALESCE(p.m3, 0) + COALESCE(p.m4, 0)) / 3.0, 2)
                FROM pivoted p
                WHERE sms.stock_id = p.stock_id
            """, timeout=300)  # 5 minute timeout for heavy query

            # Step 2: Calculate seasonality using all 12 months
            await conn.execute("""
                UPDATE wms.stock_movement_summary
                SET
                    seasonal_peak_trough_ratio = CASE
                        WHEN LEAST(qty_m1, qty_m2, qty_m3, qty_m4, qty_m5, qty_m6,
                                   qty_m7, qty_m8, qty_m9, qty_m10, qty_m11, qty_m12) > 0
                        THEN ROUND(
                            GREATEST(qty_m1, qty_m2, qty_m3, qty_m4, qty_m5, qty_m6,
                                     qty_m7, qty_m8, qty_m9, qty_m10, qty_m11, qty_m12)::numeric /
                            LEAST(qty_m1, qty_m2, qty_m3, qty_m4, qty_m5, qty_m6,
                                  qty_m7, qty_m8, qty_m9, qty_m10, qty_m11, qty_m12)::numeric, 2)
                        ELSE NULL
                    END,
                    seasonality_type = CASE
                        WHEN ams_3m = 0 OR ams_3m IS NULL THEN 'DEAD'
                        -- Use CV (coefficient of variation) which is more robust than peak/trough
                        -- CV > 0.8 = high variability (erratic/seasonal), CV 0.5-0.8 = moderate, CV < 0.5 = stable
                        WHEN cv_value > 0.8 AND seasonal_peak_trough_ratio > 5.0 THEN 'HIGHLY_SEASONAL'
                        WHEN cv_value > 0.5 OR (seasonal_peak_trough_ratio IS NOT NULL AND seasonal_peak_trough_ratio > 2.0) THEN 'MODERATELY_SEASONAL'
                        ELSE 'STABLE'
                    END
            """)

            # Step 3: Set velocity category based on AMS
            await conn.execute("""
                UPDATE wms.stock_movement_summary
                SET velocity_category = CASE
                    WHEN ams_3m >= 300 THEN 'FAST'       -- 10+ per day
                    WHEN ams_3m >= 30 THEN 'MEDIUM'     -- 1-10 per day
                    WHEN ams_3m > 0 THEN 'SLOW'         -- <1 per day
                    ELSE 'DEAD'
                END
            """)

            # Step 4: Set lead time category based on UD1
            await conn.execute("""
                UPDATE wms.stock_movement_summary
                SET
                    lead_time_category = CASE
                        WHEN ud1_code = 'FLTHB' THEN 'LONG'
                        ELSE 'STANDARD'
                    END,
                    lead_time_days = CASE
                        WHEN ud1_code = 'FLTHB' THEN 90   -- House Brand: 3 months
                        ELSE 14                           -- Standard: 2 weeks
                    END
            """)

            # Step 5: Set target DOI based on ABC class and lead time
            await conn.execute("""
                UPDATE wms.stock_movement_summary
                SET target_doi = CASE
                    WHEN ud1_code = 'FLTHB' THEN 120      -- House Brand: 4 months (2-4 month lead time + safety)
                    WHEN ud1_code = 'FLTF1' THEN 100      -- Focused Item 1: Similar lead time
                    WHEN abc_class = 'A' THEN 60          -- Class A: 60 days (frequent replenishment)
                    WHEN abc_class = 'B' THEN 75          -- Class B: 75 days
                    ELSE 90                                -- Class C: 90 days
                END
            """)

            # Step 6: Calculate reorder point
            await conn.execute("""
                UPDATE wms.stock_movement_summary
                SET reorder_point = ROUND(
                    (lead_time_days + 7) * (ams_3m / 30.0), 0  -- Lead time + 7 days safety * daily rate
                )
                WHERE ams_3m > 0
            """)

            # Step 7: Calculate trend 7d vs AMS (better than 7d vs 30d)
            # Uses last_7d_qty / 7 as daily rate, compared to AMS daily rate (ams_3m / 30)
            # Note: This is also updated every 60 seconds by the sync service hook
            await conn.execute("""
                UPDATE wms.stock_movement_summary
                SET
                    trend_7d_vs_ams = CASE
                        WHEN ams_3m > 0 AND last_7d_qty IS NOT NULL THEN ROUND(
                            (((COALESCE(last_7d_qty, 0) / 7.0) - (ams_3m / 30.0)) / (ams_3m / 30.0)) * 100, 1
                        )
                        ELSE NULL
                    END
            """)

            # Step 8: Calculate smart reorder recommendation
            await conn.execute("""
                UPDATE wms.stock_movement_summary
                SET reorder_recommendation = CASE
                    WHEN current_balance <= 0 THEN 'STOCKOUT'
                    WHEN velocity_category = 'DEAD' AND abc_class = 'C' THEN 'DELIST_CANDIDATE'
                    WHEN velocity_category = 'DEAD' THEN 'REVIEW'
                    WHEN current_balance < COALESCE(reorder_point, 0) THEN 'ORDER_NOW'
                    WHEN current_balance < COALESCE(reorder_point, 0) * 1.5 THEN 'ORDER_SOON'
                    WHEN days_of_inventory > COALESCE(target_doi, 90) * 2 THEN 'STOP_ORDERING'
                    WHEN days_of_inventory > COALESCE(target_doi, 90) THEN 'REDUCE_ORDER'
                    ELSE 'HOLD'
                END
            """)

            # Step 9: Get UOM descriptions (base UOM only - simpler and faster)
            await conn.execute("""
                UPDATE wms.stock_movement_summary sms
                SET
                    base_uom_desc = u."AcStockUOMDesc"
                FROM "AcStockUOM" u
                WHERE sms.base_uom = u."AcStockUOMID"
            """)

            # Get summary stats
            summary = await conn.fetchrow("""
                SELECT
                    COUNT(*) FILTER (WHERE seasonality_type = 'HIGHLY_SEASONAL') as highly_seasonal,
                    COUNT(*) FILTER (WHERE seasonality_type = 'MODERATELY_SEASONAL') as moderately_seasonal,
                    COUNT(*) FILTER (WHERE seasonality_type = 'STABLE') as stable,
                    COUNT(*) FILTER (WHERE seasonality_type = 'DEAD') as dead,
                    COUNT(*) FILTER (WHERE velocity_category = 'FAST') as fast,
                    COUNT(*) FILTER (WHERE velocity_category = 'MEDIUM') as medium,
                    COUNT(*) FILTER (WHERE velocity_category = 'SLOW') as slow,
                    COUNT(*) FILTER (WHERE reorder_recommendation = 'ORDER_NOW') as order_now,
                    COUNT(*) FILTER (WHERE reorder_recommendation = 'ORDER_SOON') as order_soon,
                    COUNT(*) FILTER (WHERE reorder_recommendation = 'STOP_ORDERING') as stop_ordering,
                    COUNT(*) FILTER (WHERE reorder_recommendation = 'DELIST_CANDIDATE') as delist_candidates,
                    COUNT(*) FILTER (WHERE trend_7d_vs_ams > 50) as trend_spike,
                    COUNT(*) FILTER (WHERE trend_7d_vs_ams > 30 AND trend_7d_vs_ams <= 50) as trend_rising,
                    COUNT(*) FILTER (WHERE trend_7d_vs_ams >= -30 AND trend_7d_vs_ams <= 30) as trend_stable,
                    COUNT(*) FILTER (WHERE trend_7d_vs_ams < -30 AND trend_7d_vs_ams >= -50) as trend_declining,
                    COUNT(*) FILTER (WHERE trend_7d_vs_ams < -50) as trend_dropping
                FROM wms.stock_movement_summary
            """)

            elapsed = (datetime.now() - start_time).total_seconds()

            return {
                "status": "success",
                "analysis_time_seconds": round(elapsed, 2),
                "seasonality": {
                    "highly_seasonal": summary['highly_seasonal'],
                    "moderately_seasonal": summary['moderately_seasonal'],
                    "stable": summary['stable'],
                    "dead": summary['dead']
                },
                "velocity": {
                    "fast": summary['fast'],
                    "medium": summary['medium'],
                    "slow": summary['slow']
                },
                "trend_vs_ams": {
                    "spike": summary['trend_spike'],
                    "rising": summary['trend_rising'],
                    "stable": summary['trend_stable'],
                    "declining": summary['trend_declining'],
                    "dropping": summary['trend_dropping']
                },
                "recommendations": {
                    "order_now": summary['order_now'],
                    "order_soon": summary['order_soon'],
                    "stop_ordering": summary['stop_ordering'],
                    "delist_candidates": summary['delist_candidates']
                }
            }
    except Exception as e:
        import traceback
        error_detail = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail)


# ============================================================================
# ANALYTICS VIEWS - Built on Existing AcStockBalanceDetail
# ============================================================================
# Uses existing AcStockBalanceDetail (25M rows, already synced) as source.
# Creates views for analytics without duplicating data.
# Enhances wms.stock_movement_summary with monthly columns.
# ============================================================================

@app.post("/api/v1/analytics/setup")
async def setup_analytics(api_key: str = Query(...)):
    """
    Create analytics views on existing AcStockBalanceDetail.
    Add monthly columns to wms.stock_movement_summary.

    No data duplication - uses existing synced tables.
    """
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # Create schema
            await conn.execute("CREATE SCHEMA IF NOT EXISTS analytics")

            # Add monthly columns to existing wms.stock_movement_summary
            await conn.execute("""
                DO $$
                BEGIN
                    -- Monthly movement columns (last 12 months)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='qty_m1') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m1 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m2 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m3 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m4 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m5 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m6 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m7 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m8 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m9 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m10 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m11 NUMERIC DEFAULT 0;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN qty_m12 NUMERIC DEFAULT 0;
                    END IF;
                    -- 3-Month Average Monthly Sellout (AMS)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='ams_3m') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN ams_3m NUMERIC DEFAULT 0;
                    END IF;
                    -- Seasonality classification
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='seasonality_type') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN seasonality_type VARCHAR(30) DEFAULT 'UNKNOWN';
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN seasonal_peak_trough_ratio NUMERIC;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN peak_months VARCHAR(30);
                    END IF;
                    -- Velocity category
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='velocity_category') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN velocity_category VARCHAR(20) DEFAULT 'UNKNOWN';
                    END IF;
                    -- Lead time category
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='lead_time_category') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN lead_time_category VARCHAR(20) DEFAULT 'STANDARD';
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN lead_time_days INTEGER DEFAULT 14;
                    END IF;
                    -- Smart reorder recommendation
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='reorder_recommendation') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN reorder_recommendation VARCHAR(30) DEFAULT 'UNKNOWN';
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN target_doi INTEGER;
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN reorder_point NUMERIC;
                    END IF;
                    -- 7-day rolling quantity (for real-time trend detection)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='last_7d_qty') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN last_7d_qty NUMERIC DEFAULT 0;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='last_sale_date') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN last_sale_date DATE;
                    END IF;
                    -- Trend vs AMS
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='trend_7d_vs_ams') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN trend_7d_vs_ams NUMERIC;
                    END IF;
                    -- UOM descriptions
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='base_uom_desc') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN base_uom_desc VARCHAR(50);
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN order_uom_desc VARCHAR(50);
                    END IF;
                    -- Product Family (from Colour ID)
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='wms' AND table_name='stock_movement_summary' AND column_name='product_family') THEN
                        ALTER TABLE wms.stock_movement_summary ADD COLUMN product_family VARCHAR(100);
                    END IF;
                END $$;
            """)

            # Create indexes on wms.stock_movement_summary for new columns
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_wms_seasonality ON wms.stock_movement_summary(seasonality_type)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_wms_velocity ON wms.stock_movement_summary(velocity_category)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_wms_recommendation ON wms.stock_movement_summary(reorder_recommendation)")

            # Create view on AcStockBalanceDetail for monthly sales analysis
            await conn.execute("""
                CREATE OR REPLACE VIEW analytics.v_monthly_sales AS
                SELECT
                    sbd."AcStockID" as stock_id,
                    sbd."AcStockUOMID" as stock_uom_id,
                    DATE_TRUNC('month', sbd."DocumentDate")::date as sale_month,
                    SUM(sbd."QuantityOut") as total_quantity,
                    SUM(sbd."QuantityOut" * sbd."ItemUnitPrice") as total_revenue,
                    COUNT(DISTINCT sbd."AcLocationID") as outlets_sold
                FROM "AcStockBalanceDetail" sbd
                WHERE sbd."DocumentType" IN ('CUS_CASH_SALES', 'CUS_INVOICE')
                  AND sbd."DocumentDate" >= CURRENT_DATE - INTERVAL '24 months'
                GROUP BY sbd."AcStockID", sbd."AcStockUOMID", DATE_TRUNC('month', sbd."DocumentDate")
            """)

            # Create view for SKU intelligence from wms.stock_movement_summary
            await conn.execute("""
                CREATE OR REPLACE VIEW analytics.v_sku_intelligence AS
                SELECT
                    stock_id,
                    stock_name,
                    barcode,
                    category,
                    brand,
                    ud1_code,
                    abc_class,
                    xyz_class,
                    abc_xyz_class,
                    cv_value,
                    gp_margin_pct as margin_pct,
                    CASE
                        WHEN gp_margin_pct < 15 THEN 'LOW_MARGIN'
                        WHEN gp_margin_pct < 30 THEN 'MEDIUM_MARGIN'
                        WHEN gp_margin_pct < 45 THEN 'GOOD_MARGIN'
                        ELSE 'HIGH_MARGIN'
                    END as margin_category,
                    revenue_last_365d as l12m_revenue,
                    qty_last_365d as l12m_quantity,
                    gp_last_365d as l12m_gross_profit,
                    revenue_last_90d as l3m_revenue,
                    qty_last_90d as l3m_quantity,
                    avg_daily_30d,
                    current_balance as current_stock_qty,
                    days_of_inventory as days_of_stock,
                    stockout_risk as stock_status,
                    trend_status as sales_trend,
                    trend_7d_vs_30d as trend_pct,
                    ams_3m,
                    seasonality_type,
                    velocity_category,
                    lead_time_category,
                    reorder_recommendation as recommended_action,
                    CASE WHEN ud1_code = 'FLTHB' THEN TRUE ELSE FALSE END as is_house_brand,
                    last_updated
                FROM wms.stock_movement_summary
            """)

            return {
                "status": "success",
                "message": "Analytics setup complete - columns added to wms.stock_movement_summary, views created",
                "columns_added": ["qty_m1-m12", "ams_3m", "seasonality_type", "velocity_category", "lead_time_category", "reorder_recommendation"],
                "views_created": ["analytics.v_monthly_sales", "analytics.v_sku_intelligence"]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/analytics/sku-intelligence")
async def get_sku_intelligence(
    api_key: str = Query(...),
    abc_class: Optional[str] = Query(default=None, description="Filter by ABC class: A, B, C"),
    xyz_class: Optional[str] = Query(default=None, description="Filter by XYZ class: X, Y, Z"),
    margin_category: Optional[str] = Query(default=None, description="LOW_MARGIN, MEDIUM_MARGIN, GOOD_MARGIN, HIGH_MARGIN"),
    stock_status: Optional[str] = Query(default=None, description="STOCKOUT, LOW, OK, OVERSTOCKED"),
    seasonality: Optional[str] = Query(default=None, description="HIGHLY_SEASONAL, MODERATELY_SEASONAL, STABLE, DEAD"),
    ud1_code: Optional[str] = Query(default=None, description="Filter by UD1 (e.g., FLTHB for House Brand)"),
    search: Optional[str] = Query(default=None, description="Search by stock code or name"),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0)
):
    """Query SKU intelligence from wms.stock_movement_summary."""
    verify_api_key(api_key)

    try:
        async with pool.acquire() as conn:
            # Build WHERE clause
            conditions = []
            params = []
            param_idx = 1

            if abc_class:
                conditions.append(f"abc_class = ${param_idx}")
                params.append(abc_class)
                param_idx += 1

            if xyz_class:
                conditions.append(f"xyz_class = ${param_idx}")
                params.append(xyz_class)
                param_idx += 1

            if margin_category:
                margin_ranges = {
                    'LOW_MARGIN': (0, 15),
                    'MEDIUM_MARGIN': (15, 30),
                    'GOOD_MARGIN': (30, 45),
                    'HIGH_MARGIN': (45, 100)
                }
                if margin_category in margin_ranges:
                    low, high = margin_ranges[margin_category]
                    conditions.append(f"gp_margin_pct >= ${param_idx} AND gp_margin_pct < ${param_idx + 1}")
                    params.extend([low, high])
                    param_idx += 2

            if stock_status:
                conditions.append(f"stockout_risk = ${param_idx}")
                params.append(stock_status)
                param_idx += 1

            if seasonality:
                conditions.append(f"seasonality_type = ${param_idx}")
                params.append(seasonality)
                param_idx += 1

            if ud1_code:
                conditions.append(f"ud1_code = ${param_idx}")
                params.append(ud1_code)
                param_idx += 1

            if search:
                conditions.append(f"(stock_id ILIKE ${param_idx} OR stock_name ILIKE ${param_idx} OR barcode ILIKE ${param_idx})")
                params.append(f"%{search}%")
                param_idx += 1

            where_clause = " AND ".join(conditions) if conditions else "TRUE"

            # Add limit and offset
            params.extend([limit, offset])

            query = f"""
                SELECT
                    stock_id, stock_name, barcode, category, brand, ud1_code,
                    abc_class, xyz_class, abc_xyz_class, cv_value,
                    gp_margin_pct, revenue_last_365d, qty_last_365d, gp_last_365d,
                    revenue_last_90d, qty_last_90d, avg_daily_30d,
                    current_balance, days_of_inventory, stockout_risk,
                    trend_status, trend_7d_vs_30d,
                    ams_3m, seasonality_type, velocity_category,
                    lead_time_category, reorder_recommendation,
                    last_updated,
                    -- UOM info for display
                    order_uom, order_uom_desc, order_uom_rate, base_uom, base_uom_desc,
                    balance_in_order_uom,
                    -- Quantities converted to ORDER UOM for meaningful display
                    ROUND(COALESCE(ams_3m, 0) / NULLIF(COALESCE(order_uom_rate, 1), 0), 1) as ams_3m_order,
                    ROUND(COALESCE(qty_last_30d, 0) / NULLIF(COALESCE(order_uom_rate, 1), 0), 1) as qty_last_30d_order,
                    ROUND(COALESCE(qty_last_90d, 0) / NULLIF(COALESCE(order_uom_rate, 1), 0), 1) as qty_last_90d_order,
                    ROUND(COALESCE(qty_last_365d, 0) / NULLIF(COALESCE(order_uom_rate, 1), 0), 1) as qty_last_365d_order
                FROM wms.stock_movement_summary
                WHERE {where_clause}
                ORDER BY revenue_last_365d DESC NULLS LAST
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """

            rows = await conn.fetch(query, *params)

            # Get total count
            count_query = f"SELECT COUNT(*) FROM wms.stock_movement_summary WHERE {where_clause}"
            total = await conn.fetchval(count_query, *params[:-2]) if params[:-2] else await conn.fetchval("SELECT COUNT(*) FROM wms.stock_movement_summary")

            return {
                "status": "success",
                "total": total,
                "limit": limit,
                "offset": offset,
                "data": [dict(row) for row in rows]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
