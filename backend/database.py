import os
import psycopg2
import psycopg2.extras
from typing import Optional, List, Any
from datetime import datetime, timezone
from backend.config import DATABASE_URL

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class DBWrapper:
    def __init__(self, raw_con):
        self.raw_con = raw_con

    def execute(self, sql: str, args: tuple = ()) -> psycopg2.extensions.cursor:
        # Convert SQLite placeholders (?) to Postgres placeholders (%s)
        pg_sql = sql.replace("?", "%s")
        
        cur = self.raw_con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute(pg_sql, args)
        except Exception as e:
            print(f"SQL Error: {e} | Query: {pg_sql} | Args: {args}")
            raise e
        return cur

    def commit(self):
        self.raw_con.commit()

    def close(self):
        self.raw_con.close()

def db():
    if not DATABASE_URL:
        # Prevent silent failure
        raise Exception("DATABASE_URL environment variable is not set. Required for PostgreSQL.")
        
    con = psycopg2.connect(DATABASE_URL)
    return DBWrapper(con)

def init_db() -> None:
    if not DATABASE_URL:
        print("Skipping init_db: DATABASE_URL missing")
        return
        
    try:
        con = db()
    except:
        # Often fails during build phase if env vars aren't present yet, that's fine
        return 

    # 1. Users
    con.execute("""
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          phone TEXT UNIQUE NOT NULL,
          name TEXT DEFAULT '',
          token TEXT UNIQUE NOT NULL,
          created_at TEXT NOT NULL,
          last_login_at TEXT NOT NULL,
          pin_hash TEXT DEFAULT '',
          last_bunk TEXT,
          last_fuel_type TEXT,
          last_amount TEXT,
          last_vehicle_type TEXT,
          last_vehicle_no TEXT
        );
    """)
    
    # 2. Vehicles
    con.execute("""
        CREATE TABLE IF NOT EXISTS vehicles (
          id SERIAL PRIMARY KEY,
          user_phone TEXT NOT NULL,
          vehicle_type TEXT NOT NULL,
          vehicle_no TEXT NOT NULL,
          is_default INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          UNIQUE(user_phone, vehicle_type, vehicle_no)
        );
    """)
    
    # 3. Vouchers
    con.execute("""
        CREATE TABLE IF NOT EXISTS vouchers (
          id TEXT PRIMARY KEY,
          user_phone TEXT,
          user_name TEXT,
          bunk_id TEXT NOT NULL,
          fuel_type TEXT NOT NULL,
          amount REAL DEFAULT 0,
          litres REAL DEFAULT 0,
          payment_method TEXT NOT NULL,
          vehicle_type TEXT,
          vehicle_no TEXT,
          status TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
    """)
    
    # 4. Devices
    # Added id SERIAL for compatibility with frontend that expects numeric ID
    con.execute("""
        CREATE TABLE IF NOT EXISTS devices (
          id SERIAL UNIQUE,
          device_token TEXT PRIMARY KEY,
          bunk_id TEXT NOT NULL,
          name TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_seen_at TEXT,
          revoked INTEGER DEFAULT 0
        );
    """)
    
    con.commit()
    con.close()

def one(cur) -> Optional[dict]:
    return cur.fetchone()

def rows(cur) -> List[dict]:
    return cur.fetchall()
