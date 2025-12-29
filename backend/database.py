import sqlite3
from typing import Optional, List
from datetime import datetime, timezone
from backend.config import DB_PATH

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db() -> None:
    con = db()
    # Enable WAL mode for better concurrency on persistent volumes
    con.execute("PRAGMA journal_mode=WAL;")
    cur = con.cursor()

    # Users
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          phone TEXT UNIQUE NOT NULL,
          name TEXT DEFAULT '',
          token TEXT UNIQUE NOT NULL,
          created_at TEXT NOT NULL,
          last_login_at TEXT NOT NULL
        );
        """
    )
    
    # Check for pin_hash column (migration for existing db)
    existing_cols = []
    try:
        cur.execute("PRAGMA table_info(users)")
        existing_cols = [row["name"] for row in cur.fetchall()]
    except:
        pass

    if "pin_hash" not in existing_cols:
        try: cur.execute("ALTER TABLE users ADD COLUMN pin_hash TEXT DEFAULT ''")
        except: pass
    
    # Add preference columns if missing
    for col in ["last_bunk", "last_fuel_type", "last_amount", "last_vehicle_type", "last_vehicle_no"]:
        if col not in existing_cols:
            try: cur.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
            except: pass

    # Vehicles (per user)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vehicles (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_phone TEXT NOT NULL,
          vehicle_type TEXT NOT NULL,
          vehicle_no TEXT NOT NULL,
          is_default INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          UNIQUE(user_phone, vehicle_type, vehicle_no)
        );
        """
    )

    # Vouchers
    cur.execute(
        """
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
        """
    )

    # Devices (attendant phones)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
          device_token TEXT PRIMARY KEY,
          bunk_id TEXT NOT NULL,
          name TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_seen_at TEXT
        );
        """
    )

    con.commit()
    con.close()

def one(cur: sqlite3.Cursor) -> Optional[sqlite3.Row]:
    return cur.fetchone()

def rows(cur: sqlite3.Cursor) -> List[sqlite3.Row]:
    return cur.fetchall()
