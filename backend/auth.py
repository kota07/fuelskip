from datetime import datetime, timezone
import hashlib
import sqlite3
from typing import Optional

from fastapi import HTTPException, Header, Depends
from backend.database import db, one, now_iso  # Need to add now_iso to database.py or utils? Let's add it to auth for now or both. 
# actually now_iso was in main.py. I should put it in a utils or just here. I'll put it in database for reusability or a new utils.
# Let's put now_iso in backend/config.py or database.py. Ideally database.py as it is used for DB timestamps.

from backend.config import OWNER_TOKEN

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# Password / PIN utils
def hash_pin(pin: str) -> str:
    # PIN hashing
    return hashlib.sha256(pin.encode()).hexdigest()

def verify_pin_hash(pin: str, hashed: str) -> bool:
    return hash_pin(pin) == hashed

# Deps
def require_owner(x_owner_token: str = Header(default="", alias="X-OWNER-TOKEN")) -> str:
    if (x_owner_token or "").strip() != OWNER_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid owner token")
    return x_owner_token

def require_user(x_user_token: str = Header(default="", alias="X-USER-TOKEN")) -> sqlite3.Row:
    tok = (x_user_token or "").strip()
    if not tok:
        raise HTTPException(status_code=401, detail="Missing user token")
    con = db()
    cur = con.execute("SELECT * FROM users WHERE token=?", (tok,))
    u = one(cur)
    con.close()
    if not u:
        raise HTTPException(status_code=401, detail="Invalid user token")
    return u

def require_device(x_device_token: str = Header(default="", alias="X-DEVICE-TOKEN")) -> sqlite3.Row:
    dt = (x_device_token or "").strip()
    if not dt:
        raise HTTPException(status_code=401, detail="Device not paired")
    con = db()
    cur = con.execute("SELECT * FROM devices WHERE device_token=?", (dt,))
    d = one(cur)
    if d:
        con.execute("UPDATE devices SET last_seen_at=? WHERE device_token=?", (now_iso(), dt))
        con.commit()
    con.close()
    if not d:
        raise HTTPException(status_code=401, detail="Device not paired")
    return d
