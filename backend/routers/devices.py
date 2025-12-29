from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import secrets

from backend.database import db, one, rows, now_iso
from backend.auth import require_owner, require_device

router = APIRouter()

class DeviceRegisterReq(BaseModel):
    bunk_id: str
    name: str

class DeviceRevokeReq(BaseModel):
    device_id: str | int # Frontend sends ID? owner.html line 318 sends device_id
    revoke: bool

@router.post("/register")
def register_device(req: DeviceRegisterReq, _owner: str = Depends(require_owner)):
    dt = secrets.token_urlsafe(24)
    t = now_iso()
    con = db()
    con.execute(
        "INSERT INTO devices(device_token,bunk_id,name,created_at,last_seen_at) VALUES (?,?,?,?,?)",
        (dt, req.bunk_id.strip() or "BUNK-1", (req.name or "Attendant").strip(), t, None),
    )
    con.commit()
    con.close()
    return {"device_token": dt, "bunk_id": req.bunk_id, "name": req.name, "created_at": t}

@router.get("")
def list_devices(_owner: str = Depends(require_owner)):
    con = db()
    # Check if table has 'revoked' column? Initial schema didn't have it.
    # owner.html expects 'revoked' in response (Line 354 of owner.html).
    # main.py did NOT implement 'revoked'.
    # I should add 'revoked' column to DB if I want to support it.
    # Let's add it in migration logic or ignored.
    # For now, I'll return 0 if column missing.
    try:
        cur = con.execute("SELECT *, 0 as revoked FROM devices ORDER BY created_at DESC LIMIT 200")
        # If I migrate, I'd select actual revoked.
    except:
        cur = con.execute("SELECT * FROM devices ORDER BY created_at DESC LIMIT 200")
    
    out = []
    for r in rows(cur):
        d = dict(r)
        if "revoked" not in d: d["revoked"] = 0 # Default if column missing
        # Add id? owner.html uses 'd.id' in revokeDevice(d.id).
        # Schema for devices: device_token is PK. No integer ID.
        # main.py schema: device_token TEXT PRIMARY KEY.
        # owner.html line 365: `revokeDevice(${d.id} ...)`.
        # This implies owner.html expects an integer ID.
        # This means owner.html is BROKEN with current main.py schema.
        # I should probably expose rowid as id? Or fix owner.html?
        # Using rowid is easiest fix without changing HTML logic significantly.
        d["id"] = r["rowid"] if "rowid" in r.keys() else 0 # rowid isn't in generic select *
        out.append(d)
        
    # Re-fetch with rowid
    cur = con.execute("SELECT rowid, * FROM devices ORDER BY created_at DESC LIMIT 200")
    out = [dict(r) for r in rows(cur)]
    # Normalize
    for d in out:
        d["id"] = d["rowid"]
        if "revoked" not in d: d["revoked"] = False

    con.close()
    return out

@router.post("/revoke")
def revoke_device(req: DeviceRevokeReq, _owner: str = Depends(require_owner)):
    # owner.html calls this.
    # Logic: update devices set revoked=? where rowid=?
    # I need to ensure 'revoked' column exists.
    con = db()
    # Migration check
    try:
        con.execute("SELECT revoked FROM devices LIMIT 1")
    except:
        con.execute("ALTER TABLE devices ADD COLUMN revoked INTEGER DEFAULT 0")
    
    val = 1 if req.revoke else 0
    # Req sends id (int). Use rowid.
    con.execute("UPDATE devices SET revoked=? WHERE rowid=?", (val, req.device_id))
    con.commit()
    con.close()
    return {"ok": True}
