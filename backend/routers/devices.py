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
    device_id: str | int 
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
    # Postgres schema now includes 'revoked' by default in init_db.
    # We query standard 'id' column instead of rowid.
    
    cur = con.execute("SELECT * FROM devices ORDER BY created_at DESC LIMIT 200")
    
    out = []
    for r in rows(cur):
        d = dict(r)
        # 'revoked' default to 0/False. Postgres returns 0 or boolean? 
        # In init_db: revoked INTEGER DEFAULT 0.
        if "revoked" not in d: d["revoked"] = 0 
        
        # 'id' should be present in new schema
        if "id" not in d:
            # Fallback for old schema? No, we are migrating.
            d["id"] = 0 
            
        out.append(d)
        
    con.close()
    return out

@router.post("/revoke")
def revoke_device(req: DeviceRevokeReq, _owner: str = Depends(require_owner)):
    # owner.html calls this.
    # Logic: update devices set revoked=? where id=?
    con = db()
    
    val = 1 if req.revoke else 0
    # Use standard 'id' column
    con.execute("UPDATE devices SET revoked=? WHERE id=?", (val, req.device_id))
    con.commit()
    con.close()
    return {"ok": True}
