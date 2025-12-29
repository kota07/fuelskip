from typing import List, Optional, Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel
from backend.database import db, one, rows, now_iso
from backend.auth import require_user

router = APIRouter()

# --- Models ---
class VehicleIn(BaseModel):
    user_id: int | str  # Frontend sends user_id, but we rely on token. We'll validate matches.
    vehicle_type: str
    vehicle_no: str

class VehicleSetDefault(BaseModel):
    user_id: int | str
    vehicle_id: int

class UserUpdate(BaseModel):
    user_id: int | str
    last_bunk: Optional[str] = None
    last_fuel_type: Optional[str] = None
    last_amount: Optional[float] = None
    last_vehicle_type: Optional[str] = None
    last_vehicle_no: Optional[str] = None

# --- Routes ---

@router.get("/vehicles")
def list_vehicles(user_id: str | None = None, user=Depends(require_user)):
    # Frontend sends user_id param, but we trust the token user.
    # Optional: verify user['id'] == user_id
    con = db()
    cur = con.execute(
        "SELECT id,vehicle_type,vehicle_no,is_default,created_at FROM vehicles WHERE user_phone=? ORDER BY is_default DESC, id DESC",
        (user["phone"],),
    )
    out = [dict(r) for r in rows(cur)]
    con.close()
    return out

@router.post("/vehicles/add")
def add_vehicle(v: VehicleIn, user=Depends(require_user)):
    vt = v.vehicle_type.strip()
    vn = v.vehicle_no.strip().upper()
    if not vt or not vn:
        raise HTTPException(status_code=400, detail="vehicle_type and vehicle_no required")
    con = db()
    try:
        con.execute(
            "INSERT INTO vehicles(user_phone,vehicle_type,vehicle_no,is_default,created_at) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING",
            (user["phone"], vt, vn, 0, now_iso()),
        )
        con.commit()
    finally:
        con.close()
    return {"ok": True}

@router.post("/vehicles/set-default")
def set_default_vehicle(req: VehicleSetDefault, user=Depends(require_user)):
    con = db()
    cur = con.execute(
        "SELECT id FROM vehicles WHERE id=? AND user_phone=?",
        (req.vehicle_id, user["phone"]),
    )
    if not one(cur):
        con.close()
        raise HTTPException(status_code=404, detail="Vehicle not found")
    
    con.execute("UPDATE vehicles SET is_default=0 WHERE user_phone=?", (user["phone"],))
    con.execute(
        "UPDATE vehicles SET is_default=1 WHERE id=? AND user_phone=?",
        (req.vehicle_id, user["phone"]),
    )
    con.commit()
    con.close()
    return {"ok": True}

@router.delete("/vehicles/{vehicle_id}")
def delete_vehicle(vehicle_id: int, user=Depends(require_user)):
    con = db()
    con.execute(
        "DELETE FROM vehicles WHERE id=? AND user_phone=?",
        (vehicle_id, user["phone"]),
    )
    con.commit()
    con.close()
    return {"ok": True}

@router.post("/update")
def update_user_defaults(req: UserUpdate, user=Depends(require_user)):
    # Update user preference columns
    fields = []
    args = []
    
    if req.last_bunk is not None:
        fields.append("last_bunk=?")
        args.append(req.last_bunk)
    if req.last_fuel_type is not None:
        fields.append("last_fuel_type=?")
        args.append(req.last_fuel_type)
    if req.last_amount is not None:
        fields.append("last_amount=?")
        args.append(str(req.last_amount))
    if req.last_vehicle_type is not None:
        fields.append("last_vehicle_type=?")
        args.append(req.last_vehicle_type)
    if req.last_vehicle_no is not None:
        fields.append("last_vehicle_no=?")
        args.append(req.last_vehicle_no)
        
    if not fields:
        return {"ok": True}
        
    args.append(user["phone"])
    q = f"UPDATE users SET {', '.join(fields)} WHERE phone=?"
    
    con = db()
    con.execute(q, tuple(args))
    con.commit()
    con.close()
    return {"ok": True}
