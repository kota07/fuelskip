import secrets
import os
import hmac
import hashlib
import base64
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Header
from pydantic import BaseModel, Field

from backend.database import db, one, rows, now_iso
from backend.auth import require_user, require_owner, require_device
from backend.config import SIG_SECRET

router = APIRouter()

# --- Config ---
RP_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RP_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")

# --- Utils ---
def sign_voucher(voucher_id: str) -> str:
    mac = hmac.new(SIG_SECRET.encode("utf-8"), voucher_id.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("utf-8").rstrip("=")[:32]

def verify_sig(voucher_id: str, sig: str) -> bool:
    if not voucher_id or not sig:
        return False
    expected = sign_voucher(voucher_id)
    return hmac.compare_digest(expected, sig)

def normalize_fuel(ft: str) -> str:
    x = (ft or "").strip().upper()
    if x in {"PETROL", "GAS", "DIESEL", "EV"}:
        return x
    if x in {"CNG", "LPG"}:
        return "CNG"
    return "PETROL"

# --- Models ---
class VoucherCreate(BaseModel):
    bunk_id: str
    fuel_type: str
    amount: float = 0
    litres: float = 0
    pay_method: str = Field(..., description="wallet|razorpay") # renamed to match frontend payload? frontend sends "pay_method"
    vehicle_type: Optional[str] = None
    vehicle_no: Optional[str] = None
    # user_id included in frontend payload? No, backend had it in models but logic ignored it for token.
    user_id: Optional[int|str] = None

class VoucherOut(BaseModel):
    id: str
    bunk_id: str
    fuel_type: str
    amount: float
    litres: float
    payment_method: str | None = None
    vehicle_type: Optional[str] = None
    vehicle_no: Optional[str] = None
    status: str
    created_at: str
    user_phone: Optional[str] = None
    qr_sig: Optional[str] = None
    used: bool | None = None 

# --- Routes ---

@router.get("/nearby-bunks")
def nearby_bunks(lat: float, lon: float):
    # Mock
    return [
        {"id":"BUNK-1", "name":"BPCL Siripuram", "dist": 1.2},
        {"id":"BUNK-2", "name":"Gajuwaka Expressway", "dist": 4.5},
    ]

@router.post("/create-voucher")
def create_voucher(req: VoucherCreate, user=Depends(require_user)):
    voucher_id = secrets.token_hex(6)
    fuel_type = normalize_fuel(req.fuel_type)
    payment_method = (req.pay_method or "wallet").lower()
    amount = float(req.amount or 0)
    litres = float(req.litres or 0)
    bunk_id = req.bunk_id.strip() or "BUNK-1"

    # FAKE PAYMENT LOGIC: Always mark PAID
    status = "paid"
    
    t = now_iso()
    con = db()
    con.execute(
        """
        INSERT INTO vouchers(id,user_phone,user_name,bunk_id,fuel_type,amount,litres,payment_method,vehicle_type,vehicle_no,status,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            voucher_id,
            user["phone"],
            user["name"],
            bunk_id,
            fuel_type,
            amount,
            litres,
            payment_method,
            (req.vehicle_type or None),
            (req.vehicle_no or None),
            status,
            t,
            t,
        ),
    )
    con.commit()
    con.close()

    # If using Razorpay real logic, we would return order_id here.
    # But for "fake payments", we return empty razorpay_order_id so frontend thinks "Voucher created" immediately.
    # Frontend logic: if(data.razorpay_order_id) { open } else { "Voucher created" }.
    return {
        "ok": True,
        "id": voucher_id,
        "amount": amount,
        "status": status,
        "razorpay_order_id": None, 
        "razorpay_key_id": RP_KEY_ID
    }

@router.get("/my-vouchers")
def my_vouchers(user_id: str|None=None, user=Depends(require_user)):
    con = db()
    cur = con.execute(
        "SELECT * FROM vouchers WHERE user_phone=? ORDER BY created_at DESC LIMIT 50",
        (user["phone"],),
    )
    rows_ = rows(cur)
    out = []
    for r in rows_:
        d = dict(r)
        d["qr_sig"] = sign_voucher(d["id"])
        out.append(d)
    con.close()
    return out

@router.get("/voucher/{voucher_id}")
def get_voucher_public(voucher_id: str, user=Depends(require_user)):
    # Frontend calls this sometimes to get sig
    con = db()
    cur = con.execute("SELECT * FROM vouchers WHERE id=? AND user_phone=?", (voucher_id, user["phone"]))
    v = one(cur)
    con.close()
    if not v:
        raise HTTPException(status_code=404, detail="Not Found")
    d = dict(v)
    d["qr_sig"] = sign_voucher(d["id"])
    return d

@router.get("/voucher-status/{voucher_id}")
def get_voucher_status(voucher_id: str):
    # Public or User? Frontend calls without headers sometimes? 
    # Frontend wrapper: checkVoucherStatus calls fetch(API/voucher-status/ID).
    # It does NOT appear to send headers in customer.html (Line 1175).
    # So this must be public.
    con = db()
    cur = con.execute("SELECT status, updated_at FROM vouchers WHERE id=?", (voucher_id,))
    v = one(cur)
    con.close()
    if not v:
        raise HTTPException(status_code=404, detail="Not Found")
    return {"status": v["status"], "updated_at": v["updated_at"]}

# --- Owner Routes (Voucher List) ---
@router.get("/vouchers")
def owner_list_vouchers(
    bunk_id: Optional[str] = None,
    status: Optional[str] = None,
    _owner: str = Depends(require_owner),
):
    q = "SELECT * FROM vouchers WHERE 1=1"
    args: List[Any] = []
    if bunk_id:
        q += " AND bunk_id=?"
        args.append(bunk_id)
    if status:
        q += " AND LOWER(status)=LOWER(?)"
        args.append(status)
    q += " ORDER BY created_at DESC LIMIT 500"
    con = db()
    cur = con.execute(q, tuple(args))
    out = [dict(r) for r in rows(cur)]
    con.close()
    return out
