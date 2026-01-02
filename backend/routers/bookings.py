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
CF_APP_ID = os.getenv("CASHFREE_APP_ID", "")
CF_SECRET_KEY = os.getenv("CASHFREE_SECRET_KEY", "")
CF_ENVIRONMENT = os.getenv("CASHFREE_ENVIRONMENT", "test") # "test" or "production"

# --- Utils ---
def sign_booking(booking_id: str) -> str:
    mac = hmac.new(SIG_SECRET.encode("utf-8"), booking_id.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("utf-8").rstrip("=")[:32]

def verify_sig(booking_id: str, sig: str) -> bool:
    if not booking_id or not sig:
        return False
    expected = sign_booking(booking_id)
    return hmac.compare_digest(expected, sig)

def normalize_fuel(ft: str) -> str:
    x = (ft or "").strip().upper()
    if x in {"PETROL", "GAS", "DIESEL", "EV"}:
        return x
    if x in {"CNG", "LPG"}:
        return "CNG"
    return "PETROL"

# --- Models ---
class BookingCreate(BaseModel):
    bunk_id: str
    fuel_type: str
    amount: float = 0
    litres: float = 0
    pay_method: str = Field(..., description="wallet|razorpay")
    vehicle_type: Optional[str] = None
    vehicle_no: Optional[str] = None
    user_id: Optional[int|str] = None

class BookingOut(BaseModel):
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

class PaymentVerify(BaseModel):
    booking_id: str
    payment_id: Optional[str] = None

# --- Routes ---

@router.get("/nearby-bunks")
def nearby_bunks(lat: float, lon: float):
    # Mock
    return [
        {"id":"BUNK-1", "name":"Service Point 1", "dist": 1.2},
        {"id":"BUNK-2", "name":"Service Point 2", "dist": 4.5},
    ]

@router.post("/create-booking")
def create_booking(req: BookingCreate, user=Depends(require_user)):
    booking_id = secrets.token_hex(6)
    fuel_type = normalize_fuel(req.fuel_type)
    payment_method = (req.pay_method or "wallet").lower()
    amount = float(req.amount or 0)
    litres = float(req.litres or 0)
    bunk_id = req.bunk_id.strip() or "BUNK-1"

    # Cashfree Integration
    payment_session_id = None
    status = "pending"
    
    # If keys exist, try to create real order
    if CF_APP_ID and CF_SECRET_KEY and amount >= 1 and payment_method in {"cashfree", "razorpay"}:
        try:
            import requests
            url = "https://sandbox.cashfree.com/pg/orders" if CF_ENVIRONMENT == "test" else "https://api.cashfree.com/pg/orders"
            headers = {
                "accept": "application/json",
                "content-type": "application/json",
                "x-api-version": "2023-08-01",
                "x-client-id": CF_APP_ID,
                "x-client-secret": CF_SECRET_KEY
            }
            payload = {
                "order_amount": amount,
                "order_currency": "INR",
                "order_id": booking_id,
                "customer_details": {
                    "customer_id": str(user["phone"]),
                    "customer_phone": str(user["phone"]),
                    "customer_name": user["name"] or "Fleet Driver"
                },
                "order_meta": {
                    "return_url": f"https://fueltag-production.up.railway.app/customer.html?order_id={booking_id}"
                },
                "order_note": "Fleet Management Service Credit"
            }
            resp = requests.post(url, json=payload, headers=headers)
            order_data = resp.json()
            payment_session_id = order_data.get("payment_session_id")
        except Exception as e:
            print(f"Cashfree Error: {e}")
            pass

    # If NO payment session, auto-mark PAID (Fake mode)
    if not payment_session_id:
        status = "paid"
    
    t = now_iso()
    con = db()
    con.execute(
        """
        INSERT INTO vouchers(id,user_phone,user_name,bunk_id,fuel_type,amount,litres,payment_method,vehicle_type,vehicle_no,status,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            booking_id,
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

    return {
        "ok": True,
        "id": booking_id,
        "amount": amount,
        "status": status,
        "payment_session_id": payment_session_id,
        "cf_environment": CF_ENVIRONMENT
    }

@router.post("/verify-payment")
def verify_payment(req: PaymentVerify, user=Depends(require_user)):
    booking_id = req.booking_id
    t = now_iso()
    con = db()
    
    # Real Verification logic if Cashfree keys are present
    is_paid = True # Default for "fake" mode
    if CF_APP_ID and CF_SECRET_KEY:
        try:
            import requests
            url = f"https://sandbox.cashfree.com/pg/orders/{booking_id}" if CF_ENVIRONMENT == "test" else f"https://api.cashfree.com/pg/orders/{booking_id}"
            headers = {
                "accept": "application/json",
                "x-api-version": "2023-08-01",
                "x-client-id": CF_APP_ID,
                "x-client-secret": CF_SECRET_KEY
            }
            resp = requests.get(url, headers=headers)
            cf_data = resp.json()
            status = cf_data.get("order_status")
            is_paid = (status == "PAID")
        except Exception as e:
            print(f"Verify Error: {e}")
            is_paid = False

    if is_paid:
        con.execute("UPDATE vouchers SET status='paid', updated_at=? WHERE id=? AND user_phone=?", (t, booking_id, user["phone"]))
        con.commit()
    
    con.close()
    return {"ok": is_paid}

@router.get("/my-bookings")
def my_bookings(user_id: str|None=None, user=Depends(require_user)):
    con = db()
    cur = con.execute(
        "SELECT * FROM vouchers WHERE user_phone=? ORDER BY created_at DESC LIMIT 50",
        (user["phone"],),
    )
    rows_ = rows(cur)
    out = []
    for r in rows_:
        d = dict(r)
        d["qr_sig"] = sign_booking(d["id"])
        out.append(d)
    con.close()
    return out

@router.get("/booking/{booking_id}")
def get_booking_public(booking_id: str, user=Depends(require_user)):
    # Frontend calls this sometimes to get sig
    con = db()
    cur = con.execute("SELECT * FROM vouchers WHERE id=? AND user_phone=?", (booking_id, user["phone"]))
    v = one(cur)
    con.close()
    if not v:
        raise HTTPException(status_code=404, detail="Not Found")
    d = dict(v)
    d["qr_sig"] = sign_booking(d["id"])
    return d

@router.get("/booking-status/{booking_id}")
def get_booking_status(booking_id: str):
    # Public or User? Frontend calls without headers sometimes? 
    # Frontend wrapper: checkVoucherStatus calls fetch(API/voucher-status/ID).
    # It does NOT appear to send headers in customer.html (Line 1175).
    # So this must be public.
    con = db()
    cur = con.execute("SELECT status, updated_at FROM vouchers WHERE id=?", (booking_id,))
    v = one(cur)
    con.close()
    if not v:
        raise HTTPException(status_code=404, detail="Not Found")
    return {"status": v["status"], "updated_at": v["updated_at"]}

# --- Owner Routes (Voucher List) ---
@router.get("/bookings")
def owner_list_bookings(
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
