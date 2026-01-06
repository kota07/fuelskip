import secrets
import os
import hmac
import hashlib
import base64
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Header, Request
from pydantic import BaseModel, Field

from backend.database import db, one, rows, now_iso
from backend.auth import require_user, require_owner, require_device
from backend.config import SIG_SECRET

router = APIRouter()

# --- Config ---
CF_APP_ID = os.getenv("CASHFREE_APP_ID", "")
CF_SECRET_KEY = os.getenv("CASHFREE_SECRET_KEY", "")
CF_ENVIRONMENT = os.getenv("CASHFREE_ENVIRONMENT", "sandbox").strip().lower()

# --- Utils ---
def _verify_cashfree_order(booking_id: str) -> bool:
    if not (CF_APP_ID and CF_SECRET_KEY):
        return True # Default to paid in fake mode
    try:
        import requests
        url = f"https://sandbox.cashfree.com/pg/orders/{booking_id}" if CF_ENVIRONMENT == "sandbox" else f"https://api.cashfree.com/pg/orders/{booking_id}"
        headers = {
            "accept": "application/json",
            "x-api-version": "2023-08-01",
            "x-client-id": CF_APP_ID,
            "x-client-secret": CF_SECRET_KEY
        }
        resp = requests.get(url, headers=headers)
        cf_data = resp.json()
        print(f"DEBUG: Cashfree Verify Response for {booking_id}: {cf_data}")
        
        status = (cf_data.get("order_status") or "").upper()
        if status in ["PAID", "SUCCESS"]:
            return True
            
        # Fallback: check nested payments
        payments = cf_data.get("payments", [])
        for p in payments:
            if (p.get("payment_status") or "").upper() == "SUCCESS":
                return True
    except Exception as e:
        print(f"Verify Error: {e}")
    return False

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
    pay_method: str = Field(..., description="wallet|cashfree")
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
def create_booking(req: BookingCreate, request: Request, user=Depends(require_user)):
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
    if CF_APP_ID and CF_SECRET_KEY and amount >= 1 and payment_method in {"cashfree"}:
        try:
            import requests
            url = "https://sandbox.cashfree.com/pg/orders" if CF_ENVIRONMENT == "sandbox" else "https://api.cashfree.com/pg/orders"
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
                    "return_url": f"{str(request.base_url).replace('http://', 'https://')}customer.html?order_id={booking_id}"
                },
                "order_note": "Fleet Management Service Credit"
            }
            resp = requests.post(url, json=payload, headers=headers)
            order_data = resp.json()
            if resp.status_code != 200:
                print(f"CASHFREE API ERROR (Status {resp.status_code}): {order_data}")
                # Provide a more specific error message based on common Cashfree errors
                error_msg = order_data.get('message', 'Unknown Error')
                error_code = order_data.get('code', 'Unknown Code')
                detailed_error = f"Cashfree API Error: [{error_code}] {error_msg}"
                raise HTTPException(status_code=400, detail=detailed_error)
            payment_session_id = order_data.get("payment_session_id")
        except HTTPException:
            raise
        except Exception as e:
            print(f"Cashfree Connection Error: {e}")
            raise HTTPException(status_code=500, detail=f"Connection Error: {str(e)}")

    # If NO payment session, handle based on environment
    if not payment_session_id:
        if CF_ENVIRONMENT == "production":
            raise HTTPException(status_code=400, detail="Cashfree live session failed. Please ensure your Live Keys are set and your account is active.")
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
    is_paid = _verify_cashfree_order(booking_id)

    if is_paid:
        con = db()
        # Award loyalty points (1 per 100 ₹)
        cur = con.execute("SELECT amount, user_phone FROM vouchers WHERE id=?", (booking_id,))
        v = one(cur)
        if v:
            pts = int(float(v["amount"] or 0) / 100)
            if pts > 0:
                con.execute("UPDATE users SET points = points + ? WHERE phone = ?", (pts, v["user_phone"]))

        con.execute("UPDATE vouchers SET status='paid', updated_at=? WHERE id=? AND status='pending'", (t, booking_id))
        con.commit()
        con.close()
    
    return {"ok": is_paid}

@router.post("/cashfree-webhook")
async def cashfree_webhook(request: Request):
    """
    Cashfree Webhook for asynchronous payment notifications.
    Ensures payment is recorded even if the user doesn't return to the app.
    """
    timestamp = request.headers.get("x-webhook-timestamp")
    signature = request.headers.get("x-webhook-signature")
    
    if not timestamp or not signature:
        raise HTTPException(status_code=400, detail="Missing signature headers")

    raw_body = await request.body()
    body_str = raw_body.decode("utf-8")
    
    # Verify Signature
    # Algorithm: Base64(HMAC-SHA256(timestamp + raw_body, secret_key))
    data_to_sign = timestamp + body_str
    computed_sig = base64.b64encode(
        hmac.new(CF_SECRET_KEY.encode("utf-8"), data_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode("utf-8")
    
    if not hmac.compare_digest(computed_sig, signature):
        print(f"WEBHOOK SIG MISMATCH: {computed_sig} vs {signature}")
        raise HTTPException(status_code=401, detail="Invalid signature")

    import json
    try:
        payload = json.loads(body_str)
        print(f"DEBUG: Webhook Payload: {payload}")
        data = payload.get("data", {})
        order = data.get("order", {})
        order_id = order.get("order_id")
        payment = data.get("payment", {})
        payment_status = payment.get("payment_status")
        
        if order_id and payment_status == "SUCCESS":
            t = now_iso()
            con = db()
            # Award loyalty points
            cur_v = con.execute("SELECT amount, user_phone FROM vouchers WHERE id=?", (order_id,))
            v_data = one(cur_v)
            if v_data:
                pts = int(float(v_data["amount"] or 0) / 100)
                if pts > 0:
                    con.execute("UPDATE users SET points = points + ? WHERE phone = ?", (pts, v_data["user_phone"]))

            con.execute(
                "UPDATE vouchers SET status='paid', updated_at=? WHERE id=? AND status='pending'",
                (t, order_id)
            )
            con.commit()
            con.close()
            print(f"WEBHOOK SUCCESS: Order {order_id} marked as PAID and points awarded")
        
    except Exception as e:
        print(f"Webhook Processing Error: {e}")
        return {"ok": False}

    return {"ok": True}

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
    con = db()
    cur = con.execute("SELECT status, updated_at FROM vouchers WHERE id=?", (booking_id,))
    v = one(cur)
    
    if v and v["status"] == "pending":
        if _verify_cashfree_order(booking_id):
            t = now_iso()
            # Award loyalty points
            cur_v = con.execute("SELECT amount, user_phone FROM vouchers WHERE id=?", (booking_id,))
            v_data = one(cur_v)
            if v_data:
                pts = int(float(v_data["amount"] or 0) / 100)
                if pts > 0:
                    con.execute("UPDATE users SET points = points + ? WHERE phone = ?", (pts, v_data["user_phone"]))

            con.execute("UPDATE vouchers SET status='paid', updated_at=? WHERE id=? AND status='pending'", (t, booking_id))
            con.commit()
            # Fetch updated
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
