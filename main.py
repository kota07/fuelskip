from fastapi import FastAPI, HTTPException, Request, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import uuid
import datetime
import os
import math
import hmac
import hashlib
import re  # ✅ FIX: required by parse_qr_payload helpers

from dotenv import load_dotenv
load_dotenv()

import razorpay

from sqlalchemy import create_engine, Column, String, Float, DateTime, Boolean, Integer, Text
from sqlalchemy import text as sql_text
from sqlalchemy.orm import sessionmaker, declarative_base, Session


# ---------------- DB Setup ----------------
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./fuelskip.db")
if SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine_kwargs = {}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(SQLALCHEMY_DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    phone = Column(String, unique=True, index=True)
    name = Column(String, nullable=True)
    created_at = Column(DateTime)

    # NOTE: wallet_balance column may exist from older DB.
    # We intentionally DO NOT use it anymore to avoid wallet compliance.
    wallet_balance = Column(Float, default=0.0)


class VoucherDB(Base):
    __tablename__ = "vouchers"
    id = Column(String, primary_key=True, index=True)
    bunk_id = Column(String, index=True)

    amount = Column(Float)
    litres = Column(Float)
    status = Column(String, index=True)  # pending/paid/used/failed
    price_per_litre = Column(Float)

    created_at = Column(DateTime)
    expires_at = Column(DateTime)

    used = Column(Boolean, default=False)

    razorpay_order_id = Column(String, index=True)
    razorpay_payment_id = Column(String, index=True, nullable=True)

    user_id = Column(Integer, index=True, nullable=True)

    vehicle_type = Column(String, nullable=True)
    vehicle_no = Column(String, nullable=True)

    # ✅ fuel type
    fuel_type = Column(String, nullable=True)  # PETROL/DIESEL/CNG/EV

    # ✅ Only razorpay now (kept for record)
    pay_method = Column(String, nullable=True)  # "razorpay"


class WebhookEventDB(Base):
    __tablename__ = "webhook_events"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(String, unique=True, index=True)
    event_type = Column(String, index=True)
    order_id = Column(String, index=True, nullable=True)
    payment_id = Column(String, index=True, nullable=True)
    raw = Column(Text, nullable=True)
    created_at = Column(DateTime)


class ErrorLogDB(Base):
    __tablename__ = "error_logs"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    where = Column(String)
    message = Column(String)
    created_at = Column(DateTime)


class DeviceDB(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=True)
    bunk_id = Column(String, index=True)
    device_token = Column(String, unique=True, index=True)
    created_at = Column(DateTime)
    last_seen_at = Column(DateTime, nullable=True)

    revoked = Column(Boolean, default=False)  # ✅ NEW: owner can disable a device


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# -------------- end DB setup --------------


app = FastAPI(title="FuelSkip")

ATTENDANT_TOKEN = os.getenv("ATTENDANT_TOKEN", "")
OWNER_TOKEN = os.getenv("OWNER_TOKEN", "")
ATTENDANT_BUNK_ID = os.getenv("ATTENDANT_BUNK_ID", "")


def _require_token(expected: str, provided: str | None, label: str):
    if not expected:
        raise HTTPException(status_code=500, detail=f"{label} token not configured")
    if not provided or provided != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


# -------- Signed QR helpers --------
def _qr_secret() -> bytes:
    secret = os.getenv("QR_SIGNING_SECRET", "")
    if not secret or len(secret) < 16:
        raise HTTPException(status_code=500, detail="QR_SIGNING_SECRET not configured")
    return secret.encode("utf-8")


def sign_voucher_qr(voucher: VoucherDB) -> str:
    created = voucher.created_at.replace(tzinfo=None).isoformat(timespec="seconds")
    # Keep signature stable: id|bunk|amount|created
    msg = f"{voucher.id}|{voucher.bunk_id}|{voucher.amount:.2f}|{created}".encode("utf-8")
    return hmac.new(_qr_secret(), msg, hashlib.sha256).hexdigest()


def verify_voucher_sig(voucher: VoucherDB, sig: str | None) -> bool:
    if not sig:
        return False
    expected = sign_voucher_qr(voucher)
    return hmac.compare_digest(expected, sig)


cors_origins_raw = os.getenv("CORS_ORIGINS", "*")
cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins_raw != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")


def sanitize_hex_id(s: str | None, min_len: int = 6, max_len: int = 128) -> str | None:
    """Extract the first hex-looking token from a noisy string."""
    if not s:
        return None
    txt = str(s).strip()
    txt = txt.strip().strip("[](){}<>\"'`")
    m = re.search(r"[0-9a-fA-F]{%d,%d}" % (min_len, max_len), txt)
    if not m:
        return None
    return m.group(0).lower()


def parse_qr_payload(payload: str) -> tuple[str, str | None]:
    """Accept multiple QR payload formats and extract (voucher_id, sig)."""
    if payload is None:
        return "", None

    s = str(payload).strip()

    for prefix in ("QR payload:", "Payload:", "qr payload:", "QR:", "qr:"):
        if s.lower().startswith(prefix.lower()):
            s = s[len(prefix):].strip()

    if "voucher=" in s:
        try:
            vid_m = re.search(r"(?:\?|&|\b)voucher=([^&\s#]+)", s)
            sig_m = re.search(r"(?:\?|&|\b)sig=([^&\s#]+)", s)
            vid_raw = vid_m.group(1) if vid_m else s
            sig_raw = sig_m.group(1) if sig_m else None
            vid = sanitize_hex_id(vid_raw) or vid_raw.strip()
            sig = sanitize_hex_id(sig_raw, min_len=8) if sig_raw else None
            return vid, sig
        except Exception:
            pass

    if "|" in s:
        left, right = s.split("|", 1)
        vid = sanitize_hex_id(left) or left.strip()
        sig = sanitize_hex_id(right, min_len=8) or right.strip()
        return vid, sig

    vid = sanitize_hex_id(s) or s.strip()
    return vid, None


@app.get("/")
def root():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/index.html")
def index_page():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/customer.html")
def customer_page():
    return FileResponse(os.path.join(BASE_DIR, "customer.html"))


@app.get("/attendant.html")
def attendant_page():
    return FileResponse(os.path.join(BASE_DIR, "attendant.html"))


@app.get("/owner.html")
def owner_page():
    return FileResponse(os.path.join(BASE_DIR, "owner.html"))


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

    # SQLite schema patch for older dev DB
    if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
        with engine.begin() as conn:
            cols = [r[1] for r in conn.execute(sql_text("PRAGMA table_info(users)")).fetchall()]
            if "wallet_balance" not in cols:
                conn.execute(sql_text("ALTER TABLE users ADD COLUMN wallet_balance FLOAT DEFAULT 0"))

            vcols = [r[1] for r in conn.execute(sql_text("PRAGMA table_info(vouchers)")).fetchall()]
            if "vehicle_type" not in vcols:
                conn.execute(sql_text("ALTER TABLE vouchers ADD COLUMN vehicle_type VARCHAR"))
            if "vehicle_no" not in vcols:
                conn.execute(sql_text("ALTER TABLE vouchers ADD COLUMN vehicle_no VARCHAR"))
            if "razorpay_payment_id" not in vcols:
                conn.execute(sql_text("ALTER TABLE vouchers ADD COLUMN razorpay_payment_id VARCHAR"))
            if "pay_method" not in vcols:
                conn.execute(sql_text("ALTER TABLE vouchers ADD COLUMN pay_method VARCHAR"))
            if "fuel_type" not in vcols:
                conn.execute(sql_text("ALTER TABLE vouchers ADD COLUMN fuel_type VARCHAR"))

            # ✅ NEW: add revoked column to devices table if missing
            dcols = [r[1] for r in conn.execute(sql_text("PRAGMA table_info(devices)")).fetchall()]
            if "revoked" not in dcols:
                conn.execute(sql_text("ALTER TABLE devices ADD COLUMN revoked BOOLEAN DEFAULT 0"))


# ----- Razorpay setup -----
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")

razor_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


# -------- Bunks (static for now) --------
bunks = {
    "BUNK-1": {
        "id": "BUNK-1",
        "name": "BPCL Siripuram",
        "lat": 17.6868,
        "lon": 83.2185,
        "address": "Siripuram, Visakhapatnam",
        "pumps": [1, 2, 3],
        "price_per_litre": 108.16,
    },
    "BUNK-2": {
        "id": "BUNK-2",
        "name": "Gajuwaka Expressway",
        "lat": 17.6860,
        "lon": 83.1470,
        "address": "Gajuwaka, Visakhapatnam",
        "pumps": [1, 2],
        "price_per_litre": 108.16,
    },
}


def distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


def log_error(db: Session, where: str, message: str):
    try:
        db.add(ErrorLogDB(where=where, message=message[:1000], created_at=datetime.datetime.utcnow()))
        db.commit()
    except Exception:
        pass


# -------- Pydantic models --------
class CreateVoucher(BaseModel):
    bunk_id: str
    amount: float | None = None
    litres: float | None = None
    user_id: int | None = None
    vehicle_type: str | None = None
    vehicle_no: str | None = None
    fuel_type: str | None = "PETROL"  # PETROL/DIESEL/CNG/EV
    pay_method: str | None = "razorpay"  # wallet removed


class LoginRequest(BaseModel):
    phone: str
    name: str | None = None


class LoginResponse(BaseModel):
    user_id: int
    phone: str
    name: str | None = None


class RegisterDeviceRequest(BaseModel):
    name: str | None = None
    bunk_id: str


class RevokeDeviceRequest(BaseModel):
    device_id: int
    revoke: bool = True
# --------------------------------


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.phone == req.phone).first()
    if not user:
        user = UserDB(phone=req.phone, name=req.name, created_at=datetime.datetime.utcnow(), wallet_balance=0.0)
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        if req.name and (not user.name):
            user.name = req.name
            db.commit()
            db.refresh(user)

    return LoginResponse(user_id=user.id, phone=user.phone, name=user.name)


@app.get("/nearby-bunks")
def nearby_bunks(lat: float, lon: float) -> List[dict]:
    results = []
    for bunk in bunks.values():
        dist = distance_km(lat, lon, bunk["lat"], bunk["lon"])
        results.append(
            {"id": bunk["id"], "name": bunk["name"], "address": bunk.get("address"), "distance_km": dist, "pumps": bunk["pumps"]}
        )
    results.sort(key=lambda x: x["distance_km"])
    return results


@app.post("/create-voucher")
def create_voucher(req: CreateVoucher, db: Session = Depends(get_db)):
    if req.bunk_id not in bunks:
        raise HTTPException(status_code=404, detail="Bunk not found")

    if req.amount is None and req.litres is None:
        raise HTTPException(status_code=400, detail="Send amount or litres")

    bunk = bunks[req.bunk_id]
    price = bunk.get("price_per_litre")
    if price is None:
        raise HTTPException(status_code=500, detail="Bunk price not configured")

    amount = req.amount
    litres = req.litres

    if amount is not None and amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be > 0")
    if litres is not None and litres <= 0:
        raise HTTPException(status_code=400, detail="Litres must be > 0")

    if amount is not None and litres is None:
        litres = round(amount / price, 2)
    elif litres is not None and amount is None:
        amount = round(litres * price, 2)

    if amount is None or litres is None:
        raise HTTPException(status_code=400, detail="Invalid amount/litres")

    voucher_id = uuid.uuid4().hex[:12]
    now = datetime.datetime.utcnow()
    expires = now + datetime.timedelta(minutes=30)

    pay_method = "razorpay"

    try:
        order = razor_client.order.create(
            {
                "amount": int(float(amount) * 100),
                "currency": "INR",
                "receipt": voucher_id,
                "payment_capture": 1,
                "notes": {"type": "voucher", "voucher_id": voucher_id},
            }
        )
    except Exception as e:
        log_error(db, "create-voucher", str(e))
        raise HTTPException(status_code=500, detail="Razorpay order error")

    v = VoucherDB(
        id=voucher_id,
        bunk_id=req.bunk_id,
        amount=float(amount),
        litres=float(litres),
        status="pending",
        price_per_litre=price,
        created_at=now,
        expires_at=expires,
        razorpay_order_id=order["id"],
        used=False,
        user_id=req.user_id,
        vehicle_type=req.vehicle_type,
        vehicle_no=req.vehicle_no,
        fuel_type=(req.fuel_type or "PETROL").upper(),
        pay_method=pay_method,
    )
    db.add(v)
    db.commit()
    db.refresh(v)

    qr_sig = sign_voucher_qr(v)

    return {
        "voucher_id": voucher_id,
        "amount": float(amount),
        "litres": float(litres),
        "price_per_litre": price,
        "expires_at": expires,
        "razorpay_order_id": order["id"],
        "razorpay_key_id": RAZORPAY_KEY_ID,
        "qr_sig": qr_sig,
        "status": "pending",
        "pay_method": "razorpay",
        "fuel_type": v.fuel_type,
    }


@app.get("/voucher/{voucher_id}")
def get_voucher(voucher_id: str, db: Session = Depends(get_db)):
    voucher_id, _sig = parse_qr_payload(voucher_id)
    v = db.query(VoucherDB).filter(VoucherDB.id == voucher_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Voucher not found")

    user = None
    if v.user_id:
        user = db.query(UserDB).filter(UserDB.id == v.user_id).first()

    d = {k: v.__dict__[k] for k in v.__dict__ if not k.startswith("_")}
    d["user_phone"] = user.phone if user else None
    d["user_name"] = user.name if user else None
    return d


@app.get("/voucher-status/{voucher_id}")
def voucher_status(voucher_id: str, db: Session = Depends(get_db)):
    voucher_id, _sig = parse_qr_payload(voucher_id)
    v = db.query(VoucherDB).filter(VoucherDB.id == voucher_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Voucher not found")
    return {"status": v.status, "used": bool(v.used)}


# ------------------ DEVICE PAIRING (OWNER) ------------------
@app.post("/devices/register")
def register_device(
    req: RegisterDeviceRequest,
    db: Session = Depends(get_db),
    x_owner_token: str | None = Header(None, alias="X-OWNER-TOKEN"),
):
    _require_token(OWNER_TOKEN, x_owner_token, "Owner")
    if req.bunk_id not in bunks:
        raise HTTPException(status_code=404, detail="Bunk not found")

    token = uuid.uuid4().hex
    d = DeviceDB(
        name=req.name or "Attendant Device",
        bunk_id=req.bunk_id,
        device_token=token,
        created_at=datetime.datetime.utcnow(),
        last_seen_at=None,
        revoked=False,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return {"device_id": d.id, "name": d.name, "bunk_id": d.bunk_id, "device_token": d.device_token}


@app.get("/devices")
def list_devices(
    db: Session = Depends(get_db),
    x_owner_token: str | None = Header(None, alias="X-OWNER-TOKEN"),
):
    _require_token(OWNER_TOKEN, x_owner_token, "Owner")
    devices = db.query(DeviceDB).order_by(DeviceDB.created_at.desc()).all()
    return [
        {
            "id": d.id,
            "name": d.name,
            "bunk_id": d.bunk_id,
            "created_at": d.created_at,
            "last_seen_at": d.last_seen_at,
            "revoked": bool(getattr(d, "revoked", False)),
        }
        for d in devices
    ]


@app.post("/devices/revoke")
def revoke_device(
    req: RevokeDeviceRequest,
    db: Session = Depends(get_db),
    x_owner_token: str | None = Header(None, alias="X-OWNER-TOKEN"),
):
    _require_token(OWNER_TOKEN, x_owner_token, "Owner")

    d = db.query(DeviceDB).filter(DeviceDB.id == req.device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")

    d.revoked = bool(req.revoke)
    db.commit()
    return {"ok": True, "device_id": d.id, "revoked": bool(d.revoked)}
# ------------------------------------------------------------


@app.post("/validate/{voucher_id}")
def validate_voucher(
    voucher_id: str,
    sig: str | None = None,
    db: Session = Depends(get_db),
    x_device_token: str | None = Header(None, alias="X-DEVICE-TOKEN"),
    x_attendant_token: str | None = Header(None, alias="X-ATTENDANT-TOKEN"),
):
    vid_from_payload, sig_from_payload = parse_qr_payload(voucher_id)
    if sig is None and sig_from_payload:
        sig = sig_from_payload
    voucher_id = vid_from_payload

    device = None
    if x_device_token:
        device = db.query(DeviceDB).filter(DeviceDB.device_token == x_device_token).first()

    if device and bool(getattr(device, "revoked", False)):
        raise HTTPException(status_code=403, detail="Device revoked by owner")

    if not device:
        _require_token(ATTENDANT_TOKEN, x_attendant_token, "Attendant")

    v = db.query(VoucherDB).filter(VoucherDB.id == voucher_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Voucher not found")

    if not verify_voucher_sig(v, sig):
        raise HTTPException(status_code=403, detail="Invalid QR signature")

    if device:
        device.last_seen_at = datetime.datetime.utcnow()
        db.commit()
        if v.bunk_id != device.bunk_id:
            raise HTTPException(status_code=403, detail=f"Wrong bunk. This device is for {device.bunk_id}")
    else:
        if ATTENDANT_BUNK_ID and v.bunk_id != ATTENDANT_BUNK_ID:
            raise HTTPException(status_code=403, detail=f"Wrong bunk. This device is for {ATTENDANT_BUNK_ID}")

    if v.status not in ("paid", "used"):
        raise HTTPException(status_code=400, detail="Payment not completed yet")

    if v.used or v.status == "used":
        return {
            "approved": True,
            "already_used": True,
            "voucher_id": voucher_id,
            "bunk_id": v.bunk_id,
            "amount": v.amount,
            "litres": v.litres,
            "fuel_type": v.fuel_type,
        }

    v.used = True
    v.status = "used"
    db.commit()

    return {
        "approved": True,
        "already_used": False,
        "voucher_id": voucher_id,
        "bunk_id": v.bunk_id,
        "amount": v.amount,
        "litres": v.litres,
        "fuel_type": v.fuel_type,
    }


# ---------------- Razorpay webhook ----------------
@app.post("/razorpay-webhook")
async def razorpay_webhook(request: Request, db: Session = Depends(get_db)):
    body_bytes = await request.body()
    signature = request.headers.get("x-razorpay-signature")

    if not WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    try:
        razor_client.utility.verify_webhook_signature(body_bytes.decode("utf-8"), signature, WEBHOOK_SECRET)
    except Exception as e:
        log_error(db, "webhook-verify", str(e))
        raise HTTPException(status_code=400, detail="Invalid signature")

    payload = await request.json()
    event = payload.get("event")
    event_id = payload.get("event_id") or payload.get("id")

    # idempotency
    if event_id:
        already = db.query(WebhookEventDB).filter(WebhookEventDB.event_id == event_id).first()
        if already:
            return {"ok": True, "deduped": True}

        db.add(
            WebhookEventDB(
                event_id=event_id,
                event_type=event or "",
                raw=str(payload)[:20000],
                created_at=datetime.datetime.utcnow(),
            )
        )
        db.commit()

    payment_entity = payload.get("payload", {}).get("payment", {}).get("entity", {})
    order_id = payment_entity.get("order_id")
    payment_id = payment_entity.get("id")

    if event in ("payment.captured", "payment.failed"):
        if order_id:
            v = db.query(VoucherDB).filter(VoucherDB.razorpay_order_id == order_id).first()
            if v:
                if payment_id:
                    v.razorpay_payment_id = payment_id
                v.status = "paid" if event == "payment.captured" else "failed"
                db.commit()
                return {"ok": True, "type": "voucher"}

    return {"ok": True}
# -------------------------------------------------


@app.get("/vouchers")
def list_vouchers(
    bunk_id: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    x_owner_token: str | None = Header(None, alias="X-OWNER-TOKEN"),
):
    _require_token(OWNER_TOKEN, x_owner_token, "Owner")
    q = db.query(VoucherDB)
    if bunk_id:
        q = q.filter(VoucherDB.bunk_id == bunk_id)
    if status:
        q = q.filter(VoucherDB.status == status)
    results = q.order_by(VoucherDB.created_at.desc()).all()
    out = []
    for v in results:
        d = {k: v.__dict__[k] for k in v.__dict__ if not k.startswith("_")}
        out.append(d)
    return out


@app.get("/my-vouchers")
def my_vouchers(user_id: int, db: Session = Depends(get_db)):
    q = db.query(VoucherDB).filter(VoucherDB.user_id == user_id).order_by(VoucherDB.created_at.desc())
    out = []
    for v in q.all():
        d = {k: v.__dict__[k] for k in v.__dict__ if not k.startswith("_")}
        out.append(d)
    return out
