from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import uuid, datetime, os, math

from dotenv import load_dotenv
load_dotenv()   # this reads .env into environment

import razorpay

from sqlalchemy import create_engine, Column, String, Float, DateTime, Boolean, Integer
from sqlalchemy.orm import sessionmaker, declarative_base, Session

# --- DB setup ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./fuelskip.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    phone = Column(String, unique=True, index=True)
    name = Column(String, nullable=True)
    created_at = Column(DateTime)


class VoucherDB(Base):
    __tablename__ = "vouchers"

    id = Column(String, primary_key=True, index=True)       # voucher_id
    bunk_id = Column(String, index=True)
    amount = Column(Float)
    litres = Column(Float)
    status = Column(String, index=True)                     # pending/paid/used
    price_per_litre = Column(Float)
    created_at = Column(DateTime)
    expires_at = Column(DateTime)
    used = Column(Boolean, default=False)
    razorpay_order_id = Column(String, index=True)
    user_id = Column(Integer, index=True, nullable=True)    # link to users


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# --- end DB setup ---


app = FastAPI(title="FuelSkip Flow A")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      # OK for testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Static / HTML pages ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Optional: serve whole folder as /static
app.mount("/static", StaticFiles(directory=BASE_DIR), name="static")


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
# ------------------------------


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)


# ----- Razorpay setup -----
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")  # set same value in dashboard

print("KEY_ID =", RAZORPAY_KEY_ID)

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    print("WARNING: Razorpay keys not set in env; set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET")

razor_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
# --------------------------


bunks = {
    "BUNK-1": {
        "id": "BUNK-1",
        "name": "BPCL Siripuram",
        "lat": 17.6868,
        "lon": 83.2185,
        "address": "Siripuram, Visakhapatnam",
        "vpa": "bunk1@icici",
        "pumps": [1, 2, 3],
        "price_per_litre": 108.16,
    },
    "BUNK-2": {
        "id": "BUNK-2",
        "name": "Gajuwaka Expressway",
        "lat": 17.6860,
        "lon": 83.1470,
        "address": "Gajuwaka, Visakhapatnam",
        "vpa": "bunk2@icici",
        "pumps": [1, 2],
        "price_per_litre": 108.16,
    },
}

# simple haversine in km
def distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


# ---------- Pydantic models ----------
class CreateVoucher(BaseModel):
    bunk_id: str
    amount: float | None = None
    litres: float | None = None
    user_id: int | None = None


class PaymentUpdate(BaseModel):
    voucher_id: str
    status: str  # "paid" or "failed"


class LoginRequest(BaseModel):
    phone: str
    name: str | None = None


class LoginResponse(BaseModel):
    user_id: int
    phone: str
    name: str | None = None
# ------------------------------------


@app.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.phone == req.phone).first()
    if not user:
        user = UserDB(
            phone=req.phone,
            name=req.name,
            created_at=datetime.datetime.utcnow(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return LoginResponse(user_id=user.id, phone=user.phone, name=user.name)


@app.get("/nearby-bunks")
def nearby_bunks(lat: float, lon: float) -> List[dict]:
    """
    Simple nearby bunk list using static bunks dict.
    Vouchers never depend on this; it is only for UX in customer.html.
    """
    results = []
    for bunk in bunks.values():
        dist = distance_km(lat, lon, bunk["lat"], bunk["lon"])
        results.append(
            {
                "id": bunk["id"],
                "name": bunk["name"],
                "address": bunk.get("address"),
                "distance_km": dist,
                "pumps": bunk["pumps"],
            }
        )
    # sort by distance
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

    # calculate missing side from price_per_litre
    if amount is not None and litres is None:
        litres = round(amount / price, 2)
    elif litres is not None and amount is None:
        amount = round(litres * price, 2)

    voucher_id = str(uuid.uuid4())[:8]

    # ----- Razorpay ORDER instead of UPI link -----
    try:
        order = razor_client.order.create(
            {
                "amount": int(amount * 100),  # Razorpay uses paise
                "currency": "INR",
                "receipt": voucher_id,
                "payment_capture": 1,
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Razorpay order error: {e}")
    # ---------------------------------------------

    now = datetime.datetime.utcnow()
    # keep expires_at field but it's not enforced anywhere now
    expires = now + datetime.timedelta(minutes=30)

    voucher_db = VoucherDB(
        id=voucher_id,
        bunk_id=req.bunk_id,
        amount=amount,
        litres=litres,
        status="pending",  # pending → paid → used
        price_per_litre=price,
        created_at=now,
        expires_at=expires,
        razorpay_order_id=order["id"],
        used=False,
        user_id=req.user_id,
    )
    db.add(voucher_db)
    db.commit()

    return {
        "voucher_id": voucher_id,
        "amount": amount,
        "litres": litres,
        "price_per_litre": price,
        "expires_at": expires,
        "razorpay_order_id": order["id"],
        "razorpay_key_id": RAZORPAY_KEY_ID,
    }


@app.get("/voucher/{voucher_id}")
def get_voucher(voucher_id: str, db: Session = Depends(get_db)):
    v = db.query(VoucherDB).filter(VoucherDB.id == voucher_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Voucher not found")
    
    # Include user info if exists
    user = None
    if v.user_id:
        user = db.query(UserDB).filter(UserDB.id == v.user_id).first()
    
    return {
        **v.__dict__,
        "user_phone": user.phone if user else None,
        "user_name": user.name if user else None,
    }


@app.get("/voucher-status/{voucher_id}")
def voucher_status(voucher_id: str, db: Session = Depends(get_db)):
    v = db.query(VoucherDB).filter(VoucherDB.id == voucher_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Voucher not found")
    return {"status": v.status}


@app.post("/validate/{voucher_id}")
def validate_voucher(voucher_id: str, db: Session = Depends(get_db)):
    v = db.query(VoucherDB).filter(VoucherDB.id == voucher_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Voucher not found")

    if v.status != "paid":
        raise HTTPException(status_code=400, detail="Payment not completed yet")

    if v.used:
        raise HTTPException(status_code=400, detail="Voucher already used")

    # NOTE: no time-based expiry check here → voucher valid anytime
    v.used = True
    v.status = "used"
    db.commit()

    return {
        "approved": True,
        "voucher_id": voucher_id,
        "bunk_id": v.bunk_id,
        "amount": v.amount,
        "litres": v.litres,
    }


# ---------- Razorpay webhook ----------
@app.post("/razorpay-webhook")
async def razorpay_webhook(request: Request, db: Session = Depends(get_db)):
    body_bytes = await request.body()
    print("WEBHOOK BODY:", body_bytes)
    signature = request.headers.get("x-razorpay-signature")

    if not WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    try:
        razor_client.utility.verify_webhook_signature(
            body_bytes.decode("utf-8"),
            signature,
            WEBHOOK_SECRET,
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid signature")

    payload = await request.json()
    event = payload.get("event")

    if event == "payment.captured":
        payment_entity = payload["payload"]["payment"]["entity"]
        order_id = payment_entity.get("order_id")

        if order_id:
            v = (
                db.query(VoucherDB)
                .filter(VoucherDB.razorpay_order_id == order_id)
                .first()
            )
            if v:
                v.status = "paid"
                db.commit()

    return {"ok": True}
# --------------------------------------


@app.get("/vouchers")
def list_vouchers(
    bunk_id: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    q = db.query(VoucherDB)
    if bunk_id:
        q = q.filter(VoucherDB.bunk_id == bunk_id)
    if status:
        q = q.filter(VoucherDB.status == status)
    results = q.order_by(VoucherDB.created_at.desc()).all()
    return [v.__dict__ for v in results]


@app.get("/my-vouchers")
def my_vouchers(user_id: int, db: Session = Depends(get_db)):
    q = (
        db.query(VoucherDB)
        .filter(VoucherDB.user_id == user_id)
        .order_by(VoucherDB.created_at.desc())
    )
    return [v.__dict__ for v in q.all()]


@app.get("/admin/users")
def list_users(db: Session = Depends(get_db)):
    users = db.query(UserDB).order_by(UserDB.created_at.desc()).all()
    return [u.__dict__ for u in users]
