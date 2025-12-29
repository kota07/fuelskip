from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database import init_db
from backend.routers import auth, user, vouchers, devices, attendant

app = FastAPI(title="FuelSkip Pilot API (Refactored)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/health")
def health():
    return {"ok": True, "status": "running"}

# Mount Routers
app.include_router(auth.router) # /login, /me
app.include_router(user.router, prefix="/user") # /user/vehicles...
app.include_router(vouchers.router) # /create-voucher, /my-vouchers...
app.include_router(devices.router, prefix="/devices") # /devices/register...
app.include_router(attendant.router, prefix="/attendant") # /attendant/voucher...
