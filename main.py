from fastapi import FastAPI
from fastapi.responses import FileResponse
import os
from fastapi.middleware.cors import CORSMiddleware
from backend.database import init_db
from backend.routers import auth, user, bookings, devices, attendant

app = FastAPI(title="FuelSkip Management System")

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
app.include_router(bookings.router) # /create-booking, /my-bookings...
app.include_router(devices.router, prefix="/devices") # /devices/register...
app.include_router(attendant.router, prefix="/attendant") # /attendant/booking...

# --- Frontend Static Files ---
@app.get("/")
async def serve_customer():
    if os.path.exists("customer.html"):
        return FileResponse("customer.html")
    return {"error": "customer.html not found"}

@app.get("/customer.html")
async def serve_customer_html():
    if os.path.exists("customer.html"):
        return FileResponse("customer.html")
    return {"error": "customer.html not found"}

@app.get("/attendant.html")
async def serve_attendant():
    if os.path.exists("attendant.html"):
        return FileResponse("attendant.html")
    return {"error": "attendant.html not found"}

@app.get("/owner.html")
async def serve_owner():
    if os.path.exists("owner.html"):
        return FileResponse("owner.html")
    return {"error": "owner.html not found"}

@app.get("/terms.html")
async def serve_terms():
    if os.path.exists("terms.html"):
        return FileResponse("terms.html")
    return {"error": "Not found"}

@app.get("/privacy.html")
async def serve_privacy():
    if os.path.exists("privacy.html"):
        return FileResponse("privacy.html")
    return {"error": "Not found"}

@app.get("/contact.html")
async def serve_contact():
    if os.path.exists("contact.html"):
        return FileResponse("contact.html")
    return {"error": "Not found"}

@app.get("/refunds.html")
async def serve_refunds():
    if os.path.exists("refunds.html"):
        return FileResponse("refunds.html")
    return {"error": "Not found"}

@app.get("/manifest.json")
async def serve_manifest():
    if os.path.exists("manifest.json"):
        return FileResponse("manifest.json")
    return {"error": "Not found"}

@app.get("/service-worker.js")
async def serve_sw():
    if os.path.exists("service-worker.js"):
        return FileResponse("service-worker.js")
    return {"error": "Not found"}

@app.get("/icon-192.png")
async def serve_icon192():
    if os.path.exists("icon-192.png"):
        return FileResponse("icon-192.png")
    return {"error": "Not found"}

@app.get("/icon-512.png")
async def serve_icon512():
    if os.path.exists("icon-512.png"):
        return FileResponse("icon-512.png")
    return {"error": "Not found"}
