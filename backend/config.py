import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("FUELTAG_DB", "fueltag.db")
DATABASE_URL = os.getenv("DATABASE_URL") # Production DB URL
OWNER_TOKEN = os.getenv("FUELTAG_OWNER_TOKEN", "Kota@123")
SIG_SECRET = os.getenv("FUELTAG_SIG_SECRET", "dev-secret-change-me")

# Ensure critical secrets are set (fallback warning could be added here)

# --- System Settings (Source of Truth) ---
FUEL_RATES = {
    "PETROL": 109.50,
    "DIESEL": 97.20,
    "CNG": 90.00,
    "EV": 15.00
}

BUNKS = [
    {"id": "BUNK-1", "name": "BPCL Siripuram", "lat": 17.723, "lon": 83.315},
    {"id": "BUNK-2", "name": "Gajuwaka Expressway", "lat": 17.689, "lon": 83.212},
]
