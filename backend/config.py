import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("FUELSKIP_DB", "fuelskip.db")
OWNER_TOKEN = os.getenv("FUELSKIP_OWNER_TOKEN", "Kota@123")
SIG_SECRET = os.getenv("FUELSKIP_SIG_SECRET", "dev-secret-change-me")

# Ensure critical secrets are set (fallback warning could be added here)
