import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("FUELTAG_DB", "fueltag.db")
DATABASE_URL = os.getenv("DATABASE_URL") # Production DB URL
OWNER_TOKEN = os.getenv("FUELTAG_OWNER_TOKEN", "Kota@123")
SIG_SECRET = os.getenv("FUELTAG_SIG_SECRET", "dev-secret-change-me")

# Ensure critical secrets are set (fallback warning could be added here)
