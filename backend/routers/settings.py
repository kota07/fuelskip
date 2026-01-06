from backend.config import FUEL_RATES, BUNKS, OWNER_TOKEN
from backend.database import db, one, now_iso
from fastapi import APIRouter, HTTPException, Header, Body
import json

router = APIRouter()

@router.get("/info")
def get_system_info():
    """
    Returns the current fuel rates and authorized service points (bunks).
    Used by the frontend to replace hardcoded values.
    """
    con = db()
    cur = con.execute("SELECT value FROM settings WHERE key='fuel_rates'")
    row = one(cur)
    con.close()
    
    rates = FUEL_RATES
    if row:
        try:
            import json
            rates = json.loads(row["value"])
        except:
            pass

    return {
        "rates": rates,
        "bunks": BUNKS
    }

@router.post("/info")
def update_system_info(
    token: str = Header(..., alias="X-OWNER-TOKEN"),
    rates: dict = Body(...)
):
    if token != OWNER_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    con = db()
    import json
    con.execute(
        "INSERT INTO settings(key, value) VALUES ('fuel_rates', ?) ON CONFLICT(key) DO UPDATE SET value=?",
        (json.dumps(rates), json.dumps(rates))
    )
    con.commit()
    con.close()
    return {"ok": True}
