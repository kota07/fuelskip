from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
import secrets
from backend.database import db, one, now_iso
from backend.auth import hash_pin, verify_pin_hash, require_user

router = APIRouter()

class LoginReq(BaseModel):
    phone: str = Field(..., min_length=6, max_length=20)
    name: str = Field(default="")
    pin: str = Field(..., min_length=4, max_length=10, description="4-digit PIN")

class LoginResp(BaseModel):
    user_id: int
    token: str
    phone: str
    name: str
    # Legacy fields to match frontend expectations if needed
    last_fuel_type: str | None = None
    last_amount: float | None = None
    last_bunk: str | None = None
    points: int = 0

@router.post("/login", response_model=LoginResp)
@router.post("/auth/login", response_model=LoginResp)
def login(req: LoginReq):
    phone = req.phone.strip()
    name = (req.name or "").strip()
    pin = req.pin.strip()
    
    t = now_iso()
    token = secrets.token_urlsafe(24)
    
    con = db()
    cur = con.execute("SELECT * FROM users WHERE phone=?", (phone,))
    u = one(cur)
    
    if u:
        # Existing user: Verify PIN
        # If no pin_hash set (legacy user), we might need to set it? 
        # For security, we should reject or allow setting it once.
        # Decisions: If pin_hash is empty, set it. If not, verify.
        stored_hash = u["pin_hash"]
        if not stored_hash:
            # First time setting PIN for existing legacy user
            new_hash = hash_pin(pin)
            con.execute(
                "UPDATE users SET name=?, token=?, last_login_at=?, pin_hash=? WHERE phone=?",
                (name or u["name"], token, t, new_hash, phone),
            )
            # Re-fetch user to get ID
            user_id = u["id"]
        else:
            if not verify_pin_hash(pin, stored_hash):
                con.close()
                raise HTTPException(status_code=401, detail="Invalid PIN")
            
            # PIN OK, rotate token
            con.execute(
                "UPDATE users SET name=?, token=?, last_login_at=? WHERE phone=?",
                (name or u["name"], token, t, phone),
            )
            user_id = u["id"]
            
        # Get defaults (this was missing in original main.py logic but frontend expects it?)
        # unique logic for getting defaults not implemented in main.py, customer.html 836 expects it.
        # We can mock it or store in DB if we added columns. main.py didn't have last_... columns.
        # I will return nulls.
        
    else:
        # New user
        new_hash = hash_pin(pin)
        cur = con.execute(
            "INSERT INTO users(phone,name,token,created_at,last_login_at,pin_hash) VALUES (?,?,?,?,?,?) RETURNING id",
            (phone, name, token, t, t, new_hash),
        )
        user_id = cur.fetchone()['id']
        
    con.commit()
    con.close()
    
    return LoginResp(
        user_id=user_id,
        token=token,
        phone=phone,
        name=name,
        last_bunk=u["last_bunk"] if u and "last_bunk" in u.keys() else None,
        last_fuel_type=u["last_fuel_type"] if u and "last_fuel_type" in u.keys() else None,
        last_amount=float(u["last_amount"]) if u and "last_amount" in u.keys() and u["last_amount"] else None,
        points=u["points"] if u and "points" in u.keys() else 0,
    )

@router.get("/me")
def me(user=Depends(require_user)):
    return {
        "user_id": user["id"],
        "phone": user["phone"],
        "name": user["name"],
        "points": user.get("points", 0),
        "last_login_at": user["last_login_at"]
    }
