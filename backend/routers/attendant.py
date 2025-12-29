from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from backend.database import db, one, now_iso
from backend.auth import require_device
from backend.routers.vouchers import verify_sig, sign_voucher

router = APIRouter()

class DispenseReq(BaseModel):
    voucher: str
    sig: str | None = None

@router.get("/voucher")
def attendant_check_voucher(
    voucher: str = Query(...),
    sig: str | None = Query(None),
    device = Depends(require_device)
):
    # attendant.html line 479 calls /attendant/voucher?voucher=...&sig=...
    # Verify sig?
    # If sig provided, verify. If not, maybe just return details?
    # attendant.html logic: "if !verify_sig... Invalid QR signature".
    
    # If sig is present, verify.
    if sig:
        if not verify_sig(voucher, sig):
            raise HTTPException(status_code=400, detail="Invalid QR signature")
    
    con = db()
    cur = con.execute("SELECT * FROM vouchers WHERE id=?", (voucher,))
    v = one(cur)
    con.close()
    
    if not v:
        raise HTTPException(status_code=404, detail="Not Found")
    
    d = dict(v)
    d["qr_sig"] = sign_voucher(d["id"])
    
    # Add customer name for UI
    d["customer_name"] = v["user_name"]
    d["customer_phone"] = v["user_phone"]
    
    return d

@router.post("/dispense")
def dispense(req: DispenseReq, device=Depends(require_device)):
    voucher_id = req.voucher
    sig = req.sig
    
    if not voucher_id:
        raise HTTPException(status_code=400, detail="Voucher ID missing")
    if sig and not verify_sig(voucher_id, sig):
        raise HTTPException(status_code=400, detail="Invalid QR signature")

    con = db()
    cur = con.execute("SELECT * FROM vouchers WHERE id=?", (voucher_id,))
    v = one(cur)
    if not v:
        con.close()
        raise HTTPException(status_code=404, detail="Not Found")

    st = (v["status"] or "").lower()
    if st == "used":
        con.close()
        return {"ok": True, "status": "used", "message": "Voucher already used"}
    if st != "paid":
        con.close()
        raise HTTPException(status_code=400, detail=f"Not ready to dispense (status={v['status']})")

    # Mark used
    con.execute(
        "UPDATE vouchers SET status='used', updated_at=? WHERE id=?",
        (now_iso(), voucher_id),
    )
    con.commit()
    con.close()
    return {"ok": True, "status": "used"}
