from fastapi import APIRouter
from backend.config import FUEL_RATES, BUNKS

router = APIRouter()

@router.get("/info")
def get_system_info():
    """
    Returns the current fuel rates and authorized service points (bunks).
    Used by the frontend to replace hardcoded values.
    """
    return {
        "rates": FUEL_RATES,
        "bunks": BUNKS
    }
