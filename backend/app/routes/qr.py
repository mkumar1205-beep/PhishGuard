from fastapi import APIRouter, UploadFile, File
from pyzbar.pyzbar import decode
from PIL import Image
import io

router = APIRouter()

@router.post("/analyze/qr")
async def analyze_qr(file: UploadFile = File(...)):
    contents = await file.read()
    image = Image.open(io.BytesIO(contents))
    decoded = decode(image)

    if not decoded:
        return {"error": "No QR code found"}

    qr_data = decoded[0].data.decode("utf-8")
    is_upi = qr_data.startswith("upi://")

    return {
        "decoded": qr_data,
        "is_upi": is_upi,
        "verdict": "suspicious" if is_upi else "clean"
    }
import io
from fastapi import APIRouter, UploadFile, File, HTTPException
from PIL import Image

router = APIRouter()

@router.post("/")
async def analyze_qr(file: UploadFile = File(...)):
    contents = await file.read()

    try:
        image = Image.open(io.BytesIO(contents))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image file")

    codes = qr_decode(image)
    if not codes:
        raise HTTPException(status_code=422, detail="No QR code found in image")

    results = []
    for code in codes:
        decoded = code.data.decode("utf-8", errors="ignore").strip()

        if decoded.startswith("upi://"):
            result = await analyze_upi_qr(decoded)
            results.append(result)
        elif decoded.startswith("http"):
            results.append({
                "type": "url",
                "decoded": decoded,
                "message": "Submit this URL to /analyze/ for full analysis",
                "url_for_analysis": decoded,
            })
        else:
            results.append({
                "type": "text",
                "decoded": decoded,
                "risk": "unknown",
                "note": "Not a URL or UPI string"
            })

    return {"qr_results": results, "count": len(results)}


async def analyze_upi_qr(upi_string: str) -> dict:
    try:
        query = upi_string.replace("upi://pay?", "")
        params = dict(p.split("=") for p in query.split("&") if "=" in p)

        payee_vpa = params.get("pa", "")
        payee_name = params.get("pn", "").replace("+", " ")
        amount = params.get("am", "0")

        flags = []
        score = 0

        payee_name_lower = payee_name.lower()
        vpa_domain = payee_vpa.split("@")[-1] if "@" in payee_vpa else ""

        official_keywords = ["sbi", "hdfc", "rbi", "bank", "customer care",
                             "helpline", "support", "irctc"]
        if any(kw in payee_name_lower for kw in official_keywords):
            legit_vpa_domains = ["sbi.in", "hdfcbank", "icici", "axisbank",
                                 "paytm", "phonepe", "ybl", "upi"]
            if not any(d in vpa_domain for d in legit_vpa_domains):
                score += 40
                flags.append(
                    f"Display name '{payee_name}' does not match "
                    f"VPA domain '{vpa_domain}' — classic impersonation"
                )

        try:
            amt_float = float(amount)
            if amt_float > 0:
                score += 10
                flags.append(f"Pre-set payment amount: ₹{amount}")
            if amt_float > 10000:
                score += 20
                flags.append(f"Very large pre-set amount: ₹{amount}")
        except ValueError:
            pass

        risk_level = "dangerous" if score >= 40 else "suspicious" if score >= 20 else "safe"

        return {
            "type": "upi",
            "decoded": upi_string,
            "payee_vpa": payee_vpa,
            "payee_name": payee_name,
            "amount": amount,
            "vpa_domain": vpa_domain,
            "score": score,
            "risk_level": risk_level,
            "flags": flags,
        }

    except Exception as e:
        return {
            "type": "upi",
            "decoded": upi_string,
            "error": str(e),
            "risk_level": "unknown"
        }
