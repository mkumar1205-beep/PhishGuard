import whois
import httpx
import Levenshtein
from urllib.parse import urlparse
from datetime import datetime, timezone
from app.models.schemas import SignalResult
from app.config import settings

BRAND_DOMAINS = {
    "sbi.co.in": "SBI",
    "hdfcbank.com": "HDFC Bank",
    "icicibank.com": "ICICI Bank",
    "axisbank.com": "Axis Bank",
    "kotakbank.com": "Kotak Bank",
    "paytm.com": "Paytm",
    "phonepe.com": "PhonePe",
    "npci.org.in": "NPCI",
    "rbi.org.in": "RBI",
    "irctc.co.in": "IRCTC",
    "amazon.in": "Amazon",
    "flipkart.com": "Flipkart",
    "uidai.gov.in": "UIDAI",
    "incometax.gov.in": "Income Tax",
    "epfindia.gov.in": "EPFO",
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml", ".tk", ".cf"}

async def analyze_domain(url: str) -> SignalResult:
    score = 0
    flags = []
    raw = {}

    try:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        domain = parsed.netloc.lower().replace("www.", "")
        raw["domain"] = domain

        # 1. Domain age via WHOIS
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation).days
                raw["domain_age_days"] = age_days
                if age_days < 7:
                    score += 30
                    flags.append(f"Domain registered only {age_days} days ago")
                elif age_days < 30:
                    score += 20
                    flags.append(f"Very new domain ({age_days} days old)")
                elif age_days < 90:
                    score += 10
                    flags.append(f"Recent domain ({age_days} days old)")
            else:
                score += 15
                flags.append("Domain age unknown — WHOIS lookup failed")
        except Exception as e:
            score += 15
            flags.append("Domain age unknown — WHOIS lookup failed")
            raw["whois_error"] = str(e)

        # 2. Suspicious TLD
        tld = "." + domain.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            score += 25
            flags.append(f"Suspicious TLD: {tld}")
        raw["tld"] = tld

        # 3. Typosquatting check
        for legit_domain, brand_name in BRAND_DOMAINS.items():
            dist = Levenshtein.distance(domain, legit_domain)
            if 0 < dist <= 3:
                score += 35
                flags.append(f"Possible {brand_name} impersonation (distance={dist} from {legit_domain})")
                raw["impersonating"] = brand_name
                break

        # 4. Brand keyword in domain
        for brand_domain, brand_name in BRAND_DOMAINS.items():
            brand_keyword = brand_domain.split(".")[0]
            if brand_keyword in domain and not domain.endswith(brand_domain):
                score += 30
                flags.append(f"Brand keyword '{brand_keyword}' found in suspicious domain — possible {brand_name} impersonation")
                raw["impersonating"] = brand_name
                break

        # 5. VirusTotal
        if settings.VIRUSTOTAL_API_KEY:
            try:
                vt_result = await check_virustotal(domain)
                raw["virustotal"] = vt_result
                if vt_result.get("malicious", 0) > 2:
                    score += 25
                    flags.append(f"VirusTotal: {vt_result['malicious']} engines flagged this")
            except Exception as e:
                raw["vt_error"] = str(e)

        # 6. HTTPS check
        if not url.startswith("https://"):
            score += 5
            flags.append("Not using HTTPS")

    except Exception as e:
        flags.append(f"Domain analysis error: {str(e)}")

    return SignalResult(
        score=min(score, 40),
        flags=flags,
        confidence=0.85,
        raw_data=raw
    )

async def check_virustotal(domain: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    async with httpx.AsyncClient() as client:
        r = await client.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
            }
    return {}