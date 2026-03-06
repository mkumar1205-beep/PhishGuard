from fastapi import APIRouter
from app.models.schemas import ReportRequest
from app.database import get_redis
import json, time

router = APIRouter()

@router.post("/")
async def submit_report(req: ReportRequest):
    r = await get_redis()
    key = f"phishguard:reports:{req.url}"
    report = {
        "url": req.url,
        "city": req.user_city or "unknown",
        "notes": req.notes or "",
        "timestamp": time.time(),
    }
    await r.rpush(key, json.dumps(report))
    count = await r.llen(key)
    return {"message": "Report submitted", "total_reports": count, "url": req.url}


@router.get("/stats/{domain}")
async def get_report_stats(domain: str):
    r = await get_redis()
    keys = await r.keys(f"phishguard:reports:*{domain}*")
    total = 0
    cities = {}
    for key in keys[:20]:
        reports = await r.lrange(key, 0, -1)
        for rep_str in reports:
            rep = json.loads(rep_str)
            total += 1
            city = rep.get("city", "unknown")
            cities[city] = cities.get(city, 0) + 1
    return {
        "domain": domain,
        "total_reports": total,
        "by_city": cities,
        "message": f"{total} user{'s' if total != 1 else ''} reported this domain"
    }