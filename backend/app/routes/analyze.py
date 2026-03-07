import asyncio
import hashlib
from fastapi import APIRouter, HTTPException
from app.models.schemas import (
    AnalyzeRequest, AnalyzeResponse, RiskLevel,
    MitmSummary, BlockedRequest,
)
from app.services.domain_service import analyze_domain
from app.services.nlp_service import analyze_nlp
from app.services.sandbox_service import analyze_visual
from app.services.llm_service import generate_verdict, generate_scam_arc, generate_annotations
from app.database import get_cached_result, set_cached_result
from urllib.parse import urlparse

router = APIRouter()


def score_to_risk(score: int) -> RiskLevel:
    if score >= 70:
        return RiskLevel.DANGEROUS
    elif score >= 40:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.SAFE


def _build_mitm_summary(raw_data: dict) -> MitmSummary | None:
    """
    Pull mitmproxy data out of visual_result.raw_data and build a clean
    MitmSummary object for the API response.
    Returns None if no mitm data is present (local dev mode).
    """
    mitm = raw_data.get("mitm")
    if not mitm:
        return None

    tlog = mitm.get("traffic_log", [])
    page_domain = urlparse(raw_data.get("final_url", "")).netloc

    external_post_domains = list({
        e["host"] for e in tlog
        if e.get("method") == "POST"
        and e.get("host")
        and e["host"] != page_domain
    })

    blocked = [
        BlockedRequest(**b) for b in mitm.get("blocked_requests", [])
        if all(k in b for k in ["timestamp", "url", "host", "method", "reason"])
    ]

    return MitmSummary(
        terminated_early=mitm.get("terminated_early", False),
        termination_reason=mitm.get("termination_reason", ""),
        blocked_requests=blocked,
        total_requests_captured=len(tlog),
        external_post_domains=external_post_domains,
    )


@router.post("/", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):

    # 1. Cache check
    cache_key = hashlib.md5(req.url.encode()).hexdigest()
    cached = await get_cached_result(cache_key)
    if cached:
        cached["cached"] = True
        return AnalyzeResponse(**cached)

    # 2. Run domain + nlp + sandbox in parallel
    try:
        domain_result, nlp_result, visual_result = await asyncio.gather(
            analyze_domain(req.url),
            analyze_nlp(req.message or ""),
            analyze_visual(req.url),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    # 3. Composite score
    raw_score = domain_result.score + nlp_result.score + visual_result.score
    composite_score = min(raw_score, 100)

    # 4. LLM verdict + scam arc
    verdict_data, scam_arc = await asyncio.gather(
        generate_verdict(req, domain_result, nlp_result, visual_result),
        generate_scam_arc(req.url, composite_score),
    )

    # 5. Screenshot annotations
    annotations = await generate_annotations(
        visual_result.raw_data.get("screenshot_b64")
    )

    # 6. Build mitmproxy summary
    mitm_summary = _build_mitm_summary(visual_result.raw_data)

    # 7. If mitm terminated early, bump score — this is strong evidence
    final_score = verdict_data.get("score", composite_score)
    if mitm_summary and mitm_summary.terminated_early:
        final_score = min(final_score + 20, 100)

    # 8. Build response
    response = AnalyzeResponse(
        score=final_score,
        risk_level=score_to_risk(final_score),
        verdict_en=verdict_data.get("verdict_en", "Analysis complete."),
        verdict_hi=verdict_data.get("verdict_hi", "विश्लेषण पूर्ण।"),
        tactics=verdict_data.get("tactics", []),
        domain_signals=domain_result.raw_data,
        nlp_signals=nlp_result.raw_data,
        visual_signals=visual_result.raw_data,
        screenshot_b64=visual_result.raw_data.get("screenshot_b64"),
        annotations=annotations,
        scam_arc=scam_arc,
        mitm_summary=mitm_summary,
    )

    # 9. Cache
    await set_cached_result(cache_key, response.dict())
    return response