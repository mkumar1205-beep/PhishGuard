import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from app.models.schemas import SignalResult

SUSPICIOUS_DOM_SIGNALS = [
    "input[type='password']",
    "input[name*='otp']",
    "input[name*='pin']",
    "input[placeholder*='OTP']",
    "input[placeholder*='password']",
]

def _run_playwright(url: str) -> dict:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

    score = 0
    flags = []
    raw = {}

    if not url.startswith("http"):
        url = "https://" + url

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ]
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                java_script_enabled=True,
                extra_http_headers={"DNT": "1"},
                user_agent="Mozilla/5.0 (compatible; PhishGuardBot/1.0)"
            )
            page = context.new_page()

            # 1. Navigate
            try:
                response = page.goto(url, timeout=60000, wait_until="domcontentloaded")
                raw["http_status"] = response.status if response else None
                raw["final_url"] = page.url

                if page.url != url:
                    flags.append(f"Redirects to: {page.url}")
                    if page.url.count("http") > 1:
                        score += 15
                        flags.append("Multiple redirect hops detected")

            except PlaywrightTimeout:
                score += 10
                flags.append("Page timed out — suspicious")
                raw["timeout"] = True
                browser.close()
                return {"score": min(score, 25), "flags": flags, "confidence": 0.6, "raw": raw}

            # 2. Screenshot
            screenshot_bytes = page.screenshot(full_page=True, type="png")
            raw["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode("utf-8")

            # 3. DOM signals
            dom_signals = {}
            for selector in SUSPICIOUS_DOM_SIGNALS:
                count = page.locator(selector).count()
                if count > 0:
                    dom_signals[selector] = count

            if dom_signals:
                score += 15
                flags.append(f"Credential form detected: {list(dom_signals.keys())}")
                raw["dom_signals"] = dom_signals

            # 4. Page title urgency
            title = page.title()
            raw["page_title"] = title
            urgency_words = ["urgent", "verify", "suspended", "blocked", "expires", "warning"]
            if any(w in title.lower() for w in urgency_words):
                score += 10
                flags.append(f"Urgency in page title: '{title}'")

            # 5. iFrame count
            iframe_count = page.locator("iframe").count()
            if iframe_count > 2:
                score += 5
                flags.append(f"Suspicious iframes: {iframe_count}")
                raw["iframe_count"] = iframe_count

            browser.close()

    except Exception as e:
        flags.append(f"Sandbox error: {str(e)}")
        raw["error"] = str(e)

    return {"score": score, "flags": flags, "confidence": 0.8 if raw.get("screenshot_b64") else 0.3, "raw": raw}


async def analyze_visual(url: str) -> SignalResult:
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, _run_playwright, url)

    return SignalResult(
        score=min(result["score"], 30),
        flags=result["flags"],
        confidence=result["confidence"],
        raw_data=result["raw"]
    )