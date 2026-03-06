import asyncio
import base64
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
from app.models.schemas import SignalResult

SUSPICIOUS_DOM_SIGNALS = [
    "input[type='password']",
    "input[name*='otp']",
    "input[name*='pin']",
    "input[placeholder*='OTP']",
    "input[placeholder*='password']",
]

async def analyze_visual(url: str) -> SignalResult:
    score = 0
    flags = []
    raw = {}

    if not url.startswith("http"):
        url = "https://" + url

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ]
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                java_script_enabled=True,
                extra_http_headers={"DNT": "1"},
                user_agent="Mozilla/5.0 (compatible; PhishGuardBot/1.0)"
            )
            page = await context.new_page()

            # 1. Navigate with timeout
            try:
                response = await page.goto(url, timeout=8000, wait_until="domcontentloaded")
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
                await browser.close()
                return SignalResult(score=min(score, 25), flags=flags, confidence=0.6, raw_data=raw)

            # 2. Screenshot
            screenshot_bytes = await page.screenshot(full_page=True, type="png")
            raw["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode("utf-8")

            # 3. DOM signals
            dom_signals = {}
            for selector in SUSPICIOUS_DOM_SIGNALS:
                count = await page.locator(selector).count()
                if count > 0:
                    dom_signals[selector] = count

            if dom_signals:
                score += 15
                flags.append(f"Credential form detected: {list(dom_signals.keys())}")
                raw["dom_signals"] = dom_signals

            # 4. Page title urgency
            title = await page.title()
            raw["page_title"] = title
            urgency_words = ["urgent", "verify", "suspended", "blocked", "expires", "warning"]
            if any(w in title.lower() for w in urgency_words):
                score += 10
                flags.append(f"Urgency in page title: '{title}'")

            # 5. iFrame count
            iframe_count = await page.locator("iframe").count()
            if iframe_count > 2:
                score += 5
                flags.append(f"Suspicious iframes: {iframe_count}")
                raw["iframe_count"] = iframe_count

            await browser.close()

    except Exception as e:
        flags.append(f"Sandbox error: {str(e)}")
        raw["error"] = str(e)

    return SignalResult(
        score=min(score, 30),
        flags=flags,
        confidence=0.8 if raw.get("screenshot_b64") else 0.3,
        raw_data=raw
    )
