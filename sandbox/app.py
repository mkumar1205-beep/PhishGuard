"""
PhishGuard Sandbox Microservice
--------------------------------
Standalone FastAPI app. Runs ONLY in the isolated sandbox Docker container.
Has internet access to visit URLs but cannot reach any internal service.

mitmproxy runs as a subprocess on port 8080.
Playwright routes all traffic through it.
After the visit, we pull mitmproxy's captured traffic + block events.
"""

import asyncio
import base64
import importlib.util
import sys
import subprocess
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="PhishGuard Sandbox")

MITM_PROXY_PORT = 8080
MITM_ADDON_PATH = "/sandbox/mitm_addon.py"

class SandboxRequest(BaseModel):
    url: str


SUSPICIOUS_DOM_SIGNALS = [
    "input[type='password']",
    "input[name*='otp']",
    "input[name*='pin']",
    "input[placeholder*='OTP']",
    "input[placeholder*='password']",
]

BRAND_KEYWORDS = {
    "paypal": "paypal.com", "apple": "apple.com", "google": "google.com",
    "microsoft": "microsoft.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com",
    "whatsapp": "whatsapp.com", "bank": None,
    "sbi": "sbi.co.in", "hdfc": "hdfcbank.com", "icici": "icicibank.com",
    "paytm": "paytm.com", "phonepe": "phonepe.com", "irctc": "irctc.co.in",
}

URGENCY_WORDS = [
    "urgent", "verify", "suspended", "blocked", "expires", "warning",
    "immediately", "action required", "limited time", "account locked",
    "confirm now", "otp", "aadhaar", "pan card", "kyc",
]

# Fake credentials injected into forms during behavioural simulation.
# mitmproxy watches for these strings leaving in POST bodies → exfil detection.
FAKE_CREDS = {
    "username": "testuser_phishguard_9182",
    "password": "FakePass_PG_!9182",
    "otp":      "123456",
    "aadhaar":  "999999999999",
    "pan":      "ABCDE1234F",
    "phone":    "9876543210",
    "email":    "test.phishguard@mailtest.invalid",
}


# ── mitmproxy process management ──────────────────────────────────────────

def _start_mitmdump() -> subprocess.Popen:
    """Start mitmdump as a subprocess, returns the handle."""
    cmd = [
        sys.executable, "-m", "mitmdump",
        "--listen-port", str(MITM_PROXY_PORT),
        "--scripts", MITM_ADDON_PATH,
        "--ssl-insecure",
        "--quiet",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)   # wait for port to bind before Playwright launches
    return proc


def _stop_mitmdump(proc: subprocess.Popen):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def _load_mitm_module():
    """Import mitm_addon at runtime to read its live shared state."""
    spec = importlib.util.spec_from_file_location("mitm_addon", MITM_ADDON_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _get_mitm_results() -> dict:
    try:
        return _load_mitm_module().get_results()
    except Exception as e:
        return {
            "traffic_log": [],
            "blocked_requests": [],
            "terminated_early": False,
            "termination_reason": f"Could not read mitm results: {e}",
        }


def _reset_mitm():
    try:
        _load_mitm_module().reset()
    except Exception:
        pass


# ── mitmproxy traffic scoring ─────────────────────────────────────────────

def _score_mitm(mitm: dict, page_domain: str) -> tuple[int, list[str]]:
    score = 0
    flags = []

    if mitm.get("terminated_early"):
        score += 30
        flags.append(f"Proxy hard-block: {mitm.get('termination_reason', '')}")

    for b in mitm.get("blocked_requests", []):
        flags.append(f"Blocked → {b['host']}: {b['reason']}")

    tlog = mitm.get("traffic_log", [])

    # External POSTs seen at packet level (catches what Playwright misses)
    post_domains = {
        e["host"] for e in tlog
        if e.get("method") == "POST" and e.get("host") != page_domain
    }
    if post_domains:
        score += 15
        flags.append(f"Proxy: external POST to {len(post_domains)} domain(s)")

    # Credential strings seen in GET URLs (query-string exfil)
    for entry in tlog:
        url = entry.get("url", "").lower()
        if any(v.lower() in url for v in FAKE_CREDS.values()):
            score += 20
            flags.append(f"Credential data in GET URL: {entry['url'][:80]}")
            break

    # High external domain count
    external = {
        e["host"] for e in tlog
        if e.get("host") and e["host"] != page_domain
        and not e["host"].endswith("." + page_domain)
    }
    if len(external) > 10:
        score += 10
        flags.append(f"Contacted {len(external)} external domains")

    return min(score, 25), flags


# ── Behavioural simulation ────────────────────────────────────────────────

def _simulate_form_interaction(page):
    """
    Fill visible form inputs with fake credentials and try to submit.
    Forces exfiltration requests to fire so mitmproxy captures them.
    """
    field_map = {
        "input[type='email']":     FAKE_CREDS["email"],
        "input[type='tel']":       FAKE_CREDS["phone"],
        "input[type='password']":  FAKE_CREDS["password"],
        "input[name*='user']":     FAKE_CREDS["username"],
        "input[name*='mobile']":   FAKE_CREDS["phone"],
        "input[name*='phone']":    FAKE_CREDS["phone"],
        "input[name*='otp']":      FAKE_CREDS["otp"],
        "input[name*='pin']":      FAKE_CREDS["otp"],
        "input[name*='aadhaar']":  FAKE_CREDS["aadhaar"],
        "input[name*='pan']":      FAKE_CREDS["pan"],
    }
    for selector, value in field_map.items():
        try:
            loc = page.locator(selector).first
            if loc.count() > 0 and loc.is_visible():
                loc.fill(value)
        except Exception:
            pass

    # Attempt form submission
    try:
        btn = page.locator("input[type='submit'], button[type='submit']").first
        if btn.count() > 0 and btn.is_visible():
            btn.click(timeout=3000)
    except Exception:
        pass


# ── Main Playwright runner ────────────────────────────────────────────────

def _run_playwright(url: str) -> dict:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

    score = 0
    flags = []
    raw = {}
    original_url = url if url.startswith("http") else "https://" + url
    url = original_url

    _reset_mitm()
    mitm_proc = _start_mitmdump()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-plugins",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--safebrowsing-disable-auto-update",
                    f"--proxy-server=http://127.0.0.1:{MITM_PROXY_PORT}",
                ]
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                java_script_enabled=True,
                extra_http_headers={"DNT": "1"},
                user_agent="Mozilla/5.0 (compatible; PhishGuardBot/1.0)",
                ignore_https_errors=True,   # trust mitmproxy's MITM cert
            )
            page = context.new_page()
            network_requests, console_errors = [], []

            page.on("request", lambda req: network_requests.append({
                "url": req.url, "method": req.method, "resource_type": req.resource_type
            }))
            page.on("console", lambda msg: console_errors.append(
                {"type": msg.type, "text": msg.text}
            ) if msg.type in ("error", "warning") else None)

            # ── Navigate ──────────────────────────────────────────────────
            try:
                response = page.goto(url, timeout=60000, wait_until="domcontentloaded")
                raw["http_status"] = response.status if response else None
            except PlaywrightTimeout:
                score += 10
                flags.append("Page timed out — suspicious")
                raw["timeout"] = True
                try:
                    raw["screenshot_b64"] = base64.b64encode(
                        page.screenshot(full_page=True, type="png")
                    ).decode()
                except Exception:
                    pass
                browser.close()
                mitm_data = _get_mitm_results()
                raw["mitm"] = mitm_data
                ms, mf = _score_mitm(mitm_data, urlparse(url).netloc)
                return {
                    "score": min(score + ms, 40),
                    "flags": flags + mf,
                    "confidence": 0.7,
                    "raw": raw,
                }

            # Deferred JS wait
            try:
                page.wait_for_timeout(3000)
            except Exception:
                pass

            final_url = page.url
            raw["final_url"] = final_url
            page_domain = urlparse(final_url).netloc

            # ── Early termination check ───────────────────────────────────
            # mitmproxy may have already hard-blocked during page load
            mitm_early = _get_mitm_results()
            if mitm_early.get("terminated_early"):
                try:
                    raw["screenshot_b64"] = base64.b64encode(
                        page.screenshot(full_page=True, type="png")
                    ).decode()
                except Exception:
                    pass
                raw["mitm"] = mitm_early
                browser.close()
                ms, mf = _score_mitm(mitm_early, page_domain)
                flags.append("Analysis terminated — malicious activity blocked by proxy")
                return {
                    "score": min(score + ms + 30, 100),
                    "flags": flags + mf,
                    "confidence": 0.95,
                    "raw": raw,
                }

            # ── Redirect analysis ─────────────────────────────────────────
            if final_url != original_url:
                flags.append(f"Redirects to: {final_url}")
                if final_url.count("http") > 1:
                    score += 15
                    flags.append("Multiple redirect hops detected")

            # ── Playwright network signals ────────────────────────────────
            suspicious_requests = [
                req for req in network_requests
                if urlparse(req["url"]).netloc not in ("", page_domain)
                and req["method"] == "POST"
            ]
            if suspicious_requests:
                score += 20
                flags.append("Page sends data to external server")
                raw["suspicious_network_requests"] = suspicious_requests
            raw["network_requests"] = network_requests[:100]

            # ── Screenshot 1 ──────────────────────────────────────────────
            raw["screenshot_b64"] = base64.b64encode(
                page.screenshot(full_page=True, type="png")
            ).decode()

            # ── Behavioural simulation (triggers exfil for proxy to catch)
            try:
                _simulate_form_interaction(page)
            except Exception:
                pass

            try:
                page.wait_for_timeout(2000)
            except Exception:
                pass

            # ── Screenshot 2 (post-interaction) ──────────────────────────
            try:
                raw["screenshot_b64_final"] = base64.b64encode(
                    page.screenshot(full_page=True, type="png")
                ).decode()
            except Exception:
                pass

            # ── DOM signals ───────────────────────────────────────────────
            dom_signals = {}
            for sel in SUSPICIOUS_DOM_SIGNALS:
                try:
                    c = page.locator(sel).count()
                    if c > 0:
                        dom_signals[sel] = c
                except Exception:
                    pass
            if dom_signals:
                score += 15
                flags.append(f"Credential form detected: {list(dom_signals.keys())}")
                raw["dom_signals"] = dom_signals

            # ── Form action targets ───────────────────────────────────────
            forms = page.locator("form")
            suspicious_form_targets, form_actions = [], []
            for i in range(forms.count()):
                try:
                    action = forms.nth(i).get_attribute("action")
                    if action:
                        form_actions.append(action)
                        ad = urlparse(action).netloc
                        if ad and ad != page_domain:
                            suspicious_form_targets.append(action)
                    else:
                        score += 5
                        flags.append("Form without action attribute detected")
                except Exception:
                    pass
            if suspicious_form_targets:
                score += 20
                flags.append("Form submits data to external domain")
                raw["suspicious_form_targets"] = suspicious_form_targets
            raw["form_actions"] = form_actions

            # ── Title signals ─────────────────────────────────────────────
            title = page.title()
            raw["page_title"] = title
            if any(w in title.lower() for w in URGENCY_WORDS):
                score += 10
                flags.append(f"Urgency language in title: '{title}'")
            for brand, legit in BRAND_KEYWORDS.items():
                if brand in title.lower():
                    if legit is None:
                        score += 10
                        flags.append(f"Sensitive keyword '{brand}' in title")
                    elif legit not in page_domain:
                        score += 20
                        flags.append(f"Brand impersonation: '{brand}' but domain is '{page_domain}'")
                    break

            # ── iFrames ───────────────────────────────────────────────────
            try:
                ic = page.locator("iframe").count()
                if ic > 2:
                    score += 5
                    flags.append(f"Suspicious iframe count: {ic}")
                    raw["iframe_count"] = ic
            except Exception:
                pass

            # ── Cookies ───────────────────────────────────────────────────
            try:
                cookies = context.cookies()
                tracking = [c for c in cookies if c.get("domain", "") not in page_domain]
                raw["cookies_set"] = len(cookies)
                if tracking:
                    score += 5
                    flags.append(f"Third-party tracking cookies: {len(tracking)}")
                    raw["tracking_cookies"] = [c["name"] for c in tracking]
            except Exception:
                pass

            # ── Console errors ────────────────────────────────────────────
            if console_errors:
                raw["console_errors"] = console_errors[:20]
                if sum(1 for e in console_errors if e["type"] == "error") > 5:
                    score += 5
                    flags.append("High JS error count — possible obfuscated kit")

            browser.close()

    except Exception as e:
        flags.append(f"Sandbox error: {str(e)}")
        raw["error"] = str(e)

    finally:
        _stop_mitmdump(mitm_proc)

    # ── Pull final mitmproxy results ──────────────────────────────────────
    mitm_data = _get_mitm_results()
    raw["mitm"] = mitm_data
    mitm_score, mitm_flags = _score_mitm(mitm_data, urlparse(url).netloc)
    score += mitm_score
    flags += mitm_flags

    return {
        "score": score,
        "flags": flags,
        "confidence": 0.95 if raw.get("screenshot_b64") else 0.3,
        "raw": raw,
    }


# ── FastAPI endpoints ─────────────────────────────────────────────────────

@app.post("/run")
async def run_sandbox(req: SandboxRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL required")
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = await loop.run_in_executor(pool, _run_playwright, req.url)
    return result


@app.get("/health")
async def health():
    return {"status": "ok", "service": "sandbox"}