from playwright.async_api import async_playwright
import base64

async def analyze_visual(url: str) -> dict:
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.goto(url, timeout=15000)
        screenshot = await page.screenshot()
        await browser.close()
        return {
            "screenshot": base64.b64encode(screenshot).decode("utf-8"),
            "url": url
        }