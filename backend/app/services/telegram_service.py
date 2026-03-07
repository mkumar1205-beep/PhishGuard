import os
import httpx
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from dotenv import load_dotenv

load_dotenv()
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

def escape_md(text: str) -> str:
    chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in chars:
        text = text.replace(char, f'\\{char}')
    return str(text)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text

    if "http://" in text or "https://" in text:
        await update.message.reply_text("🔍 Analyzing URL...")

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    "http://localhost:8000/analyze/",
                    json={"url": text.strip(), "message": ""}
                )
                data = response.json()

            print(f"[DEBUG] Full response: {data}")

            score = data.get("score", "N/A")
            risk_level = data.get("risk_level", "unknown")
            verdict_en = data.get("verdict_en", "No verdict")
            verdict_hi = data.get("verdict_hi", "")
            tactics = data.get("tactics", [])
            scam_arc = data.get("scam_arc", "")
            domain_signals = data.get("domain_signals", {})

            if risk_level == "dangerous":
                emoji = "🚨"
            elif risk_level == "suspicious":
                emoji = "⚠️"
            else:
                emoji = "✅"

            reply = (
                f"{emoji} *Risk Level:* {risk_level.upper()}\n"
                f"📊 *Risk Score:* {score}/100\n\n"
                f"🔍 *Analysis:* {escape_md(verdict_en)}\n\n"
                f"🇮🇳 *Hindi:* {escape_md(verdict_hi)}\n"
            )

            if domain_signals:
                age = domain_signals.get("domain_age_days", "unknown")
                domain = domain_signals.get("domain", "")
                reply += f"\n🌐 *Domain:* {escape_md(str(domain))}\n"
                reply += f"📅 *Domain Age:* {escape_md(str(age))} days\n"

            if tactics:
                reply += f"\n🎯 *Tactics:* {escape_md(', '.join(tactics))}"

            if scam_arc:
                reply += f"\n\n📖 *What happens if you click:*\n{escape_md(scam_arc)}"

            await update.message.reply_text(reply, parse_mode="Markdown")

        except Exception as e:
            import traceback
            traceback.print_exc()
            await update.message.reply_text(f"❌ Error: {str(e)}")

    else:
        await update.message.reply_text("ℹ️ Please send a URL starting with http:// or https://")


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📷 QR code received, analyzing...")

    try:
        photo = update.message.photo[-1]
        file = await context.bot.get_file(photo.file_id)

        async with httpx.AsyncClient(timeout=30) as client:
            image_response = await client.get(file.file_path)
            response = await client.post(
                "http://localhost:8000/analyze/qr",
                files={"file": ("qr.png", image_response.content, "image/png")}
            )
            data = response.json()

        print(f"[DEBUG] QR response: {data}")

        results = data.get("qr_results", [])
        if not results:
            await update.message.reply_text("❌ No QR code found in image")
            return

        reply = ""
        for r in results:
            if r["type"] == "upi":
                emoji = "🚨" if r["risk_level"] == "dangerous" else "⚠️" if r["risk_level"] == "suspicious" else "✅"
                reply += (
                    f"{emoji} *UPI QR Detected*\n"
                    f"👤 Payee: {escape_md(r.get('payee_name', 'Unknown'))}\n"
                    f"🏦 VPA: {escape_md(r.get('payee_vpa', 'Unknown'))}\n"
                    f"💰 Amount: ₹{escape_md(r.get('amount', '0'))}\n"
                    f"📊 Risk: {r['risk_level'].upper()}\n"
                )
                if r.get("flags"):
                    reply += f"🚩 Flags: {escape_md(', '.join(r['flags']))}\n"
            elif r["type"] == "url":
                reply += (
                    f"🔗 *URL QR Detected*\n"
                    f"📎 URL: {escape_md(r['decoded'])}\n"
                    f"ℹ️ Send this URL in chat for full analysis\n"
                )
            else:
                reply += f"📄 *Text QR:* {escape_md(r['decoded'])}\n"

        await update.message.reply_text(reply, parse_mode="Markdown")

    except Exception as e:
        import traceback
        traceback.print_exc()
        await update.message.reply_text(f"❌ Error: {str(e)}")


def run_bot():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    app.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    print("🤖 PhishGuard bot is running...")
    app.run_polling()

if __name__ == "__main__":
    run_bot()