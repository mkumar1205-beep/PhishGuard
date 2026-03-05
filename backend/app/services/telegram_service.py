import os
import asyncio
from telegram import Update
from telegram.ext import Application, MessageHandler, filters, ContextTypes
from app.services.sandbox_service import analyze_visual
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text

    # Check if message contains a URL
    if "http://" in text or "https://" in text:
        await update.message.reply_text("🔍 Analyzing URL, please wait...")

        try:
            result = await analyze_visual(text.strip())

            if result.get("screenshot"):
                await update.message.reply_text(
                    f"✅ Analysis complete for:\n{result['url']}\n\n"
                    f"📸 Screenshot captured successfully."
                )
            else:
                await update.message.reply_text("⚠️ Could not capture screenshot.")

        except Exception as e:
            await update.message.reply_text(f"❌ Error analyzing URL: {str(e)}")
    else:
        await update.message.reply_text("ℹ️ Please send a URL starting with http:// or https://")


def run_bot():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("🤖 PhishGuard bot is running...")
    app.run_polling()


if __name__ == "__main__":
    run_bot()