import os
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

BOT_TOKEN = os.getenv("BOT_TOKEN", "8625577706:AAGaBoc3lQxx9fxE1kkY466PLhtArH3Gz-g")
OWNER_ID = int(os.getenv("OWNER_ID", "1878450954"))

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != OWNER_ID:
        await update.message.reply_text("❌ Access Denied")
        return
    kb=[[InlineKeyboardButton("📊 My Panel", callback_data="panel")]]
    await update.message.reply_text("👋 Prime Dastan Panel Live ✅", reply_markup=InlineKeyboardMarkup(kb))

async def panel_btn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q=update.callback_query
    await q.answer()
    await q.edit_message_text("📊 Panel Online ✅\n\nBot: @YourBot\nHosting: Railway\nOwner: 1878450954")

def main():
    app=Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(panel_btn))
    app.run_polling()

if __name__=="__main__":
    main()
