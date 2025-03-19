import win32evtlog
import pymongo
import smtplib
import requests
import os
import logging
import threading
from email.mime.text import MIMEText
from datetime import datetime, timezone
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "your_email@gmail.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "recipient_email@gmail.com")

# Telegram Configuration
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "your_chat_id")

# MongoDB Connection
try:
    client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    db = client["insider_threat_db"]
    logs_collection = db["system_event_logs"]
    client.server_info()  # Test connection
except Exception as e:
    logging.error(f"[MONGODB] Connection failed: {e}")
    logs_collection = None  # Prevent crashes if DB is down

# Suspicious Event IDs
SUSPICIOUS_EVENTS = {4625, 4672, 4688, 4732, 5379}

# Logger setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def send_email_alert(subject, message):
    """Send an email alert securely."""
    if not EMAIL_PASSWORD:
        logging.error("[EMAIL] Missing email password in environment variables.")
        return

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        logging.info("[EMAIL] Alert sent!")
    except Exception as e:
        logging.error(f"[EMAIL] Error: {e}")

def send_telegram_alert(message):
    """Send a Telegram alert."""
    if not TELEGRAM_BOT_TOKEN:
        logging.error("[TELEGRAM] Missing bot token in environment variables.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}

    try:
        requests.post(url, json=payload)
        logging.info("[TELEGRAM] Alert sent!")
    except Exception as e:
        logging.error(f"[TELEGRAM] Error: {e}")

def monitor_events():
    """Continuously monitor Windows Security, System, and Application logs."""
    server = "localhost"
    log_types = ["Security", "System", "Application"]
    
    last_processed_time = datetime(2000, 1, 1, tzinfo=timezone.utc)

    logging.info("🚀 Starting real-time system monitoring...")

    while True:
        for log_type in log_types:
            hand = None
            new_logs = []

            try:
                logging.info(f"🔍 Checking {log_type} logs...")
                hand = win32evtlog.OpenEventLog(server, log_type)
                if not hand:
                    raise Exception(f"❌ Failed to open {log_type} log. Run as Administrator.")

                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)

                if not events:
                    continue

                for event in events:
                    try:
                        if not hasattr(event, "TimeGenerated"):
                            continue

                        # Convert TimeGenerated to proper datetime
                        event_time = datetime.fromtimestamp(event.TimeGenerated.timestamp(), tz=timezone.utc)
                        if event_time <= last_processed_time:
                            continue  # Instead of break, skip only that event

                        event_data = {
                            "timestamp": event_time.isoformat(),
                            "event_id": event.EventID & 0xFFFF,
                            "source": event.SourceName,
                            "category": event.EventCategory,
                            "message": " ".join(event.StringInserts) if hasattr(event, "StringInserts") and event.StringInserts else f"Event {event.EventID}"
                        }
                        new_logs.append(event_data)

                        # Alert for critical events
                        if event_data["event_id"] in SUSPICIOUS_EVENTS:
                            alert_message = (
                                f"⚠ ALERT: Suspicious activity detected!\n"
                                f"📌 Event ID: {event_data['event_id']}\n"
                                f"📜 Message: {event_data['message']}"
                            )
                            send_email_alert("🚨 Suspicious Activity Detected!", alert_message)
                            send_telegram_alert(alert_message)

                    except Exception as e:
                        logging.warning(f"[WARNING] Skipping event due to parsing error: {e}")
                        continue

                if new_logs and logs_collection:
                    try:
                        logs_collection.insert_many(new_logs)
                        logging.info(f"[LOGS] {len(new_logs)} new {log_type} events logged to MongoDB.")
                        last_processed_time = datetime.now(timezone.utc)
                    except Exception as e:
                        logging.error(f"[LOGS] Error inserting into MongoDB: {e}")

            except Exception as e:
                logging.error(f"[ERROR] Unexpected error in {log_type}: {e}")

            finally:
                if hand:
                    try:
                        win32evtlog.CloseEventLog(hand)
                    except Exception as e:
                        logging.warning(f"[WARNING] Failed to close event log handle: {e}")

        time.sleep(5)  # Prevent excessive resource use

def start_monitoring():
    """Start the event monitoring as a background thread inside Flask."""
    print("[Event Logger] System Event Logger started...")
    monitoring_thread = threading.Thread(target=monitor_events, daemon=True)
    monitoring_thread.start()
