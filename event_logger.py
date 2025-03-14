import win32evtlog
import pymongo
import smtplib
import requests
from email.mime.text import MIMEText
from datetime import datetime, timezone
import time

# MongoDB Connection
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]
logs_collection = db["system_logs"]

# Email Notification Settings
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "mwaniabenjamin210@gmail.com"
EMAIL_PASSWORD = "nbxo cuaq qopa dwaw"
EMAIL_RECEIVER = "mwaniabenjamin087@gmail.com"

# Telegram Bot Settings
TELEGRAM_BOT_TOKEN = "8173523825:AAEA1Yv5STVAzzi-gxhCtdkuEvIqjqYmOeU"
TELEGRAM_CHAT_ID = "6482574334"

# Event IDs for monitoring
EVENT_IDS = {
    "logon_success": 4624,
    "logon_fail": 4625,  # Failed login attempt
    "logoff": 4634,
    "process_creation": 4688,
    "usb_insert": 2003,  # Example, may vary
    "usb_remove": 2100,
    "privilege_escalation": 4672  # Special privilege assigned
}

def send_email_alert(subject, message):
    """Send an email alert."""
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print("[EMAIL] Alert sent!")
    except Exception as e:
        print(f"[EMAIL] Error: {e}")

def send_telegram_alert(message):
    """Send a Telegram alert."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    
    try:
        requests.post(url, json=payload)
        print("[TELEGRAM] Alert sent!")
    except Exception as e:
        print(f"[TELEGRAM] Error: {e}")

def monitor_events():
    """Continuously monitor Windows Security logs."""
    server = "localhost"
    log_type = "Security"

    print("Starting real-time system monitoring...")

    while True:
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(hand, flags, 0)

        for event in events:
            event_id = event.EventID & 0xFFFF
            event_time = datetime.fromtimestamp(event.TimeGenerated.timestamp(), timezone.utc)
            message = " ".join(event.StringInserts) if event.StringInserts else "No details"

            if event_id in EVENT_IDS.values():
                event_data = {
                    "timestamp": event_time,
                    "event_id": event_id,
                    "source": event.SourceName,
                    "category": event.EventCategory,
                    "message": message
                }

                logs_collection.insert_one(event_data)
                print(f"Logged Event: {event_data}")

                # Suspicious Activity Alerts
                if event_id == EVENT_IDS["logon_fail"]:
                    alert_msg = f"🚨 Failed Login Attempt at {event_time} \nDetails: {message}"
                    send_email_alert("Failed Login Alert", alert_msg)
                    send_telegram_alert(alert_msg)

                if event_id == EVENT_IDS["privilege_escalation"]:
                    alert_msg = f"⚠️ Privilege Escalation Detected at {event_time} \nDetails: {message}"
                    send_email_alert("Privilege Escalation Alert", alert_msg)
                    send_telegram_alert(alert_msg)

        win32evtlog.CloseEventLog(hand)
        time.sleep(5)  # Check every 5 seconds

if __name__ == "__main__":
    monitor_events()
