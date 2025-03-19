import json
import time
import pymongo
import smtplib
import os
import requests
import threading
from email.mime.text import MIMEText
from scapy.all import sniff, IP, TCP, UDP, Raw
import datetime  # Correct import for datetime module

# Load environment variables with default values
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = os.getenv("DB_NAME", "insider_threat_db")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "network_activity_logs")

ALERT_THRESHOLD = int(os.getenv("ALERT_THRESHOLD", 5))
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
SMTP_SERVER = os.getenv("SMTP_SERVER", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# MongoDB Connection
try:
    db_client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db_client.server_info()  # Test connection
    db = db_client[DB_NAME]
    collection = db[COLLECTION_NAME]
    print("[INFO] Connected to MongoDB.")
except Exception as e:
    print(f"[ERROR] MongoDB connection failed: {e}")
    exit(1)

suspicious_activity = {}

def send_email_alert(log_data):
    """Send email alert for suspicious activity."""
    if not (SMTP_SERVER and SMTP_USER and SMTP_PASSWORD and ALERT_EMAIL):
        print("[WARNING] Email alert settings are incomplete. Skipping email alert.")
        return
    try:
        # Convert MongoDB ObjectId and datetime for JSON serialization
        log_data["_id"] = str(log_data["_id"])
        if isinstance(log_data.get("timestamp"), datetime.datetime):
            log_data["timestamp"] = log_data["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

        # Create the email content with proper MIME formatting
        message_body = f"🚨 Suspicious network activity detected:\n\n{json.dumps(log_data, indent=4)}"
        msg = MIMEText(message_body, 'plain', 'utf-8')  # Ensure utf-8 encoding for emoji support
        msg["Subject"] = "🚨 Insider Threat Alert 🚨"
        msg["From"] = SMTP_USER
        msg["To"] = ALERT_EMAIL

        # Send the email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_EMAIL, msg.as_string())

        print("[ALERT] Email alert sent successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to send email alert: {e}")


def send_telegram_alert(log_data):
    """Send Telegram alert for suspicious activity."""
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        print("[WARNING] Telegram alert settings are incomplete. Skipping Telegram alert.")
        return
    try:
        log_data["_id"] = str(log_data["_id"])
        message = f"\U0001F6A8 Insider Threat Alert! \U0001F6A8\n\n{json.dumps(log_data, indent=4)}"
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        response = requests.post(url, json=payload)
        
        if response.status_code == 200:
            print("[ALERT] Telegram alert sent successfully.")
        else:
            print(f"[ERROR] Failed to send Telegram alert: {response.text}")
    except Exception as e:
        print(f"[ERROR] Telegram alert error: {e}")

def extract_payload(packet):
    """Extract payload data from a network packet."""
    try:
        return packet[Raw].load.decode(errors='ignore') if Raw in packet else "No Payload"
    except Exception as e:
        print(f"[ERROR] Payload extraction failed: {e}")
        return "Error extracting payload"

def log_suspicious_activity(log_data):
    """Handle logging and alerts for suspicious network activity."""
    src_ip = log_data["source"]
    suspicious_activity[src_ip] = suspicious_activity.get(src_ip, 0) + 1
    if suspicious_activity[src_ip] >= ALERT_THRESHOLD:
        send_email_alert(log_data)
        send_telegram_alert(log_data)
        suspicious_activity[src_ip] = 0  # Reset counter after alert

def process_packet(packet):
    """Process captured network packets and log suspicious activity."""
    try:
        if IP in packet:
            # Correct timestamp handling
            event_time = time.strftime("%a %b %d %H:%M:%S %Y")  # Get current time

            log_data = {
                "timestamp": datetime.datetime.strptime(event_time, "%a %b %d %H:%M:%S %Y"),  # Fixed timestamp
                "source": packet[IP].src,
                "destination": packet[IP].dst,
                "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER",
                "payload": extract_payload(packet)
            }
            inserted_log = collection.insert_one(log_data)
            log_data["_id"] = inserted_log.inserted_id
            print(f"[INFO] Log inserted: {log_data}")
            log_suspicious_activity(log_data)
    except Exception as e:
        print(f"[ERROR] Packet processing failed: {e}")

def start_network_logging():
    print("[Network Logger] 🚀 Network Traffic Logger started...")
    from scapy.all import get_if_list
    interfaces = get_if_list()
    print("[DEBUG] Available interfaces:", interfaces)

    correct_iface = "Wi-Fi"  # Replace this after printing get_if_list()

    try:
        sniff(prn=process_packet, store=False, filter="tcp or udp", iface=correct_iface)
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")
