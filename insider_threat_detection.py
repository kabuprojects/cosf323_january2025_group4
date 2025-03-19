import os
import time
import joblib
import numpy as np
import pymongo
import win32evtlog
import threading
from datetime import datetime, timezone
from pymongo import MongoClient
from sklearn.feature_extraction.text import TfidfVectorizer

# 🛠 Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]  # ✅ Use the correct database name
collection = db["threat_alerts"]

# 📌 Load Model and Vectorizer
MODEL_PATH = "anomaly_detector.pkl"
VECTORIZER_PATH = "vectorizer.pkl"

if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
    print("⚠️ No trained model or vectorizer found! Please run `train_anomaly_detector.py` first.")
    exit()

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
print("✅ Anomaly Detection Model & Vectorizer Loaded!")

# 🚨 Alert Function (could be extended for email/Telegram)
def send_alert(event):
    print(f"🚨 [ALERT] Suspicious Activity Detected: {event}")

# 🎯 Anomaly Detection Function
def detect_anomaly(event):
    try:
        if not event.get("message"):  # Safety check
            print("⚠️ Skipping anomaly detection due to empty message.")
            return False
        event_features = vectorizer.transform([event["message"]]).toarray()
        prediction = model.predict(event_features)
        is_anomalous = prediction[0] == -1
        if is_anomalous:
            send_alert(event)
        return is_anomalous
    except Exception as e:
        print(f"⚠️ Error in anomaly detection: {e}")
        return False

# 📝 Log Event to MongoDB
def log_event(event):
    try:
        event["timestamp"] = datetime.now(timezone.utc).isoformat()

        if detect_anomaly(event):
            print("[⚠️ ALERT] Insider Threat Detected!")
            event["threat"] = True
        else:
            print("✅ Normal Event Logged.")
            event["threat"] = False

        # Optional: You might want to use a better unique key (event_id + message hash)
        duplicate_check = {
            "event_id": event["event_id"],
            "timestamp": event["timestamp"]
        }

        if not collection.find_one(duplicate_check):
            collection.insert_one(event)
            print(f"📌 Logged Event: {event}")
        else:
            print("⚠️ Duplicate Event Skipped.")

    except Exception as e:
        print(f"⚠️ Error logging event: {e}")

# 📡 Real-Time Windows Event Log Monitoring
def monitor_logs():
    try:
        server = None  # Local machine
        log_type = "Security"

        print("🔍 Monitoring Windows Security Logs...")
        hand = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                for event in events:
                    log_event({
                        "event_id": event.EventID,
                        "source": event.SourceName,
                        "category": event.EventCategory,
                        "message": event.StringInserts[0] if event.StringInserts else "No message",
                    })
            time.sleep(3)  # Polling interval
    except Exception as e:
        print(f"⚠️ Error monitoring logs: {e}")

# 🚀 Start Monitoring in a Thread
def start_monitoring():
    print("[Threat Monitor] Insider Threat Monitoring started...")
    thread = threading.Thread(target=monitor_logs, daemon=True)
    thread.start()
    print("✅ Log monitoring started in background thread.")
