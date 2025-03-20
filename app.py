import os
import time
import joblib
import threading
import pymongo
import smtplib
import win32evtlog
import pyshark
import psutil
import browserhistory as bh
import imaplib
import email
import usb.core
import usb.util
import asyncio
from flask import request
import secrets
import logging
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pymongo import MongoClient
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask import Flask
from dotenv import load_dotenv

load_dotenv()  # Load variables from .env file

app = Flask(__name__, template_folder='templates', static_folder='static') 


# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]

collection = db["threat_alerts"]        # For logging threat alerts (existing line)
users_collection = db["users"]          # Added for handling user registration/login

app.secret_key = secrets.token_hex(16)
# Load AI Model and Vectorizer
MODEL_PATH = "anomaly_detector.pkl"
VECTORIZER_PATH = "vectorizer.pkl"

if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
    print("⚠️ No trained model or vectorizer found! Please train the model first.")
    exit()

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)
print("✅ Anomaly Detection Model Loaded!")

# Email Configuration
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "your_sender_email@example.com")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "your_receiver_email@example.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "your_password")

import logging

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a file handler or console handler
handler = logging.FileHandler('app.log')  # You can also use logging.StreamHandler() for console
handler.setLevel(logging.INFO)

# Create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(handler)

def send_email_alert(event):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = "🚨 Insider Threat Alert 🚨"

        event_details = (
            f"Timestamp: {event.get('timestamp', 'N/A')}\n"
            f"Event ID: {event.get('event_id', 'N/A')}\n"
            f"Source: {event.get('source', 'N/A')}\n"
            f"Message: {event.get('message', 'N/A')}\n"
        )
        msg.attach(MIMEText(event_details, 'plain', 'utf-8'))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print("📧 Email alert sent successfully!")
    except Exception as e:
        print(f"⚠️ Error sending email alert: {e}")

def send_alert(event):
    print(f"🚨 [ALERT] Suspicious Activity Detected: {event}")
    send_email_alert(event)

def detect_anomaly(event):
    try:
        if not event.get("message"):
            print("⚠️ Skipping anomaly detection due to empty message.")
            return False
        features = vectorizer.transform([event["message"]]).toarray()
        is_anomalous = model.predict(features)[0] == -1
        if is_anomalous:
            send_alert(event)
        return is_anomalous
    except Exception as e:
        print(f"⚠️ Error in anomaly detection: {e}")
        return False

def log_event(event):
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    collection.insert_one(event)
    print("✅ Event logged successfully!")

def monitor_system_logs():
    print("🔍 Starting Insider Threat Monitoring...")
    while True:
        events = [
            {"event_id": "4625", "source": "Security", "message": "Failed login attempt"},
            {"event_id": "4688", "source": "Security", "message": "Process created: cmd.exe"},
        ]
        for event in events:
            log_event(event)
            detect_anomaly(event)
        time.sleep(5)

def monitor_usb():
    print("🔍 Starting USB Monitoring...")
    import usb.core
    import usb.backend.libusb1

    # Correct backend loading with DLL path
    backend = usb.backend.libusb1.get_backend(find_library=lambda x: './libusb-1.0.dll')
    if backend is None:
        print("❌ libusb-1.0.dll not found or failed to load. USB monitoring may not work.")
    else:
        print("✅ libusb-1.0.dll successfully loaded for USB monitoring.")

    while True:
        try:
            # Pass the backend here
            devices = usb.core.find(find_all=True, backend=backend)
            for device in devices:
                event = {
                    "source": "USB",
                    "message": f"USB Device Connected: VendorID={hex(device.idVendor)} ProductID={hex(device.idProduct)}"
                }
                log_event(event)
                detect_anomaly(event)
        except usb.core.USBError as e:
            print(f"⚠️ USB Monitoring Error: {e}")
        except Exception as e:
            print(f"⚠️ General USB Monitoring Error: {e}")
        time.sleep(10)

def monitor_emails():
    print("🔍 Starting Email Monitoring...")
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(EMAIL_SENDER, EMAIL_PASSWORD)
        while True:
            mail.select("inbox")
            _, data = mail.search(None, "UNSEEN")
            for num in data[0].split():
                _, msg_data = mail.fetch(num, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        subject = msg["subject"]
                        sender = msg["from"]
                        event = {"source": "Email", "message": f"Suspicious Email from {sender}: {subject}"}
                        log_event(event)
                        detect_anomaly(event)
            time.sleep(20)
    except imaplib.IMAP4.error as e:
        print(f"⚠️ IMAP Login Failed: {e}")
    except Exception as e:
        print(f"⚠️ Error in email monitoring: {e}")

def monitor_web_apps():
    print("🔍 Starting Web, App & Browser History Monitoring...")
    while True:
        try:
            history = bh.get_browserhistory()
            for browser, urls in history.items():
                for url_entry in urls:
                    url = url_entry[1]
                    event = {"source": f"Browser({browser})", "message": f"Visited Website: {url}"}
                    log_event(event)
                    detect_anomaly(event)

            for proc in psutil.process_iter(['pid', 'name']):
                event = {"source": "Application", "message": f"Running Application: {proc.info['name']}"}
                log_event(event)
                detect_anomaly(event)
        except Exception as e:
            print(f"⚠️ Error in web/app monitoring: {e}")
        time.sleep(30)


def start_network_monitoring():
    try:
        print("🔍 Starting Network Traffic Monitoring...")
        network_monitor()  # Directly start the blocking network monitor
    except Exception as e:
        print(f"⚠️ Error in network monitoring: {e}")


def network_monitor():
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())  # ✅ FIX: Add this line
        capture = pyshark.LiveCapture(interface="Wi-Fi", use_json=True)
        print("✅ Network capture started. Listening for packets...")
        process_packets(capture)
    except Exception as e:
        print(f"⚠️ Error initializing network capture: {e}")


def process_packets(capture):
    for packet in capture.sniff_continuously():
        try:
            if hasattr(packet, 'ip'):
                src = packet.ip.src
                dst = packet.ip.dst
                protocol = packet.highest_layer
                event = {"source": "Network", "message": f"Traffic: {src} -> {dst} ({protocol})"}
                log_event(event)
                detect_anomaly(event)
        except AttributeError:
            # Some packets may not have IP layers, skip those
            continue
        except Exception as e:
            print(f"⚠️ Packet processing error: {e}")


def start_monitoring():
    threads = [
        threading.Thread(target=monitor_system_logs, daemon=True),
        threading.Thread(target=monitor_usb, daemon=True),
        threading.Thread(target=monitor_emails, daemon=True),
        threading.Thread(target=monitor_web_apps, daemon=True),
        threading.Thread(target=start_network_monitoring, daemon=True),
    ]
    for thread in threads:
        thread.start()
    print("✅ All Monitoring Services Started!")


@app.route('/')
def index():
    logger.info('Index page accessed')
    return render_template('index.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    data = request.get_json()
    if not data:
        return jsonify({"msg": "Invalid request format"}), 400

    full_name = data.get("full_name", "").strip()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "User").strip()

    if not (full_name and username and email and password):
        return jsonify({"msg": "All fields are required"}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"msg": "Username already taken"}), 400
    if users_collection.find_one({"email": email}):
        return jsonify({"msg": "Email already registered"}), 400

    hashed_password = generate_password_hash(password)

    users_collection.insert_one({
        "full_name": full_name,
        "username": username,
        "email": email,
        "password": hashed_password,
        "role": role
    })

    return jsonify({"msg": "Registration successful! Redirecting...", "redirect": "/login"}), 200

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json()
    if not data:
        data = request.form
    if not data:
        return jsonify({"msg": "Missing login data"}), 400

    username = data.get("username")
    password = data.get("password")

    user = users_collection.find_one({"username": username})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"msg": "Invalid username or password"}), 401

    session["user"] = {
        "id": str(user["_id"]),
        "username": user["username"],
        "role": user.get("role", "User")
    }

    logger.info(f"User {username} logged in successfully.")
    send_email_alert({"source": "User Login", "message": f"User {username} has logged in."})

    return jsonify({"msg": "Login successful!", "redirect": "/dashboard"}), 200

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if "user" not in session:
        logger.warning("Unauthorized access to dashboard")
        return redirect(url_for("login"))

    logger.info(f"Dashboard accessed by {session['user']['username']}")
    return render_template("dashboard.html", username=session["user"]["username"])

# API Endpoint to fetch real-time events from MongoDB
@app.route('/api/events')
def get_events():
    events = list(db.threat_alerts.find().sort('timestamp', -1).limit(50))  # ✅ Correct collection
    for e in events:
        e['_id'] = str(e['_id'])  # Convert ObjectId to string
    return jsonify(events)

@app.route('/api/alerts')
def get_threat_alerts():
    alerts = list(db.threat_alerts.find(
        {"threat_level": {"$in": ["High", "Critical"]}}
    ).sort('timestamp', -1).limit(50))
    for alert in alerts:
        alert['_id'] = str(alert['_id'])
    return jsonify(alerts)

if __name__ == '__main__':
    start_monitoring()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
