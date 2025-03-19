from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash
from flask_pymongo import PyMongo
from flask_mail import Mail, Message
from flask_cors import CORS
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP
from event_logger import start_monitoring as start_event_monitoring
from network_traffic_logger import start_network_logging
from windows_event_monitor import start_windows_event_monitor
from insider_threat_detection import start_monitoring
from werkzeug.security import generate_password_hash, check_password_hash
from monitoring import start_all_monitors
# Call the function
start_all_monitors()
import os
import secrets
import logging
import threading
import subprocess
import time
import threat_detection  
import pickle
import datetime
import socket
import pandas as pd
import sys


sys.stdout.reconfigure(encoding='utf-8')



# Initialize Flask App
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")


app.secret_key = secrets.token_hex(16)  # Secure session key

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/insider_threat_db"
mongo = PyMongo(app)

# ✅ Start the Windows event monitor thread here
start_windows_event_monitor(socketio)

# Database Collections
users_collection = mongo.db.users
threat_alerts = mongo.db.threat_alerts
system_event_logs = mongo.db.system_event_logs
network_activity_logs = mongo.db.network_activity_logs
windows_security_events = mongo.db.windows_security_events
network_logs = mongo.db.network_logs


# Flask-Mail Configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("SMTP_USER")
app.config["MAIL_PASSWORD"] = os.getenv("SMTP_PASSWORD")  # Use environment variables for security


mail = Mail(app)

with open("anomaly_model.pkl", "rb") as f:
    model = pickle.load(f)

# Function to capture and log network traffic
def capture_network_traffic():
    """ Network Traffic Capture & Anomaly Detection """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        while True:
            packet, addr = sock.recvfrom(65535)
            source, destination, payload_size = "192.168.1.1", "8.8.8.8", len(packet)
            df = pd.DataFrame([[source, destination, payload_size]], columns=["source", "destination", "payload_size"])
            df["source"] = df["source"].astype("category").cat.codes
            df["destination"] = df["destination"].astype("category").cat.codes
            prediction = model.predict(df)[0]
            log = {
                "timestamp": datetime.datetime.utcnow(),
                "source": source,
                "destination": destination,
                "protocol": "TCP",
                "payload_size": payload_size,
                "anomaly": prediction == -1
            }
            network_activity_logs.insert_one(log)
            socketio.emit("update_network_activity", log)
            if prediction == -1:
                logger.warning(f"[ALERT] Network Anomaly Detected: {log}")
    except Exception as e:
        logger.error(f"Error in network capture: {e}")
def stream_logs_to_dashboard():
    """ Periodically stream logs to frontend """
    while True:
        logs = {
            "threat_alerts": list(threat_alerts.find().sort("_id", -1).limit(10)),
            "system_event_logs": list(system_event_logs.find().sort("_id", -1).limit(10)),
            "network_activity_logs": list(network_activity_logs.find().sort("_id", -1).limit(10)),
            "windows_security_events": list(windows_security_events.find().sort("_id", -1).limit(10))
        }
        for key in logs:
            for log in logs[key]:
                log["_id"] = str(log["_id"])
        socketio.emit("update_dashboard", logs)
        time.sleep(5)


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def safe_thread_start(target_func, *args):
    """ Start a thread safely with exception handling. """
    try:
        t = threading.Thread(target=target_func, args=args, daemon=True)
        t.start()
        logging.info(f"✅ Started thread: {target_func.__name__} (Thread ID: {t.ident})")
    except Exception as e:
        logging.error(f"❌ Error starting thread {target_func.__name__}: {e}")

def start_logging_threads():
    """ Start all monitoring threads and confirm they run. """
    safe_thread_start(start_monitoring)
    safe_thread_start(start_event_monitoring)
    safe_thread_start(start_network_logging)
    safe_thread_start(stream_logs_to_dashboard)
    safe_thread_start(capture_network_traffic)


# Users Collection
users_collection = mongo.db.users

# --------------------------
# Logger Setup
# --------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('app.log')
stream_handler = logging.StreamHandler()

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# --------------------------
# Role-Based Access Control (RBAC)
# --------------------------
from functools import wraps

def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            if "user" not in session or session["user"]["role"] != required_role:
                return jsonify({"msg": "Access denied, insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return decorated_function
    return wrapper

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
        return jsonify({"msg": "Missing JSON data"}), 400

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
    send_email_alert("User Login", f"User {username} has logged in.")

    return jsonify({"msg": "Login successful!", "redirect": "/dashboard"}), 200

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop("user", None)
    logger.info('User logged out successfully')
    return redirect(url_for("index"))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if "user" not in session:
        logger.warning("Unauthorized access to dashboard")
        return redirect(url_for("login"))

    logger.info(f"Dashboard accessed by {session['user']['username']}")
    return render_template("dashboard.html", username=session["user"]["username"])

@app.route('/admin-panel', methods=['GET'])
@role_required("Admin")
def admin_panel():
    logger.info('Admin panel accessed')
    return jsonify({"msg": "Welcome to the Admin Panel"}), 200

@app.route('/viewer-section', methods=['GET'])
@role_required("Viewer")
def viewer_section():
    logger.info('Viewer section accessed')
    return jsonify({"msg": "Welcome to the Viewer Section"}), 200

def send_email_alert(subject, body):
    try:
        msg = Message(subject, sender=os.getenv("SMTP_USER"), recipients=[os.getenv("ALERT_EMAIL")])
        msg.body = body
        mail.send(msg)
        print("[EMAIL] Alert sent successfully!")
    except Exception as e:
        logger.error(f"[EMAIL] Error sending alert: {e}")

@app.route('/api/threat_alerts')
def get_threat_alerts():
    try:
        alerts = list(threat_alerts.find().sort('timestamp', -1).limit(10))
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append({
                'timestamp': alert.get('timestamp', ''),
                'user': alert.get('user', 'Unknown'),
                'message': alert.get('message', 'No details')
            })
        return jsonify(formatted_alerts), 200
    except Exception as e:
        logger.error(f"Error fetching threat alerts: {e}")
        return jsonify({"msg": "Error fetching threat alerts"}), 500

# ✅ Updated Network Logs API Route
@app.route('/api/network_activity_logs')
def get_network_logs():
    try:
        logs = list(network_activity_logs.find().sort('timestamp', -1).limit(10))
        formatted_logs = []
        for log in logs:
            formatted_logs.append({
                'timestamp': log.get('timestamp', ''),
                'source_ip': log.get('source', 'N/A'),          # Corrected to 'source'
                'destination_ip': log.get('destination', 'N/A'),  # Corrected to 'destination'
                'protocol': log.get('protocol', 'N/A'),
                'data_size': len(log.get('payload', ''))  # Optional: Calculate size if payload exists
            })
        return jsonify(formatted_logs), 200
    except Exception as e:
        logger.error(f"Error fetching network logs: {e}")
        return jsonify({"msg": "Error fetching network logs"}), 500

# ✅ System Logs API Route
@app.route('/api/system_logs')
def get_system_logs():
    try:
        logs = list(system_event_logs.find().sort('timestamp', -1).limit(10))
        formatted_logs = []
        for log in logs:
            formatted_logs.append({
                'timestamp': log.get('timestamp', ''),
                'event': log.get('source', 'Unknown Source'),
                'details': f"From {log.get('source', 'N/A')} to {log.get('destination', 'N/A')} Protocol: {log.get('protocol', 'N/A')}"
            })
        return jsonify(formatted_logs), 200
    except Exception as e:
        logger.error(f"Error fetching system logs: {e}")
        return jsonify({"msg": "Error fetching system logs"}), 500

# ✅ Updated Windows Security Events API Route
@app.route('/api/windows_events')
def get_windows_events():
    try:
        events = list(windows_security_events.find().sort('time_generated', -1).limit(10))
        formatted_events = []
        for event in events:
            formatted_events.append({
                'time_generated': event.get('time_generated', ''),   # Timestamp field
                'event_id': event.get('event_id', 'N/A'),
                'event_name': event.get('event_name', 'N/A'),
                'source': event.get('source', 'N/A'),
                'user': event.get('user', 'N/A'),
                'message': str(event.get('message', 'No Message'))
            })
        return jsonify(formatted_events), 200
    except Exception as e:
        logger.error(f"Error fetching Windows events: {e}")
        return jsonify({"msg": "Error fetching Windows events"}), 500

# --------------------------
# Run Flask App
# --------------------------
if __name__ == '__main__':
    print("🚀 Starting Insider Threat Detection System...")
    threat_detection.start_threat_monitoring()
    start_all_monitors

# Call the function


     
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
