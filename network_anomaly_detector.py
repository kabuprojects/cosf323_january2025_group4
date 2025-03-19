import socket
import struct
import datetime
import pickle
import pandas as pd
import pymongo
import threading
from flask_socketio import SocketIO
import socketio

# Connect to Flask-SocketIO Server
sio = socketio.Client()
try:
    sio.connect("http://localhost:5000")  # Adjust if Flask runs on a different port
    print("[INFO] Connected to Flask-SocketIO server.")
except Exception as e:
    print(f"[ERROR] Could not connect to Flask-SocketIO server: {e}")

# Load AI model
try:
    with open("anomaly_model.pkl", "rb") as f:
        model = pickle.load(f)
    print("[INFO] AI model loaded successfully.")
except Exception as e:
    print(f"[ERROR] Failed to load AI model: {e}")
    exit(1)

# MongoDB Connection
try:
    client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    db = client["insider_threat_db"]
    collection = db["network_logs"]
    print("[INFO] Connected to MongoDB.")
except Exception as e:
    print(f"[ERROR] MongoDB connection failed: {e}")
    exit(1)

# Function to extract details from raw packet
def parse_packet(packet):
    try:
        ip_header = struct.unpack("!BBHHHBBH4s4s", packet[:20])
        source_ip = socket.inet_ntoa(ip_header[8])
        destination_ip = socket.inet_ntoa(ip_header[9])
        payload_size = len(packet)
        return source_ip, destination_ip, payload_size
    except Exception as e:
        print(f"[ERROR] Failed to parse packet: {e}")
        return None, None, None

# Capture network traffic and detect anomalies
def capture_traffic():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        print("[INFO] Capturing network traffic...")
    except PermissionError:
        print("[ERROR] Run the script as administrator to capture packets.")
        return
    
    while True:
        try:
            packet, addr = sock.recvfrom(65535)
            source, destination, payload_size = parse_packet(packet)

            if source and destination:
                # Prepare data for model prediction
                df = pd.DataFrame([[source, destination, payload_size]], columns=["source", "destination", "payload_size"])
                df["source"], _ = pd.factorize(df["source"])
                df["destination"], _ = pd.factorize(df["destination"])
                
                prediction = model.predict(df)[0]  # -1 means anomaly

                if prediction == -1:
                    log = {
                        "timestamp": datetime.datetime.now(),
                        "source": source,
                        "destination": destination,
                        "protocol": "TCP",
                        "payload_size": payload_size,
                        "threat": True
                    }
                    try:
                        collection.insert_one(log)
                        sio.emit("update_logs", {"logs": [log]})  # Send real-time update to Flask
                        print(f"[ALERT] Anomaly detected: {log}")
                    except Exception as e:
                        print(f"[ERROR] Failed to insert log into MongoDB: {e}")
        except Exception as e:
            print(f"[ERROR] Network capture error: {e}")

# Function to run traffic monitoring in a separate thread
def start_network_monitoring():
    thread = threading.Thread(target=capture_traffic, daemon=True)
    thread.start()

if __name__ == "__main__":
    print("[INFO] Monitoring network traffic with AI-based anomaly detection...")
    start_network_monitoring()
