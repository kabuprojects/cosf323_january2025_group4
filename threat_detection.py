import os
import json
import time
import smtplib
import threading
import torch
import numpy as np
import pywt
import win32evtlog
import pymongo
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pymongo import MongoClient
from torch import nn, optim

# MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]
collection = db["logs"]

# Load Email Credentials from Environment Variables (Best Practice)
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "your_sender_email@example.com")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER", "your_receiver_email@example.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "your_password")


def save_log(event):
    collection.insert_one(event)

def send_email_alert(alert_data):
    try:
        # Prepare the email
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = "🚨 Insider Threat Alert 🚨"

        # Ensure timestamp is stringified for JSON
        alert_data['timestamp'] = str(alert_data.get('timestamp', ''))

        # Compose body with proper emoji and JSON formatting
        body = f"⚠️ Insider Threat Detected ⚠️\n\nDetails:\n{json.dumps(alert_data, indent=2)}"
        msg.attach(MIMEText(body, 'plain', 'utf-8'))  # utf-8 for emojis

        # Send the email
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        logging.info("[EMAIL] Alert sent successfully!")

    except Exception as e:
        logging.error(f"[EMAIL] Error: {e}")
# Real-time System Monitoring
def monitor_windows_logs():
    server = "localhost"
    log_type = "Security"
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    print("[*] Starting Windows Event Log Monitoring...")

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in events:
            log_entry = {
                "event_id": event.EventID,
                "source": event.SourceName,
                "category": event.EventCategory,
                "message": event.StringInserts,
                "timestamp": event.TimeGenerated,
            }
            save_log(log_entry)
            print("[+] Logged Event:", log_entry)
        time.sleep(5)

# AI Model for Anomaly Detection
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16)
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

# Train AI Model
def train_autoencoder(data):
    model = Autoencoder(input_dim=data.shape[1])
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    for epoch in range(50):
        inputs = torch.tensor(data, dtype=torch.float32)
        outputs = model(inputs)
        loss = criterion(outputs, inputs)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        print(f"Epoch {epoch+1}, Loss: {loss.item()}")

    torch.save(model.state_dict(), "anomaly_model.pth")
    print("[*] Model saved!")
    return model

# Automated Anomaly Detection
def detect_anomalies(model, log_data):
    log_tensor = torch.tensor(log_data, dtype=torch.float32)
    with torch.no_grad():
        reconstructed = model(log_tensor)
    loss = torch.mean((log_tensor - reconstructed) ** 2, dim=1)
    anomalies = loss > torch.mean(loss) + 2 * torch.std(loss)

    for i, is_anomaly in enumerate(anomalies):
        if is_anomaly:
            send_email_alert({"message": f"Log entry {i} appears abnormal."})


# Start monitoring in a separate thread
def start_threat_monitoring():
    thread = threading.Thread(target=monitor_windows_logs, daemon=True)
    thread.start()
