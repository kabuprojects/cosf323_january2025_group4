import win32evtlog
import pymongo
import time
import socketio
import threading

# MongoDB Setup
mongo_client = pymongo.MongoClient("mongodb://localhost:27017/")
db = mongo_client["insider_threat_db"]
collection = db["windows_security_events"]

# Define event categories and IDs
EVENTS_TO_MONITOR = {
    "Logon": 4624,
    "Logoff": 4634,
    "Process Creation": 4688,
    "USB Insertion": 6416,
}

def fetch_windows_events(sio):
    """Fetches Windows Security Logs and sends alerts via WebSocket"""
    server = None  
    log_handle = win32evtlog.OpenEventLog(server, "Security")

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    print("[*] Monitoring Security logs...")

    while True:
        events = win32evtlog.ReadEventLog(log_handle, flags, 0)
        if not events:
            time.sleep(2)
            continue

        for event in events:
            event_id = event.EventID & 0xFFFF  # Extract the event ID

            for event_name, monitored_id in EVENTS_TO_MONITOR.items():
                if event_id == monitored_id:
                    log_entry = {
                        "event_name": event_name,
                        "event_id": event_id,
                        "time_generated": event.TimeGenerated.Format(),
                        "source": event.SourceName,
                        "user": event.StringInserts[0] if event.StringInserts else "N/A",
                    }

                    # Save to MongoDB and get inserted_id
                    result = collection.insert_one(log_entry)
                    log_entry['_id'] = str(result.inserted_id)  # Optional: convert ObjectId to string if needed

                    # Prepare data for emitting (remove _id if not needed in frontend)
                    emit_data = log_entry.copy()
                    # If you want to completely skip _id, uncomment the next line:
                    # emit_data.pop('_id', None)

                    # Send Real-Time Alert via WebSocket
                    sio.emit("new_event", emit_data)
                    print(f"[+] Logged & Sent Event: {emit_data}")

        time.sleep(2)  # Avoid excessive polling

def start_windows_event_monitor(sio):
    """Starts the event monitor as a background thread inside Flask"""
    print("[Windows Monitor] Windows Event Monitor thread starting... ✅")
    monitor_thread = threading.Thread(target=fetch_windows_events, args=(sio,), daemon=True)
    monitor_thread.start()
