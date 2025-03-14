import psutil
import pymongo
import time
import win32evtlog
import json

# MongoDB Connection
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["insider_threat"]
logs_collection = db["system_logs"]

def log_processes():
    analyze_logs()  # Analyze logs for suspicious activities

    for proc in psutil.process_iter(attrs=['pid', 'name', 'username']):
        log_entry = {
            "type": "process",
            "timestamp": time.time(),
            "pid": proc.info['pid'],
            "name": proc.info['name'],
            "user": proc.info['username']
        }
        logs_collection.insert_one(log_entry)

def log_network_activity():
    connections = psutil.net_connections()
    for conn in connections:
        log_entry = {
            "type": "network",
            "timestamp": time.time(),
            "local_address": conn.laddr,
            "remote_address": conn.raddr if conn.raddr else "None",
            "status": conn.status
        }
        logs_collection.insert_one(log_entry)

def log_windows_events():
    hand = win32evtlog.OpenEventLog(None, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    for event in events[:10]:
        log_entry = {
            "type": "windows_event",
            "timestamp": time.time(),
            "event_id": event.EventID,
            "event_type": event.EventType,
            "message": str(event.StringInserts) if event.StringInserts else "None"
        }
        logs_collection.insert_one(log_entry)

def analyze_logs():
    suspicious_processes = ["malicious_process.exe", "unauthorized_access"]
    print("Analyzing logs for suspicious activities...")
    
    # Check for suspicious processes
    for process in logs_collection.find({"type": "process"}):
        if process["name"] in suspicious_processes:
            print(f"Suspicious process detected: {process['name']} (PID: {process['pid']})")
    
    # Check for high frequency of file access
    file_access_counts = {}
    for log in logs_collection.find({"type": "file_access"}):
        file_access_counts[log["details"]] = file_access_counts.get(log["details"], 0) + 1
    
    for file, count in file_access_counts.items():
        if count > 10:  # Example threshold
            print(f"High frequency of access detected for file: {file} (Access Count: {count})")


if __name__ == "__main__":

    while True:
        log_processes()
        log_network_activity()
        log_windows_events()
        time.sleep(10)  # Log every 10 seconds
        analyze_logs()  # Analyze logs after logging
