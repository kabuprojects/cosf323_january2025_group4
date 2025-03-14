import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import json
import os

# Directory to monitor (modify as needed)
MONITOR_DIR = "C:/Users" if os.name == "nt" else "/home"

class FileMonitor(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            log_event("File Modified", event.src_path)
    
    def on_created(self, event):
        if not event.is_directory:
            log_event("File Created", event.src_path)
    
    def on_deleted(self, event):
        if not event.is_directory:
            log_event("File Deleted", event.src_path)

# Function to log events
def log_event(event_type, details, user=None):
    event = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "event_type": event_type,
        "details": details
    }
    if user:
        event["user"] = user

    print(json.dumps(event, indent=2))  # For now, just print (later we save/send)

# Monitor running processes
def monitor_processes():
    prev_processes = set(p.info["pid"] for p in psutil.process_iter(['pid']))
    while True:
        current_processes = set(p.info["pid"] for p in psutil.process_iter(['pid']))
        new_processes = current_processes - prev_processes
        terminated_processes = prev_processes - current_processes

        for pid in new_processes:
            log_event("New Process Started", psutil.Process(pid).as_dict(attrs=['pid', 'name']))
        
        for pid in terminated_processes:
            log_event("Process Terminated", {"pid": pid})
        
        prev_processes = current_processes
        time.sleep(5)  # Adjust monitoring frequency

if __name__ == "__main__":
    # Start file monitoring
    event_handler = FileMonitor()
    observer = Observer()
    observer.schedule(event_handler, MONITOR_DIR, recursive=True)
    observer.start()
    
    # Start process monitoring in a separate thread
    import threading
    process_thread = threading.Thread(target=monitor_processes, daemon=True)
    process_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
