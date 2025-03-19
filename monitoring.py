import logging
import threading
import time
from event_logger import start_monitoring as start_event_monitoring
from network_traffic_logger import start_network_logging
from windows_event_monitor import start_windows_event_monitor
from insider_threat_detection import start_monitoring

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def safe_thread_start(target_func, *args):
    """
    Start a thread safely with exception handling.
    """
    try:
        t = threading.Thread(target=target_func, args=args, daemon=True)
        t.start()
        logging.info(f"✅ Started thread: {target_func.__name__} (Thread ID: {t.ident})")
    except Exception as e:
        logging.error(f"❌ Error starting thread {target_func.__name__}: {e}")

def start_all_monitors():
    """
    Initialize and start all monitoring processes.
    """
    logging.info("🚀 Starting all monitoring services...")

    # Start Windows event monitoring
    try:
        from app import socketio  # Import socketio instance from main app
        start_windows_event_monitor(socketio)  # Pass the socketio object
        logging.info("✅ Windows Event Monitor started.")
    except Exception as e:
        logging.error(f"❌ Error starting Windows Event Monitor: {e}")

    # Start monitoring threads safely
    safe_thread_start(start_event_monitoring)
    safe_thread_start(start_network_logging)
    safe_thread_start(start_monitoring)  # Insider Threat Monitoring

    logging.info("✅ All monitoring services started successfully.")

# If run independently
if __name__ == "__main__":
    start_all_monitors()
