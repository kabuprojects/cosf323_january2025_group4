from scapy.all import sniff, IP, TCP, UDP
import pymongo
import datetime
import time

# MongoDB connection
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]
collection = db["network_logs"]

# Store logs in a batch before inserting into MongoDB
log_batch = []
BATCH_SIZE = 10  # Adjust batch size as needed
FILTER_LOCAL = True  # Set to False if you want to capture all traffic

def packet_callback(packet):
    global log_batch

    if packet.haslayer(IP):  # Ensure packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Filter out local network traffic if enabled
        if FILTER_LOCAL and (src_ip.startswith("192.168.") or dst_ip.startswith("192.168.")):
            return  # Skip local network traffic

        # Corrected timestamp handling
        event_time = time.strftime("%a %b %d %H:%M:%S %Y")  # Get current time in correct format

        log = {
            "timestamp": datetime.datetime.strptime(event_time, "%a %b %d %H:%M:%S %Y"),
            "source": src_ip,
            "destination": dst_ip,
            "protocol": "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Other",
            "payload_size": len(packet)
        }

        log_batch.append(log)

        # Insert batch into MongoDB
        if len(log_batch) >= BATCH_SIZE:
            collection.insert_many(log_batch)
            print(f"[INFO] Inserted {len(log_batch)} network logs into MongoDB")
            log_batch = []  # Clear batch

# Function to start sniffing
def capture_traffic():
    print("[INFO] Capturing network traffic using Scapy...")
    sniff(prn=packet_callback, store=False, filter="tcp or udp")  # Only capture TCP/UDP

if __name__ == "__main__":
    capture_traffic()
