from pymongo import MongoClient
from datetime import datetime

# 🔌 Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]
collection = db["threat_alerts"]

# 📥 Sample Historical Events (for model training)
sample_events = [
    {"timestamp": datetime.utcnow().isoformat(), "source": "System", "message": "Failed login attempt detected"},
    {"timestamp": datetime.utcnow().isoformat(), "source": "USB", "message": "USB Device Connected: 1234:abcd"},
    {"timestamp": datetime.utcnow().isoformat(), "source": "Web", "message": "Visited Website: https://github.com"},
    {"timestamp": datetime.utcnow().isoformat(), "source": "Email", "message": "Suspicious Email from spammer@example.com"},
    {"timestamp": datetime.utcnow().isoformat(), "source": "Network", "message": "Traffic: 192.168.1.5 -> 8.8.8.8 (DNS)"},
]

# 📌 Insert sample events into the database
collection.insert_many(sample_events)

print("✅ Sample events inserted into MongoDB for training.")
