import pandas as pd
import pymongo
from sklearn.ensemble import IsolationForest
import pickle

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]
collection = db["network_logs"]

# Load data from MongoDB
data = list(collection.find({}, {"_id": 0, "source": 1, "destination": 1, "payload_size": 1}))
df = pd.DataFrame(data)

# Convert IPs to numerical format
df["source"] = df["source"].astype("category").cat.codes
df["destination"] = df["destination"].astype("category").cat.codes

# Train Isolation Forest
model = IsolationForest(contamination=0.05)  # 5% anomaly threshold
model.fit(df)

# Save the model
with open("anomaly_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("[INFO] AI model trained and saved successfully.")
