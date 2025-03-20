import os
import joblib
import pandas as pd
from pymongo import MongoClient
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import IsolationForest

# 🔌 MongoDB Connection
client = MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]
collection = db["threat_alerts"]

# 📥 Fetch Events from MongoDB
print("📥 Fetching historical events from MongoDB...")
events_cursor = collection.find({}, {"message": 1, "_id": 0})
messages = [event.get("message") for event in events_cursor if event.get("message")]

if not messages:
    print("⚠️ No historical events found in MongoDB. Populate the database first.")
    exit()

# 📌 Convert to DataFrame
df = pd.DataFrame(messages, columns=["message"])

# 🎯 Feature Extraction
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(df["message"])

# 🔥 Train Isolation Forest Model
model = IsolationForest(n_estimators=100, contamination=0.2, random_state=42)
model.fit(X.toarray())

# 💾 Save Model and Vectorizer
joblib.dump(model, "anomaly_detector.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ Real-time Anomaly Detection Model trained on real events and saved successfully!")
