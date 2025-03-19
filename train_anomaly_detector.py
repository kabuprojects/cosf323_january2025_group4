import joblib
import pandas as pd
import numpy as np
from pymongo import MongoClient
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import OneClassSVM
from sklearn.utils import resample

# 🛠 Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["insider_threat_db"]  
collection = db["system_logs"]

# 📌 Load Log Data
logs = list(collection.find({}, {"_id": 0, "message": 1}))

if not logs:
    print("⚠️ No log data found in the database!")
    exit()

df = pd.DataFrame(logs)

# 🧑‍💻 Convert Log Messages into Features using TF-IDF
vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1,2), norm='l2')
X = vectorizer.fit_transform(df["message"].astype(str)).toarray()

# ⚖️ Handle Data Imbalance (Optional)
if len(X) > 10000:  # Only resample if too many logs
    X = resample(X, replace=False, n_samples=10000, random_state=42)

# 🎯 Train Isolation Forest Anomaly Detection Model
model = IsolationForest(n_estimators=200, max_samples="auto", contamination="auto", random_state=42)
model.fit(X)

# (Optional) Alternative: Train One-Class SVM
# model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
# model.fit(X)

# 💾 Save Model and Vectorizer
joblib.dump(model, "anomaly_detector.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("✅ Improved Anomaly Detection Model & Vectorizer Trained and Saved!")
