import joblib
import numpy as np

# Load the processed data
processed_data = joblib.load("processed_data.pkl")
X_train = processed_data["X_train"]
y_train = processed_data["y_train"]

# Split data into training and testing sets
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X_train, y_train, test_size=0.2, random_state=42)


# Load the trained model
model = joblib.load("intrusion_model.pkl")

# Predict on a small sample
sample = X_test[:5]  # Take first 5 test samples
predictions = model.predict(sample)

print("✅ Model test complete! Predictions:", predictions)
