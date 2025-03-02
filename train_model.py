import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score

# Dataset path
dataset_path = "dataset.csv"

# Try different encodings
try:
    train_data = pd.read_csv(dataset_path, encoding="utf-8")
except UnicodeDecodeError:
    print("⚠️ UTF-8 decoding failed. Trying alternative encoding...")
    train_data = pd.read_csv(dataset_path, encoding="ISO-8859-1")

# Detect if file is UTF-16 and reload with proper encoding
if train_data.columns[0].startswith("ÿþ"):
    print("⚠️ Detected UTF-16 encoding. Re-reading with correct encoding...")
    train_data = pd.read_csv(dataset_path, encoding="utf-16")

# Fix column names (strip spaces, remove unexpected characters)
train_data.columns = train_data.columns.str.strip()

print("✅ Corrected Column Names:", list(train_data.columns))

# Ensure expected columns exist
expected_columns = {"protocol_type", "service", "flag", "src_bytes", "dst_bytes", "label"}
missing_columns = expected_columns - set(train_data.columns)

if missing_columns:
    raise KeyError(f"❌ Missing expected columns: {missing_columns}")

# Identify categorical columns
object_columns = train_data.select_dtypes(include=['object']).columns.tolist()
print("🔍 Object columns before processing:", object_columns)

# Encode categorical features
label_encoders = {}
for col in object_columns:
    print(f"⚠️ Encoding categorical column: {col}")
    le = LabelEncoder()
    train_data[col] = le.fit_transform(train_data[col])
    label_encoders[col] = le  # Store encoder for future use

# Ensure all columns are numeric
print("✅ Updated data types:")
print(train_data.dtypes)

# Handle missing values
train_data.fillna(0, inplace=True)

# Separate features and label
X = train_data.drop(columns=["label"])
y = train_data["label"]

# Apply feature scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"🎯 Model trained successfully with accuracy: {accuracy:.4f}")

# Save the trained model and scaler
with open("scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open("intrusion_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("✅ Model and scaler saved successfully!")
