import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Load dataset with encoding detection and header correction
dataset_path = "dataset.csv"

try:
    train_data = pd.read_csv(dataset_path, encoding="utf-8")
except UnicodeDecodeError:
    print("⚠️ UTF-8 decoding failed. Trying alternative encoding...")
    train_data = pd.read_csv(dataset_path, encoding="ISO-8859-1")

# Fix unnamed columns issue
if train_data.columns[0].startswith("ÿ"):
    print("⚠️ Detected invalid characters in column names. Re-reading with correct encoding...")
    train_data = pd.read_csv(dataset_path, encoding="utf-16")

# If columns are unnamed, assume first row is the header
if "Unnamed" in train_data.columns[0]:
    print("⚠️ Fixing incorrect header row...")
    train_data = pd.read_csv(dataset_path, encoding="utf-16", header=1)

# Verify correct column names
print("✅ Corrected Column Names:", train_data.columns.tolist())

# Ensure 'label' column exists
if "label" not in train_data.columns:
    raise KeyError("❌ 'label' column not found in the dataset!")

# Identify object (non-numeric) columns
object_columns = train_data.select_dtypes(include=['object']).columns
print("🔍 Object columns before processing:", object_columns.tolist())

# Apply Label Encoding to categorical columns
label_encoders = {}
for col in object_columns:
    print(f"⚠️ Encoding categorical column: {col}")
    le = LabelEncoder()
    train_data[col] = le.fit_transform(train_data[col])
    label_encoders[col] = le

# Handle missing values
train_data.fillna(0, inplace=True)

# Separate features and label
X = train_data.drop(columns=["label"])
y = train_data["label"]

# Apply feature scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save the processed data
processed_data = {"X_train": X_scaled, "y_train": y}
joblib.dump(processed_data, "processed_data.pkl")
joblib.dump(scaler, "scaler.pkl")

print("✅ Processed data saved as processed_data.pkl")
print("✅ Scaler saved as scaler.pkl")
print("🎯 Preprocessing completed successfully!")
