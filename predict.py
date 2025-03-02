import pickle
import numpy as np
import pandas as pd

def load_model_and_scaler():
    """Load the trained model and scaler from disk."""
    with open("intrusion_model.pkl", "rb") as model_file, open("scaler.pkl", "rb") as scaler_file:
        model = pickle.load(model_file)
        scaler = pickle.load(scaler_file)
    return model, scaler

def get_user_input():
    """Collect feature values from the user."""
    print("Enter network traffic details:")
    protocol_type = int(input("Protocol Type (e.g., 0 for TCP, 1 for UDP, 2 for ICMP): "))
    service = int(input("Service (encoded numeric value): "))
    flag = int(input("Flag (encoded numeric value): "))
    src_bytes = int(input("Source Bytes: "))
    dst_bytes = int(input("Destination Bytes: "))
    return np.array([[protocol_type, service, flag, src_bytes, dst_bytes]])

def predict_traffic(model, scaler, data):
    """Scale input data and make a prediction."""
    data_scaled = scaler.transform(data)
    prediction = model.predict(data_scaled)
    return "Malicious" if prediction[0] == 1 else "Normal"

if __name__ == "__main__":
    model, scaler = load_model_and_scaler()
    user_input = get_user_input()
    result = predict_traffic(model, scaler, user_input)
    print(f"🔍 Prediction: {result}")
