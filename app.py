from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)
from database import users_collection, logs_collection
import datetime
import joblib
import numpy as np

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
# Configure JWT to look in headers and cookies
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_COOKIE_SECURE'] = False  # Set to True in production (HTTPS only)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Load trained model and scaler
model = joblib.load("models/intrusion_model.pkl")
scaler = joblib.load("models/scaler.pkl")

@app.route('/')
def home():
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
@jwt_required()  # This will now check for JWT in headers and cookies
def dashboard():
    current_user = get_jwt_identity()
    return render_template('dashboard.html', user=current_user)

@app.route('/settings')
@jwt_required()  # Optional: protect this route if needed
def settings():
    current_user = get_jwt_identity()
    return render_template('settings.html', user=current_user)


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = users_collection.find_one({'email': data['email']})
    if user and bcrypt.check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=data['email'], expires_delta=datetime.timedelta(hours=1))
        response = jsonify({'token': access_token})
        set_access_cookies(response, access_token)
        return response
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if users_collection.find_one({'email': data['email']}):
        return jsonify({'message': 'User already exists'}), 400
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    users_collection.insert_one({'email': data['email'], 'password': hashed_pw})
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/logout')
def logout():
    response = jsonify({"message": "Logged out successfully"})
    unset_jwt_cookies(response)
    return redirect(url_for('login_page'))

@app.route('/logs', methods=['GET'])
@jwt_required()
def get_logs():
    try:
        logs = list(logs_collection.find({}, {"_id": 0}))  # Retrieve logs from MongoDB
        return jsonify(logs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# New endpoint for predictions
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        if "features" not in data:
            return jsonify({"error": "No features provided"}), 400

        features = np.array(data["features"]).reshape(1, -1)
        scaled_features = scaler.transform(features)
        prediction = model.predict(scaled_features)[0]
        result = "Malicious" if prediction == 1 else "Normal"
        
        # Save prediction in MongoDB logs
        logs_collection.insert_one({
            "features": data["features"],
            "prediction": result,
            "timestamp": datetime.datetime.utcnow()
        })
        
        return jsonify({"prediction": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
