from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from flask_cors import CORS
import os
import secrets
import logging
from functools import wraps

app = Flask(__name__)
CORS(app)

# Configure Flask App
app.secret_key = secrets.token_hex(16)  # Secure session key

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/insider_threat_db"
mongo = PyMongo(app)

# Flask-Mail Configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your_email@gmail.com"
app.config["MAIL_PASSWORD"] = "your_email_password"  # Use environment variables for security

mail = Mail(app)

# Users Collection
users_collection = mongo.db.users

# --------------------------
# Logger Setup
# --------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('app.log')
stream_handler = logging.StreamHandler()

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stream_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# --------------------------
# Role-Based Access Control (RBAC) (Fixed Naming Issue)
# --------------------------
def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_function(*args, **kwargs):
            if "user" not in session or session["user"]["role"] != required_role:
                return jsonify({"msg": "Access denied, insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return decorated_function
    return wrapper

# --------------------------
# Index Route (Landing Page) - Fixed
# --------------------------
@app.route('/')
def index():
    logger.info('Index page accessed')
    return render_template('index.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html") 

    try:
        data = request.get_json()
        print("Received Data:", data)  # Debugging 

        if not data:
            return jsonify({"msg": "Invalid request format"}), 400

        full_name = data.get("full_name", "").strip()
        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "").strip()
        role = data.get("role", "User").strip()

        if not (full_name and username and email and password):
            return jsonify({"msg": "All fields are required"}), 400

        if users_collection.find_one({"username": username}):
            return jsonify({"msg": "Username already taken"}), 400
        if users_collection.find_one({"email": email}):
            return jsonify({"msg": "Email already registered"}), 400

        hashed_password = generate_password_hash(password)

        users_collection.insert_one({
            "full_name": full_name,
            "username": username,  # 🟢 Ensuring this gets saved
            "email": email,
            "password": hashed_password,
            "role": role
        })

        print("User inserted successfully")  # Debugging
        return jsonify({"msg": "Registration successful! Redirecting...", "redirect": "/login"}), 200

    except Exception as e:
        print("Error:", str(e))  # Debugging
        return jsonify({"msg": "An error occurred: " + str(e)}), 500


@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        if request.method == "GET":
            return render_template("login.html")  # Serve the login page

        data = request.get_json()
        if not data:
            return jsonify({"msg": "Missing JSON data"}), 400

        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"msg": "Username and password are required"}), 400

        # Fetch user from database
        user = users_collection.find_one({"username": username})
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"msg": "Invalid username or password"}), 401

        # Store user session properly
        session["user"] = {
            "id": str(user["_id"]),
            "username": user["username"],
            "role": user.get("role", "User")
        }

        logger.info(f"User {username} logged in successfully.")

        return jsonify({"msg": "Login successful!", "redirect": "/dashboard"}), 200

    except Exception as e:
        logger.error(f"🔥 ERROR in login: {e}")
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500


@app.route('/logout', methods=['POST'])
def logout():
    session.pop("user", None)
    logger.info('User logged out successfully')
    return jsonify({"msg": "Logged out successfully"}), 200

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')  # Renders the HTML page

    # POST request: Process password reset
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"msg": "Email is required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        logger.warning('Email not found')
        return jsonify({"msg": "Email not found"}), 404

    # Generate reset token
    reset_token = secrets.token_urlsafe(16)
    users_collection.update_one({"email": email}, {"$set": {"reset_token": reset_token}})

    # Send reset email
    reset_link = f"http://localhost:5000/reset-password/{reset_token}"
    send_email(email, "Password Reset", f"Click here to reset your password: {reset_link}")
    logger.info('Password reset link sent to user email')

    return jsonify({"msg": "Password reset link sent to your email"}), 200


@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data = request.json
    new_password = data.get('new_password')

    user = users_collection.find_one({"reset_token": token})
    if not user:
        logger.warning('Invalid or expired token')
        return jsonify({"msg": "Invalid or expired token"}), 400

    hashed_password = generate_password_hash(new_password)

    users_collection.update_one({"reset_token": token}, {"$set": {"password": hashed_password, "reset_token": None}})
    logger.info('Password reset successfully')

    return jsonify({"msg": "Password reset successful"}), 200


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if "user" not in session:  # Ensure session key is checked correctly
        logger.warning("Unauthorized access to dashboard")
        return redirect(url_for("login"))  # Redirect instead of returning JSON

    logger.info(f"Dashboard accessed by {session['user']['username']}")

    # Return HTML template with user info
    return render_template("dashboard.html", username=session["user"]["username"])

@app.route('/admin-panel', methods=['GET'])
@role_required("Admin")
def admin_panel():
    logger.info('Admin panel accessed')
    return jsonify({"msg": "Welcome to the Admin Panel"}), 200

@app.route('/viewer-section', methods=['GET'])
@role_required("Viewer")
def viewer_section():
    logger.info('Viewer section accessed')
    return jsonify({"msg": "Welcome to the Viewer Section"}), 200

def send_email(to_email, subject, body):
    try:
        msg = Message(subject, sender="your_email@gmail.com", recipients=[to_email])
        msg.body = body
        mail.send(msg)
        logger.info('Email sent successfully')
    except Exception as e:
        logger.error('Email failed: ' + str(e))

# --------------------------
# Run Flask App
# --------------------------
if __name__ == '__main__':
    app.run(debug=True)