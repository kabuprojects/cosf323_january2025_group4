from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["intrusion_detection_system"]

# Collections
users_collection = db["users"]
logs_collection = db["logs"]
