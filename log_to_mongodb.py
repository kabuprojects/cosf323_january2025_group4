from pymongo import MongoClient
import datetime

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Select or create a database
db = client["insider_threat_logs"]

# Select or create a collection
log_collection = db["system_logs"]

def insert_log(user, activity, details):
    """
    Inserts a log entry into MongoDB.
    
    :param user: The username performing the action
    :param activity: Type of activity (e.g., login, file_access)
    :param details: Additional details (dict)
    """
    log_entry = {
        "timestamp": datetime.datetime.utcnow(),
        "user": user,
        "activity": activity,
        "details": details
    }
    log_collection.insert_one(log_entry)
    print("Log inserted successfully!")

def fetch_logs(filter_query={}):
    """
    Fetches and prints logs based on a filter.
    
    :param filter_query: MongoDB query filter (default: all logs)
    """
    logs = log_collection.find(filter_query)
    for log in logs:
        print(log)

if __name__ == "__main__":
    # Example logs
    insert_log("john_doe", "file_access", {"file": "/sensitive/data.txt", "action": "read"})
    insert_log("alice", "login", {"status": "success"})
    insert_log("bob", "login", {"status": "failed"})

    print("\nAll Logs:")
    fetch_logs()
