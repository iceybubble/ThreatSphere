from pymongo import MongoClient

c = MongoClient("mongodb://localhost:27017/")
db = c["threatsphere"]
count = db["sandbox_logs"].count_documents({})
print(f"Total logs in MongoDB: {count}")
if count:
    doc = db["sandbox_logs"].find_one(sort=[("_id",-1)])
    print("Example log:", doc)
