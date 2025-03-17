from pymongo import MongoClient
from datetime import datetime

MONGO_URI = "mongodb://localhost:27017/saga_tools"

class BaseTool:
    def __init__(self, tool_name):
        self.tool_name = tool_name
        self.mongo_uri = MONGO_URI

        # Make sure relevant mongoDB will be available and created
        # db = self.client.get_database(self.tool_name)
        # collection = db.get_collection(self.username + "_inbox")

        