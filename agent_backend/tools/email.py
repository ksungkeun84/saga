from pymongo import MongoClient
from datetime import datetime
from typing import List

from agent_backend.tools.base import BaseTool


class LocalEmailClientTool(BaseTool):
    def __init__(self, user_name: str, user_email: str):
        super().__init__("email")
        self.client = MongoClient(self.mongo_uri)
        self.user_email = user_email
        self.user_name = user_name
    
    def seed_data(self, data: List[dict]):
        db = self.client.get_database(self.tool_name)
        collection_self = db.get_collection(self.user_email + "_sent")

        for email in data: 
            # Insert into self sent collection
            collection_self.insert_one(email)

            # format is "name <email>" - we want email out of it
            recipient = self._get_email_from_field(email["to"])
            collection_recipient = db.get_collection(recipient + "_inbox")
            # Insert into recipient inbox collection
            collection_recipient.insert_one(email)
    
    def get_emails(self, limit: int = 10):
        """
        This method retrieves emails from the database.
        Returns a list of dictionaries containing the email details.
        """
        db = self.client.get_database(self.tool_name)
        collection = db.get_collection(self.user_email + "_inbox")
        # Get 'limit' most recent emails. If limit is None, get all emails.
        emails = collection.find().sort("time:", -1)
        if limit is not None:
            emails = emails.limit(limit)

        # Convert to list of dictionaries
        emails = list(emails)
        # Remove objectid : we only need from/subject/body/time
        for email in emails:
            email.pop("_id", None)
            email.pop("to", None)

        return emails

    def search_emails_by_query(self, query: str):
        """
        This method searches for emails in the inbox that match the query across all fields.
        Returns a list of dictionaries containing the email details.
        """
        db = self.client.get_database(self.tool_name)
        collection = db.get_collection(self.user_email + "_inbox")
        
        # Search for emails where any field matches the query
        emails = collection.find({
            "$or": [
                {"from": {"$regex": query, "$options": "i"}},
                {"subject": {"$regex": query, "$options": "i"}},
                {"body": {"$regex": query, "$options": "i"}},
                {"time:": {"$regex": query, "$options": "i"}}
            ]
        })
        
        # Convert to list of dictionaries
        emails = list(emails)
        # Remove objectid : we only need from/subject/body/time
        for email in emails:
            email.pop("_id", None)
            email.pop("to", None)
        return emails

    def send_email(self, to: str, subject: str, body: str):
        """
        This method sends an email to the specified recipient.
        Returns True if the email was sent successfully, False otherwise.
        """
        db = self.client.get_database(self.tool_name)
        collection_self = db.get_collection(self.user_email + "_sent")

        # TODO: Check if receipent exists
        # if to + "_inbox" not in db.list_collection_names():
        #     print(db.list_collection_names())
        #     raise ValueError(f"Recipient inbox for {to} does not exist")

        email = {
            "from": f"{self.user_name} <{self.user_email}>",
            "to": to,
            "subject": subject,
            "body": body,
            "time:": datetime.now()
        }

        # Insert into self sent collection
        collection_self.insert_one(email)
        # Insert into recipient inbox collection
        collection_recipient = db.get_collection(to + "_inbox")
        collection_recipient.insert_one(email)
        return True
