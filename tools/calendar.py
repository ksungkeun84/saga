from pymongo import MongoClient
from datetime import datetime
from typing import List

from tools.base import BaseTool


class LocalCalendarClientTool(BaseTool):
    def __init__(self, user_email: str):
        super().__init__("calendar")
        self.client = MongoClient(self.mongo_uri)
        self.user_email = user_email
    
    def get_upcoming_events(self, limit: int = 10):
        """
        This method retrieves a list of upcoming events from the user's calendar.
        Returns a list of dictionaries containing the event details.
        """
        db = self.client.get_database(self.tool_name)
        collection = db.get_collection(self.user_email)
        
        # We want all calendar events that have not already ended
        now = datetime.now()
        events = collection.find({"time_to": {"$gte": now}}).sort("time_from", 1)
        if limit is not None:
            events = events.limit(limit)
        
        # Convert to list of dictionaries
        events = list(events)
        # Remove objectid : we only need to/from/subject/body/time
        for email in events:
            email.pop("_id", None)
        return events

    def add_calendar_event(self,
                           time_from: str,
                           time_to: str,
                           event: str,
                           participants: List[str],
                           details: str):
        db = self.client.get_database(self.tool_name)
        collection = db.get_collection(self.user_email)

        # Make sure time_from and time_to are ISO format
        try:
            # You can try to parse the string to a datetime object here if needed
            time_from = datetime.fromisoformat(time_from)
        except ValueError:
            print("Invalid date format for time_from")
        
        try:
            time_to = datetime.fromisoformat(time_to)
        except ValueError:
            print("Invalid date format for time_to")

        event = {
            "time_from": time_from,
            "time_to": time_to,
            "event": event,
            "participants": participants,
            "details": details,
        }

        # Insert into self sent collection
        collection.insert_one(event)
        return True
