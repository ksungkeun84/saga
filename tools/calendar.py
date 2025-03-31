from pymongo import MongoClient
from datetime import datetime
from typing import List

from tools.base import BaseTool


class LocalCalendarTool(BaseTool):
    def __init__(self, user_name: str, user_email: str):
        super().__init__("calendar")
        self.client = MongoClient(self.mongo_uri)
        self.user_name = user_name
        self.user_email = user_email
    
    def seed_data(self, data: List[dict]):
        db = self.client.get_database(self.tool_name)
        collection_self = db.get_collection(self.user_email)

        for event in data: 
            # Insert into self sent collection
            collection_self.insert_one(event)

            # format is "name <email>" - we want email out of it
            participants = event["participants"]
            for participant in participants:
                participant_email = self._get_email_from_field(participant)
                collection_participant = db.get_collection(participant_email)
                # Insert into recipient inbox collection
                collection_participant.insert_one(event)
    
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
        
        # Make sure user is in participants
        if f"{self.user_name} <{self.user_email}>" not in participants:
            participants.append(f"{self.user_name} <{self.user_email}>")

        event = {
            "time_from": time_from,
            "time_to": time_to,
            "event": event,
            "participants": participants,
            "details": details,
        }

        # Now add it to the calendar of all participants
        for participant in participants:
            participant_email = self._get_email_from_field(participant)
            collection = db.get_collection(participant_email)
            collection.insert_one(event)

        # Insert into self sent collection
        collection.insert_one(event)
        return True
