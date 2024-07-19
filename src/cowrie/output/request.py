from __future__ import annotations
import requests
import os
import json

import cowrie.core.output
from cowrie.core.config import CowrieConfig

class Output(cowrie.core.output.Output):
    """
    request output
    """

    def start(self):
        self.DATABASE_URL = os.getenv("COLLECTION_URL_COWRIE", "") + "insertOne"
        self.API_KEY = os.getenv("MONGO_API_KEY_COWRIE", "")
        self.HONEYPOT_NAME = os.getenv("HONEYPOT_NAME", "cowrie")

        print("Starting plugin to send logs to " + self.DATABASE_URL)

    def stop(self):
        print("Stopping plugin to request to " + self.DATABASE_URL)

    def write(self, event):
        if len(self.API_KEY) == 0:
            print("API_KEY is not set")
            return
        if self.DATABASE_URL == "insertOne":
            print("DATABASE_URL is not set")
            return

        if event["eventid"] == "cowrie.command.input":
            headers = {
                'Content-Type': 'application/json',
                'Access-Control-Request-Headers': '*',
                'api-key': self.API_KEY,
            }
            _payload = {
                "collection": "CowrieLogs",
                "database": "CowrieLogs",
                "dataSource": "CowrieLogs",
                "document": {
                    "session_id": event["session"],
                    "src_ip": event["src_ip"],
                    "time_stamp": event["timestamp"],
                    "honeypot_name": self.HONEYPOT_NAME,
                    "command": event["input"],
                    "response": "",
                    "isAnalyzed": False,
                }
            }
            response = requests.post(self.DATABASE_URL, headers=headers, data=json.dumps(_payload))
            if not response.ok:
                print("Failed to send data to " + self.DATABASE_URL)
                print(response.text)
            else:
                print("Sending CMD: " + event['input'] + " to " + self.DATABASE_URL)
        



        
