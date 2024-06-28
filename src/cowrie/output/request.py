from __future__ import annotations
import requests
import os

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    request output
    """

    def start(self):
        self.addr = CowrieConfig.get("output_request", "address")

        print("Starting plugin to send logs to " + self.addr)

    def stop(self):
        print("Stopping plugin to request to " + self.addr)

    def write(self, event):
        if event["eventid"] == "cowrie.command.input":
            response = requests.post(self.addr, json={
                "src_ip": event["src_ip"],
                "time_stamp": event["timestamp"],
                "input_cmd": event["input"],
                "honeypot_name": os.getenv("HONEYPOT_NAME", "cowrie"),
                "session_id": event["session"]
            })
        



        
