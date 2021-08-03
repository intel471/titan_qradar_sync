#!/usr/bin/env python3.8


from typing import List
import requests
import requests.packages.urllib3
from requests.exceptions import HTTPError
from urllib3.exceptions import InsecureRequestWarning


class TitanUtilities:
    def __init__(self, config):
        self.config = config
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    def get_malware_indicators(self, cursor: str, last_updated_from_timestamp: int) -> List:
        malware_indicators: List = []
        cursor_next: str = ""

        try:
            count: int = self.config.titan_api_batch_size

            request: str = self.config.titan_api_base_url + "indicators/stream?threatType=malware&lastUpdatedFrom=" + str(last_updated_from_timestamp) + "&count=" + str(count)
            if cursor:
                request += "&cursor=" + cursor
            self.config.logger.info("Sending request: %s", request)

            headers = {}
            if self.config.titan_user_agent:
                headers = {"User-Agent": self.config.titan_user_agent}

            response = requests.get(request, headers=headers, auth=(self.config.titan_username, self.config.titan_api_key))
            if response.status_code == 200:
                results = response.json()
                if results.get("cursorNext"):
                    cursor_next: str = results["cursorNext"]
                if results.get("indicators"):
                    malware_indicators: str = results["indicators"]

        except HTTPError as http_err:
            malware_indicators = []
            self.config.logger.error("Unable to get malware indicators from Titan: %s", {http_err})

        except Exception as e:
            malware_indicators = []
            self.config.logger.error("Unable to get malware indicators from Titan: %s", {e})

        return [malware_indicators, cursor_next]

    def process_gir(self, girs: List, gir: {}):
        try:
            if gir.get("parent"):
                parent = gir["parent"]
                self.process_gir(girs, parent)

            gir_id = None  # Not used but retain for compatibility with getting GIRs from database instead of Titan.
            reference = None
            parent_reference = None
            name = None
            description = None

            if gir.get("path"):
                reference = gir["path"].strip()
            if gir.get("parent"):
                if gir.get("parent").get("path"):
                    parent_reference = gir["parent"]["path"].strip()
            if gir.get("name"):
                name = gir["name"].strip()
            if gir.get("description"):
                description = gir["description"].strip()

            found = False
            for existing_gir in girs:
                if existing_gir[1] == reference:
                    found = True
                    break

            if found is False:
                new_gir = [gir_id, reference, parent_reference, name, description]
                girs.append(new_gir)

        except Exception as e:
            self.config.logger.error("Unable to process GIR: %s", {e})

    def get_girs(self, girs: []):
        girs_raw = []

        try:
            offset = 0
            offset_max = 1000
            count = 100
            finished = False

            while not finished:
                finished = True

                request = self.config.titan_api_base_url + "girs?count=" + str(count) + "&offset=" + str(offset)
                self.config.logger.info("Sending request: %s", request)

                headers = {}
                if self.config.titan_user_agent:
                    headers = {"User-Agent": self.config.titan_user_agent}

                response = requests.get(request, headers=headers, auth=(self.config.titan_username, self.config.titan_api_key))
                if response.status_code == 200:
                    results = response.json()
                    if results.get("girs"):
                        girs_raw_batch = results["girs"]
                        if len(girs_raw_batch) > 0:
                            for gir_raw in girs_raw_batch:
                                girs_raw.append(gir_raw)

                            if len(girs_raw_batch) >= count:
                                offset = offset + count
                                if offset <= offset_max:
                                    finished = False

            if len(girs_raw) > 0:
                for gir_raw in girs_raw:
                    if gir_raw.get("data"):
                        if gir_raw.get("data").get("gir"):
                            gir = gir_raw["data"]["gir"]
                            self.process_gir(girs, gir)

        except HTTPError as http_err:
            girs = []
            self.config.logger.error("Unable to get GIRs from Titan: %s", {http_err})

        except Exception as e:
            girs = []
            self.config.logger.error("Unable to get GIRs from Titan: %s", {e})

        return girs
