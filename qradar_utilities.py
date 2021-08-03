#!/usr/bin/env python3.8


import time
from typing import List, Dict
import json
import requests
from requests.exceptions import HTTPError
from urllib3.exceptions import InsecureRequestWarning
from json_utilities import json_get
from titan_qradar_sync_config import TitanQRadarSyncConfig


class QRadarUtilities:
    def __init__(self, config: TitanQRadarSyncConfig):
        self.config = config
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    def first_not_none_or_default(self, object_list: List, default):
        result = default

        try:
            for item in object_list:
                if item:
                    result = item
                    break

        except Exception as e:
            result = default

        return result

    def get_qradar_details(self) -> Dict:
        qradar_details: Dict = None

        try:
            self.config.logger.info("Attempting to get QRadar details.")
            request: str = self.config.qradar_base_url + "system/about"
            self.config.logger.info("Sending request: %s", request)

            headers = {}
            if self.config.qradar_user_agent:
                headers = {"User-Agent": self.config.qradar_user_agent}

            response = requests.get(request, headers=headers, auth=(self.config.qradar_username, self.config.qradar_password), verify=False)
            if response.status_code == 200:
                qradar_details = response.json()
            else:
                self.config.logger.info("Unable to obtain QRadar details.")

        except HTTPError as http_err:
            qradar_details = None
            self.config.logger.error("Unable to get QRadar details: %s", {http_err})

        except Exception as e:
            qradar_details = None
            self.config.logger.error("Unable to get QRadar details: %s", {e})

        return qradar_details

    def create_reference_set(self, set_name: str, element_type: str):
        success: bool = True

        try:
            params: Dict = {
                "name": set_name,
                "element_type": element_type,
                "time_to_live": self.config.qradar_reference_set_time_to_live,
                "timeout_type": self.config.qradar_reference_set_timeout_type
            }

            self.config.logger.info("Attempting to create " + set_name + " reference set.")
            request: str = self.config.qradar_base_url + "reference_data/sets"
            self.config.logger.info("Sending request: %s", request)

            headers = {}
            if self.config.qradar_user_agent:
                headers = {"User-Agent": self.config.qradar_user_agent}

            response = requests.post(request, headers=headers, auth=(self.config.qradar_username, self.config.qradar_password), verify=False, data=params)
            if response.status_code == 201:
                self.config.logger.info("Successfully created " + set_name + " reference set.")
            else:
                self.config.logger.info(response.content)
                success = False
                self.config.logger.info("Unable to create " + set_name + " reference set.")

        except Exception as e:
            success = False
            self.config.logger.error("Unable to create " + set_name + " reference set: %s", {e})

        return success

    def create_reference_table(self, table_name: str):
        success: bool = True

        try:
            key_name_types = (
                    "[{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"Malware Family\"}, " +
                    "{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"Malware Family Titan URL\"}, " +
                    "{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"Type\"}, " +
                    "{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"Indicator\"}, " +
                    "{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"Indicator Titan URL\"}, " +
                    "{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"Confidence Level\"}, " +
                    "{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"Context\"}, " +
                    "{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"GIRs\"}, " +
                    "{\"element_type\": \"ALNIC\", " +
                    "\"key_name\": \"Mitre Tactics\"}, " +
                    "{\"element_type\": \"DATE\", " +
                    "\"key_name\": \"Activity First\"}, " +
                    "{\"element_type\": \"DATE\", " +
                    "\"key_name\": \"Activity Last\"}, " +
                    "{\"element_type\": \"DATE\", " +
                    "\"key_name\": \"Expires\"}]"
            )

            params: Dict = {
                "name": table_name,
                "outer_key_label": "UID",
                "key_name_types": key_name_types,
                "element_type": "ALNIC",
                "time_to_live": self.config.qradar_reference_table_time_to_live,
                "timeout_type": self.config.qradar_reference_table_timeout_type
            }

            self.config.logger.info("Attempting to create " + table_name + " reference table.")
            request: str = self.config.qradar_base_url + "reference_data/tables"
            self.config.logger.info("Sending request: %s", request)

            headers = {}
            if self.config.qradar_user_agent:
                headers = {"User-Agent": self.config.qradar_user_agent}

            response = requests.post(request, headers=headers, auth=(self.config.qradar_username, self.config.qradar_password), verify=False, data=params)
            if response.status_code == 201:
                self.config.logger.info("Successfully created " + table_name + " reference table.")
            else:
                self.config.logger.info(response.content)
                success = False
                self.config.logger.info("Unable to create " + table_name + " reference table.")

        except Exception as e:
            success = False
            self.config.logger.error("Unable to create " + table_name + " reference table: %s", {e})

        return success

    def check_create_reference_set(self, set_name: str, element_type: str) -> bool:
        success: bool = True

        try:
            self.config.logger.info("Checking " + set_name + " reference set.")
            request: str = self.config.qradar_base_url + "reference_data/sets/" + set_name
            self.config.logger.info("Sending request: %s", request)

            headers = {}
            if self.config.qradar_user_agent:
                headers = {"User-Agent": self.config.qradar_user_agent}

            response = requests.get(request, headers=headers, auth=(self.config.qradar_username, self.config.qradar_password), verify=False)
            if response.status_code == 200:
                self.config.logger.info(set_name + " reference set detected.")
            else:
                self.config.logger.info(set_name + " reference set not detected.")
                success = self.create_reference_set(set_name, element_type)

        except Exception as e:
            success = False
            self.config.logger.error("Unable to check/create reference set: %s", {e})

        return success

    def check_create_reference_table(self, table_name: str) -> bool:
        success: bool = True

        try:
            self.config.logger.info("Checking " + table_name + " reference table.")
            request: str = self.config.qradar_base_url + "reference_data/tables/" + table_name
            self.config.logger.info("Sending request: %s", request)

            headers = {}
            if self.config.qradar_user_agent:
                headers = {"User-Agent": self.config.qradar_user_agent}

            response = requests.get(request, headers= headers, auth=(self.config.qradar_username, self.config.qradar_password), verify=False)
            if response.status_code == 200:
                self.config.logger.info(table_name + " reference table detected.")
            else:
                self.config.logger.info(table_name + " reference table not detected.")
                success = self.create_reference_table(table_name)

        except Exception as e:
            success = False
            self.config.logger.error("Unable to check/create reference table: %s", {e})

        return success

    def check_create_reference_data_structures(self) -> bool:
        success: bool = True

        try:
            # Reference sets.
            if self.config.qradar_populate_malware_indicators_sets:
                self.check_create_reference_set(self.config.qradar_malware_indicators_set_ip_medium_confidence, "IP")
                self.check_create_reference_set(self.config.qradar_malware_indicators_set_ip_high_confidence, "IP")
                self.check_create_reference_set(self.config.qradar_malware_indicators_set_hash_medium_confidence, "ALNIC")
                self.check_create_reference_set(self.config.qradar_malware_indicators_set_hash_high_confidence, "ALNIC")
                self.check_create_reference_set(self.config.qradar_malware_indicators_set_url_medium_confidence, "ALNIC")
                self.check_create_reference_set(self.config.qradar_malware_indicators_set_url_high_confidence, "ALNIC")

            # Reference tables.
            if self.config.qradar_populate_malware_indicators_tables:
                self.check_create_reference_table(self.config.qradar_malware_indicators_table)

        except Exception as e:
            success = False
            self.config.logger.error("Unable to check/create reference data structures: %s", {e})

        return success

    def submit_indicator_batch_reference_set(self, indicator_batch_reference_set: List, set_name: str):
        success: bool = True

        try:
            if len(indicator_batch_reference_set) > 0:
                request: str = self.config.qradar_base_url + "reference_data/sets/bulk_load/" + set_name
                self.config.logger.info("Sending request: %s", request)

                headers = {}
                if self.config.qradar_user_agent:
                    headers = {"User-Agent": self.config.qradar_user_agent}

                response = requests.post(request, headers=headers, auth=(self.config.qradar_username, self.config.qradar_password), verify=False, data=json.dumps(indicator_batch_reference_set))
                if response.status_code == 200:
                    self.config.logger.info("Successfully submitted reference set indicator batch.")
                else:
                    self.config.logger.info(response.content)
                    success = False
                    self.config.logger.info("Unable to submit reference set indicator batch.")

        except Exception as e:
            success = False
            self.config.logger.error("Unable to submit reference set indicator batch: %s", {e})

        return success

    def submit_indicator_batch_reference_table(self, indicator_batch_reference_table: Dict, table_name: str):
        success: bool = True

        try:
            request: str = self.config.qradar_base_url + "reference_data/tables/bulk_load/" + table_name
            self.config.logger.info("Sending request: %s", request)

            headers = {}
            if self.config.qradar_user_agent:
                headers = {"User-Agent": self.config.qradar_user_agent}

            response = requests.post(request, headers=headers, auth=(self.config.qradar_username, self.config.qradar_password), verify=False, data=json.dumps(indicator_batch_reference_table))
            if response.status_code == 200:
                self.config.logger.info("Successfully submitted reference table indicator batch.")
            else:
                self.config.logger.info(response.content)
                success = False
                self.config.logger.info("Unable to submit reference table indicator batch.")

        except Exception as e:
            success = False
            self.config.logger.error("Unable to submit reference table indicator batch: %s", {e})

        return success

    def create_indicator(self, indicator_context: str, indicator_type: str, indicator_girs: str, indicator_confidence_level: str, indicator_malware_family: str, indicator_malware_family_titan_url: str, indicator_expires: str, indicator_mitre_tactics: str, indicator_activity_first: str, indicator_activity_last: str, indicator_value: str, indicator_titan_url: str):
        indicator: Dict = {}

        try:
            indicator = {
                "Context": indicator_context,
                "Type": indicator_type,
                "GIRs": indicator_girs,
                "Confidence Level": indicator_confidence_level,
                "Malware Family": indicator_malware_family,
                "Malware Family Titan URL": indicator_malware_family_titan_url,
                "Expires": indicator_expires,
                "Mitre Tactics": indicator_mitre_tactics,
                "Indicator": indicator_value,
                "Indicator Titan URL": indicator_titan_url,
                "First Activity": indicator_activity_first,
                "Last Activity": indicator_activity_last
            }

        except Exception as e:
            indicator = {}
            self.config.logger.error("Unable to create indicator: %s", {e})

        return indicator

    def process_indicators(self, indicators: List, reference_object_type: str) -> bool:
        success: bool = True

        try:
            current_time: int = int(round(time.time() * 1000))

            if reference_object_type == "Reference Sets":
                indicator_batch_ip_medium = []
                indicator_batch_ip_high = []
                indicator_batch_hash_medium = []
                indicator_batch_hash_high = []
                indicator_batch_url_medium = []
                indicator_batch_url_high = []

                for indicator in indicators:
                    indicator_type: str = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_type"]), "")
                    indicator_confidence_level: str = self.first_not_none_or_default(json_get(indicator, ["data", "confidence"]), "")
                    indicator_expiration: int = self.first_not_none_or_default(json_get(indicator, ["data", "expiration"]), 0)

                    process_indicator: bool = True
                    if self.config.qradar_ignore_expired_malware_indicators_sets:
                        if indicator_expiration <= current_time:
                            process_indicator = False

                    if process_indicator:
                        if indicator_type == "ipv4":
                            indicator_value_ipv4 = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "address"]), "")
                            if indicator_value_ipv4:
                                if indicator_confidence_level == "high":
                                    indicator_batch_ip_high.append(indicator_value_ipv4) if indicator_value_ipv4 not in indicator_batch_ip_high else indicator_batch_ip_high
                                else:
                                    indicator_batch_ip_medium.append(indicator_value_ipv4) if indicator_value_ipv4 not in indicator_batch_ip_medium else indicator_batch_ip_medium
                        if indicator_type == "url":
                            indicator_value_url = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "url"]), "")
                            if indicator_value_url:
                                if indicator_confidence_level == "high":
                                    indicator_batch_url_high.append(indicator_value_url) if indicator_value_url not in indicator_batch_url_high else indicator_batch_url_high
                                else:
                                    indicator_batch_url_medium.append(indicator_value_url) if indicator_value_url not in indicator_batch_url_medium else indicator_batch_url_medium
                        if indicator_type == "file":
                            indicator_value_md5 = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "file", "md5"]), "")
                            if indicator_value_md5:
                                if indicator_confidence_level == "high":
                                    indicator_batch_hash_high.append(indicator_value_md5) if indicator_value_md5 not in indicator_batch_hash_high else indicator_batch_hash_high
                                else:
                                    indicator_batch_hash_medium.append(indicator_value_md5) if indicator_value_md5 not in indicator_batch_hash_medium else indicator_batch_hash_medium
                            indicator_value_sha1 = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "file", "sha1"]), "")
                            if indicator_value_sha1:
                                if indicator_confidence_level == "high":
                                    indicator_batch_hash_high.append(indicator_value_sha1) if indicator_value_sha1 not in indicator_batch_hash_high else indicator_batch_hash_high
                                else:
                                    indicator_batch_hash_medium.append(indicator_value_sha1) if indicator_value_sha1 not in indicator_batch_hash_medium else indicator_batch_hash_medium
                            indicator_value_sha256 = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "file", "sha256"]), "")
                            if indicator_value_sha256:
                                if indicator_confidence_level == "high":
                                    indicator_batch_hash_high.append(indicator_value_sha256) if indicator_value_sha256 not in indicator_batch_hash_high else indicator_batch_hash_high
                                else:
                                    indicator_batch_hash_medium.append(indicator_value_sha256) if indicator_value_sha256 not in indicator_batch_hash_medium else indicator_batch_hash_medium

                if self.config.qradar_populate_malware_indicators_sets:
                    self.submit_indicator_batch_reference_set(indicator_batch_ip_medium, self.config.qradar_malware_indicators_set_ip_medium_confidence)
                    self.submit_indicator_batch_reference_set(indicator_batch_ip_high, self.config.qradar_malware_indicators_set_ip_high_confidence)
                    self.submit_indicator_batch_reference_set(indicator_batch_hash_medium, self.config.qradar_malware_indicators_set_hash_medium_confidence)
                    self.submit_indicator_batch_reference_set(indicator_batch_hash_high, self.config.qradar_malware_indicators_set_hash_high_confidence)
                    self.submit_indicator_batch_reference_set(indicator_batch_url_medium, self.config.qradar_malware_indicators_set_url_medium_confidence)
                    self.submit_indicator_batch_reference_set(indicator_batch_url_high, self.config.qradar_malware_indicators_set_url_high_confidence)

            if reference_object_type == "Reference Tables":
                indicator_batch = {}

                for indicator in indicators:
                    indicator_uid_raw: str = self.first_not_none_or_default(json_get(indicator, ["data", "uid"]), "")
                    indicator_context: str = self.first_not_none_or_default(json_get(indicator, ["data", "context", "description"]), "")
                    indicator_type: str = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_type"]), "")
                    indicator_girs_list: str = self.first_not_none_or_default(json_get(indicator, ["data", "intel_requirements"]), [])
                    indicator_girs = ""
                    for gir in indicator_girs_list:
                        gir_name = ""
                        for gir_ref in self.config.girs:
                            if gir_ref[1] == gir:
                                gir_name = gir_ref[3]
                                break

                        if len(indicator_girs) > 0:
                            indicator_girs += ","
                        indicator_girs += "'" + gir + " - " + gir_name + "'"
                    indicator_girs = "[" + indicator_girs + "]"
                    indicator_confidence_level: str = self.first_not_none_or_default(json_get(indicator, ["data", "confidence"]), "")
                    indicator_malware_family: str = self.first_not_none_or_default(json_get(indicator, ["data", "threat", "data", "family"]), "")
                    indicator_malware_family_titan_url: str = self.config.titan_portal_base_url + "malware/" + self.first_not_none_or_default(json_get(indicator, ["data", "threat", "data", "malware_family_profile_uid"]), "")
                    indicator_expires: str = self.first_not_none_or_default(json_get(indicator, ["data", "expiration"]), "")
                    indicator_mitre_tactics: str = self.first_not_none_or_default(json_get(indicator, ["data", "mitre_tactics"]), "")
                    indicator_activity_first: str = self.first_not_none_or_default(json_get(indicator, ["activity", "first"]), "")
                    indicator_activity_last: str = self.first_not_none_or_default(json_get(indicator, ["activity", "last"]), "")
                    indicator_expiration: int = self.first_not_none_or_default(json_get(indicator, ["data", "expiration"]), 0)

                    process_indicator: bool = True
                    if self.config.qradar_ignore_expired_malware_indicators_tables:
                        if indicator_expiration <= current_time:
                            process_indicator = False

                    if process_indicator:
                        indicator_value: str = ""
                        if indicator_type == "ipv4":
                            indicator_value = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "address"]), "")
                            indicator_titan_url = self.config.titan_portal_base_url + "malware/indicator/" + self.first_not_none_or_default(json_get(indicator, ["uid"]), "")
                            indicator_uid = "ipv4-" + indicator_uid_raw
                            indicator_created = self.create_indicator(indicator_context, indicator_type, indicator_girs, indicator_confidence_level, indicator_malware_family, indicator_malware_family_titan_url, indicator_expires, indicator_mitre_tactics, indicator_activity_first, indicator_activity_last, indicator_value, indicator_titan_url)
                            if indicator_created:
                                indicator_batch[indicator_uid] = indicator_created
                        if indicator_type == "url":
                            indicator_value = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "url"]), "")
                            indicator_titan_url = self.config.titan_portal_base_url + "malware/indicator/" + self.first_not_none_or_default(json_get(indicator, ["uid"]), "")
                            indicator_uid = "url-" + indicator_uid_raw
                            indicator_created = self.create_indicator(indicator_context, indicator_type, indicator_girs, indicator_confidence_level, indicator_malware_family, indicator_malware_family_titan_url, indicator_expires, indicator_mitre_tactics, indicator_activity_first, indicator_activity_last, indicator_value, indicator_titan_url)
                            if indicator_created:
                                indicator_batch[indicator_uid] = indicator_created
                        if indicator_type == "file":
                            indicator_value = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "file", "md5"]), "")
                            indicator_titan_url = self.config.titan_portal_base_url + "malware/indicator/" + self.first_not_none_or_default(json_get(indicator, ["uid"]), "")
                            indicator_uid = "md5-" + indicator_uid_raw
                            indicator_created = self.create_indicator(indicator_context, indicator_type, indicator_girs, indicator_confidence_level, indicator_malware_family, indicator_malware_family_titan_url, indicator_expires, indicator_mitre_tactics, indicator_activity_first, indicator_activity_last, indicator_value, indicator_titan_url)
                            if indicator_created:
                                indicator_batch[indicator_uid] = indicator_created

                            indicator_value = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "file", "sha1"]), "")
                            indicator_titan_url = self.config.titan_portal_base_url + "malware/indicator/" + self.first_not_none_or_default(json_get(indicator, ["uid"]), "")
                            indicator_uid = "sha1-" + indicator_uid_raw
                            indicator_created = self.create_indicator(indicator_context, indicator_type, indicator_girs, indicator_confidence_level, indicator_malware_family, indicator_malware_family_titan_url, indicator_expires, indicator_mitre_tactics, indicator_activity_first, indicator_activity_last, indicator_value, indicator_titan_url)
                            if indicator_created:
                                indicator_batch[indicator_uid] = indicator_created

                            indicator_value = self.first_not_none_or_default(json_get(indicator, ["data", "indicator_data", "file", "sha256"]), "")
                            indicator_titan_url = self.config.titan_portal_base_url + "malware/indicator/" + self.first_not_none_or_default(json_get(indicator, ["uid"]), "")
                            indicator_uid = "sha256-" + indicator_uid_raw
                            indicator_created = self.create_indicator(indicator_context, indicator_type, indicator_girs, indicator_confidence_level, indicator_malware_family, indicator_malware_family_titan_url, indicator_expires, indicator_mitre_tactics, indicator_activity_first, indicator_activity_last, indicator_value, indicator_titan_url)
                            if indicator_created:
                                indicator_batch[indicator_uid] = indicator_created

                if self.config.qradar_populate_malware_indicators_tables:
                    self.submit_indicator_batch_reference_table(indicator_batch, self.config.qradar_malware_indicators_table)

        except Exception as e:
            success = False
            self.config.logger.error("Unable to process indicators: %s", {e})

        return success
