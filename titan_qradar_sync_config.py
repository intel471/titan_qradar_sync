#!/usr/bin/env python3.8


import os.path
from datetime import datetime
import logging
import configparser
from titan_utilities import TitanUtilities


class TitanQRadarSyncConfig:
    def __init__(self):
        self.script_path = os.path.dirname(os.path.realpath(__file__)) + "/"
        self.config = None
        self.logger = None
        self.handler_console = None
        self.formatter_console = None
        self.handler_file = None
        self.formatter_file = None
        self.files_config_directory = ""
        self.files_log_directory = ""
        self.files_log_prefix = ""
        self.files_cursor_file_malware_indicator_sets = ""
        self.files_cursor_file_malware_indicator_tables = ""
        self.titan_username = ""
        self.titan_api_key = ""
        self.titan_api_base_url = ""
        self.titan_api_batch_size = 100
        self.titan_portal_base_url = ""
        self.titan_user_agent = ""
        self.malware_indicators_set_initial_last_updated_timestamp = 0
        self.malware_indicators_table_initial_last_updated_timestamp = 0
        self.qradar_base_url = ""
        self.qradar_username = ""
        self.qradar_password = ""
        self.qradar_auth_key = ""
        self.qradar_user_agent = ""
        self.qradar_populate_malware_indicators_sets = True
        self.qradar_populate_malware_indicators_tables = True
        self.qradar_ignore_expired_malware_indicators_sets = True
        self.qradar_ignore_expired_malware_indicators_tables = True
        self.qradar_malware_indicators_table = ""
        self.qradar_malware_indicators_set_ip_medium_confidence = ""
        self.qradar_malware_indicators_set_ip_high_confidence = ""
        self.qradar_malware_indicators_set_hash_medium_confidence = ""
        self.qradar_malware_indicators_set_hash_high_confidence = ""
        self.qradar_malware_indicators_set_url_medium_confidence = ""
        self.qradar_malware_indicators_set_url_high_confidence = ""
        self.qradar_reference_set_time_to_live = ""
        self.qradar_reference_table_time_to_live = ""
        self.qradar_reference_set_timeout_type = ""
        self.qradar_reference_table_timeout_type = ""

        self.girs = []

    def initialise(self) -> bool:
        initialise_status: bool = False

        try:
            self.config = configparser.ConfigParser()
            self.config.read(self.script_path + "config/titan_qradar_sync.ini")

            self.files_config_directory = self.config.get("files", "config_directory")
            self.files_log_directory = self.config.get("files", "log_directory")
            self.files_log_prefix = self.config.get("files", "log_prefix")
            self.files_cursor_file_malware_indicator_sets = self.config.get("files", "cursor_file_malware_indicator_sets")
            self.files_cursor_file_malware_indicator_tables = self.config.get("files", "cursor_file_malware_indicator_tables")

            self.logger = logging.getLogger("titan_qradar_sync")
            self.logger.setLevel(logging.INFO)

            # Create a logging console handler and set the level to INFO.
            self.handler_console = logging.StreamHandler()
            self.handler_console.setLevel(logging.INFO)
            self.formatter_console = logging.Formatter("%(asctime)-15s - %(name)s - %(levelname)-8s - %(message)s")
            self.handler_console.setFormatter(self.formatter_console)
            self.logger.addHandler(self.handler_console)

            # Create a logging file handler and set the level to INFO.
            self.handler_file = logging.FileHandler(self.script_path + self.files_log_directory + self.files_log_prefix + datetime.now().strftime("%Y-%m-%d_%H.%M.%S") + ".txt", "w", encoding=None, delay="true")
            self.handler_file.setLevel(logging.INFO)
            self.formatter_file = logging.Formatter("%(asctime)-15s - %(name)s - %(levelname)-8s - %(message)s")
            self.handler_file.setFormatter(self.formatter_file)
            self.logger.addHandler(self.handler_file)

            self.titan_username = self.config.get("intel471", "titan_username")
            self.titan_api_key = self.config.get("intel471", "titan_api_key")
            self.titan_api_base_url = self.config.get("intel471", "titan_api_base_url")
            self.titan_api_batch_size = self.config.getint("intel471", "titan_api_batch_size")
            self.titan_portal_base_url = self.config.get("intel471", "titan_portal_base_url")
            self.titan_user_agent = self.config.get("intel471", "titan_user_agent")
            self.malware_indicators_set_initial_last_updated_timestamp = self.config.getint("intel471", "malware_indicators_set_initial_last_updated_timestamp")
            self.malware_indicators_table_initial_last_updated_timestamp = self.config.getint("intel471", "malware_indicators_table_initial_last_updated_timestamp")
            self.qradar_base_url = self.config.get("qradar", "base_url")
            self.qradar_username = self.config.get("qradar", "username")
            self.qradar_password = self.config.get("qradar", "password")
            self.qradar_auth_key = self.config.get("qradar", "auth_key")
            self.qradar_user_agent = self.config.get("qradar", "qradar_user_agent")
            self.qradar_populate_malware_indicators_sets = self.config.getboolean("qradar", "populate_malware_indicators_sets")
            self.qradar_populate_malware_indicators_tables = self.config.getboolean("qradar", "populate_malware_indicators_tables")
            self.qradar_ignore_expired_malware_indicators_sets = self.config.getboolean("qradar", "ignore_expired_malware_indicators_sets")
            self.qradar_ignore_expired_malware_indicators_tables = self.config.getboolean("qradar", "ignore_expired_malware_indicators_tables")
            self.qradar_malware_indicators_table = self.config.get("qradar", "malware_indicators_table")
            self.qradar_malware_indicators_set_ip_medium_confidence = self.config.get("qradar", "malware_indicators_set_ip_medium_confidence")
            self.qradar_malware_indicators_set_ip_high_confidence = self.config.get("qradar", "malware_indicators_set_ip_high_confidence")
            self.qradar_malware_indicators_set_hash_medium_confidence = self.config.get("qradar", "malware_indicators_set_hash_medium_confidence")
            self.qradar_malware_indicators_set_hash_high_confidence = self.config.get("qradar", "malware_indicators_set_hash_high_confidence")
            self.qradar_malware_indicators_set_url_medium_confidence = self.config.get("qradar", "malware_indicators_set_url_medium_confidence")
            self.qradar_malware_indicators_set_url_high_confidence = self.config.get("qradar", "malware_indicators_set_url_high_confidence")
            self.qradar_reference_set_time_to_live = self.config.get("qradar", "reference_set_time_to_live")
            self.qradar_reference_table_time_to_live = self.config.get("qradar", "reference_table_time_to_live")
            self.qradar_reference_set_timeout_type = self.config.get("qradar", "reference_set_timeout_type")
            self.qradar_reference_table_timeout_type = self.config.get("qradar", "reference_table_timeout_type")

            initialise_status = True

        except Exception as e:
            initialise_status = False
            print("Unable to initialise configuration.")

        return initialise_status

    def populate_girs(self, tu: TitanUtilities):
        self.girs = []

        try:
            self.logger.info("Fetching GIRs.")
            tu.get_girs(self.girs)

        except Exception as e:
            self.logger.error("Unable to populate GIRs: %s", {e})
