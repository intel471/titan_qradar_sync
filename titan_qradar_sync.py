#!/usr/bin/env python3.8


import sys
import os
import time
from pathlib import Path
from typing import List, Dict, Union
from titan_qradar_sync_config import TitanQRadarSyncConfig
from qradar_utilities import QRadarUtilities
from titan_utilities import TitanUtilities

config: TitanQRadarSyncConfig = TitanQRadarSyncConfig()


def perform_sync(qradar: QRadarUtilities, titan: TitanUtilities, reference_object_type: str) -> bool:
    continue_sync: bool = True

    try:
        config.logger.info("Initiating sync process.")

        last_updated_from_timestamp: int = 0
        cursor: str = ""
        cursor_file: str = ""
        if reference_object_type == "Reference Sets":
            last_updated_from_timestamp = config.malware_indicators_set_initial_last_updated_timestamp
            cursor_file = config.files_cursor_file_malware_indicator_sets

        if reference_object_type == "Reference Tables":
            last_updated_from_timestamp = config.malware_indicators_table_initial_last_updated_timestamp
            cursor_file = config.files_cursor_file_malware_indicator_tables

        if os.path.exists(cursor_file):
            with open(cursor_file, 'r') as cursor_reader:
                cursor = cursor_reader.readline()
        config.logger.info("Current cursor: %s", {cursor})

        result: List = titan.get_malware_indicators(cursor, last_updated_from_timestamp)

        indicators: List = result[0]

        config.logger.info(reference_object_type + ": " + str(len(indicators)) + " indicator activity object(s) acquired.")

        if len(indicators) > 0:
            qradar.process_indicators(indicators, reference_object_type)

        if len(indicators) < config.titan_api_batch_size:
            continue_sync = False

        config.logger.info("New cursor: %s", {result[1]})
        with open(cursor_file, 'w') as cursor_writer:
            cursor_writer.writelines(result[1])

        config.logger.info("Completed sync process.")
    except Exception as e:
        continue_sync = False
        config.logger.error("An error has occurred whilst performing the sync: %s", {e})

    return continue_sync


def process_reference_objects(qradar: QRadarUtilities, titan: TitanUtilities, reference_object_type: str) -> bool:
    success: bool = True

    try:
        config.logger.info("Processing reference objects (" + reference_object_type + ").")

        batch_count_before_pause: int = 10
        batch_count_max: int = 500
        batch_count: int = 0
        continue_process: bool = True
        while continue_process:
            continue_process = perform_sync(qradar, titan, reference_object_type)
            if continue_process:
                batch_count += 1
                if batch_count == batch_count_max:
                    continue_process = False
                else:
                    if batch_count % batch_count_before_pause == 0:
                        config.logger.info("Pausing for 30 seconds.")
                        time.sleep(30)
    except Exception as e:
        success = False
        config.logger.error("An error has occurred whilst processing reference objects: %s", {e})

    return success


def main():
    try:
        config_initialise_status: bool = config.initialise()
        if config_initialise_status is False:
            sys.exit(1)

        config.logger.info("Titan to QRadar initialisation successful.")

        # Check if the manual/automatic lock files are present.
        config.logger.info("Checking for manual/auto lock files.")
        lock_auto_file = Path(config.script_path + "lock_auto_file.txt")
        lock_manual_file = Path(config.script_path + "lock_manual_file.txt")
        if lock_auto_file.is_file():
            config.logger.info("Auto lock file present - terminating process.")
            sys.exit(1)
        elif lock_manual_file.is_file():
            config.logger.info("Manual lock file present - terminating process.")
            sys.exit(1)
        else:
            config.logger.info("Lock files not present - creating auto lock file.")
            Path(config.script_path + "lock_auto_file.txt").touch()
            config.logger.info("Auto lock file created.")

        qradar: QRadarUtilities = QRadarUtilities(config)
        qradar_details: Dict = qradar.get_qradar_details()

        if qradar_details:
            config.logger.info("QRadar details: " + str(qradar_details))
            check_create_reference_data_structures: bool = qradar.check_create_reference_data_structures()
            if check_create_reference_data_structures:
                titan: TitanUtilities = TitanUtilities(config)
                if titan:
                    config.populate_girs(titan)

                    if config.qradar_populate_malware_indicators_sets:
                        process_reference_objects(qradar, titan, "Reference Sets")
                    if config.qradar_populate_malware_indicators_tables:
                        process_reference_objects(qradar, titan, "Reference Tables")

        # Delete the auto lock file.
        config.logger.info("Deleting auto lock file.")
        lock_auto_file = Path(config.script_path + "lock_auto_file.txt")
        try:
            lock_auto_file.unlink()
        except FileNotFoundError as e:
            pass
        config.logger.info("Auto lock file deleted.")

        config.logger.info("Titan to QRadar sync completed.")
    except Exception as e:
        config.logger.error("An error has occurred: %s", {e})
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
