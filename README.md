# Intel 471 Integration for QRadar

## Overview
titan_qradar_sync provides a mechanism for synchronising data from Titan to a QRadar instance.  The following types of data are currently included in the synchronisation process:
- Malware indicators.

Synchronisation is achieved by periodically pulling data from the Titan API and submitting this to the API of the target QRadar instance.  Data may be pushed into Reference Sets and/or Reference Tables.

## Requirements
- A suitable server to host the titan_qradar_sync.py integration script. This server should have access to both the Titan API (https://api.intel471.com and the URL of the API for your QRadar instance).
- Python 3.8+ installed on the above server.
- Your Titan credentials (username and API key).
- The URL of the API for your QRadar instance.
- Your QRadar credentials (username, password and auth key).

## Configuration
The /config/titan_qradar_sync.ini contains all of the following configuration settings:

| Setting                                                 | Description                                                                                                |
| -------                                                 | -----------                                                                                                |
| files                                                   |                                                                                                            |
| config_directory                                        | The sub directory containing the config file.                                                              |
| log_directory                                           | Sub directory to which log files are written.                                                              |
| log_prefix                                              | Prefix to be used for log filenames.                                                                       |
| cursor_file_malware_indicator_sets                      | Name of the file used to store the cursor for malware indicator to Reference Set acquisitions.             |
| cursor_file_malware_indicator_tables                    | Name of the file used to store the cursor for malware indicator to Reference Table acquisitions.           |
|                                                         |                                                                                                            |
| intel471                                                |                                                                                                            |
| titan_username                                          | Titan username.                                                                                            |
| titan_api_key                                           | Titan API key.                                                                                             |
| titan_api_base_url                                      | Base URL of the Titan API.                                                                                 |
| titan_api_batch_size                                    | Maximum number of objects to obtain from Titan API for a single request (max 100).                         |
| titan_portal_base_url                                   | Base URL of the Titan portal.                                                                              |
| titan_user_agent                                        | The user agent string to be used for all requests to the Titan API.                                        |
| malware_indicators_set_initial_last_updated_timestamp   | The start point for the initial ingest of indicators to Reference Sets (unix timestamp in milliseconds).   |
| malware_indicators_table_initial_last_updated_timestamp | The start point for the initial ingest of indicators to Reference Tables (unix timestamp in milliseconds). |
|                                                         |                                                                                                            |
| qradar                                                  |                                                                                                            |
| base_url                                                | Base URL of the QRadar API (eg https://qradar-host/api/).                                                  |
| username                                                | QRadar username.                                                                                           |
| password                                                | QRadar password.                                                                                           |
| auth_key                                                | QRadar auth key.                                                                                           |
| qradar_user_agent                                       | The user agent string to be used for all requests to the QRadar API.                                       |
| populate_malware_indicator_sets                         | Populate malware indicator Reference Sets (True/False).                                                    |
| populate_malware_indicator_tables                       | Populate malware indicator Reference Tables (True/False).                                                  |
| ignore_expired_malware_indicators_sets                  | Ignore any indicators that have already expired when populating Reference Sets (True/False).               |
| ignore_expired_malware_indicators_tables                | Ignore any indicators that have already expired when populating Reference Tables (True/False).             |
| malware_indicators_set_ip_medium_confidence             | Name of the Reference Set to store IPv4 malware indicators at medium confidence level.                     |
| malware_indicators_set_ip_high_confidence               | Name of the Reference Set to store IPv4 malware indicators at high confidence level.                       |
| malware_indicators_set_hash_medium_confidence           | Name of the Reference Set to store file hash malware indicators at medium confidence level.                |
| malware_indicators_set_hash_high_confidence             | Name of the Reference Set to store file hash malware indicators at high confidence level.                  |
| malware_indicators_set_url_medium_confidence            | Name of the Reference Set to store URL malware indicators at medium confidence level.                      |
| malware_indicators_set_url_high_confidence              | Name of the Reference Set to store URL malware indicators at high confidence level.                        |
| malware_indicators_table                                | Name of the Reference Table to store malware indicators.                                                   |
| reference_set_time_to_live                              | Time To Live (TTL) for data stored in Reference Sets (eg 30 days).                                         |
| reference_table_time_to_live                            | Time To Live (TTL) for data stored in Reference Tables (eg 30 days).                                       |
| reference_set_timeout_type                              | Timeout Type for data stored in Reference Sets (eg LAST_SEEN).                                             |
| reference_table_timeout_type                            | Timeout Type for data stored in Reference Tables (eg LAST_SEEN).                                           |

Most of the config points described above are pre-populated in the sample provided.  The main items to add are the Titan credentials, the QRadar credentials and the QRadar API URL.  The values for the other config points may of course be changed to match your own requirements.

## Installation
- Copy the entire contents (files and directories) of the shared directory containing the integration to an appropriate directory on the server that will host the integration script (eg /opt/intel471/titan_qradar_sync/).
- Navigate to the directory above eg:
  ```
  cd /opt/intel471/titan_qradar_sync
  ```
- Create a virtual environment within which the integration script will run eg:
  ```
  python3 -m venv env
  ```
- Activate your virtual environment eg:
  ```
  source env/bin/activate
  ```
- Install the required packages within the virtual environment eg:
  ```
  $ pip install -r requirements.txt
  ```
- Edit the /config/titan_qradar_sync.ini file in line with your requirements (eg Titan credentials, QRadar API URL and QRadar credentials).

## Invocation
The integration script may be run manually using:
```
python3 titan_qradar_sync.py
```
However, it is recommended that the script is scheduled to run periodically (eg every 30 minutes) using at appropriate scheduling tool such as cron.  Each run will acquire any new malware indicator activity from the Titan API and push the data into the relevant QRadar Reference Sets and Reference Tables.

## Logging
Log files are written to the directory specified by the [files][log_directory] config point, using a prefix specified by the [files][log_prexix] config point.

## Cursors
The integration script acquires data from the appropriate Titan API endpoints using a stream/cursor mechanism.  This is to ensure that complete and accurate information is obtained for the target high volume and fast changing data.

Request/response cursors are used as markers for positions in the stream.  These cursors are persisted in the files specified by the [files][cursor_file_malware_indicator_sets] and [files][cursor_file_malware_indicator_tables] config points.
