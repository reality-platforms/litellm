import os
import http.client
import json

from litellm.integrations.custom_logger import CustomLogger
from datetime import datetime


def logger(payload):
    token = os.getenv("LOGTAIL_SOURCE_TOKEN")
    environment = os.getenv("RAILWAY_ENVIRONMENT_NAME")
    railwayServiceName = os.getenv("RAILWAY_SERVICE_NAME")

    if token is None:
        raise ValueError("LOGTAIL_SOURCE_TOKEN environment variable is not set")

    payload["environment"] = environment
    payload["railwayServiceName"] = railwayServiceName
    authorization = f"Bearer {token}"

    conn = http.client.HTTPSConnection("in.logs.betterstack.com")

    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json",
    }

    conn.request("POST", "/", json.dumps(payload), headers)
    res = conn.getresponse()
    data = res.read()
    print("Sent log to betterstack", data.decode("utf-8"))


def redact_api_key_info(metadata: dict) -> dict:
    """
    Redacts sensitive API key information from the metadata dictionary.

    Iterates over the key-value pairs in the provided metadata dictionary.
    If a key ends with "api_key" and the value is a string with more than
    three characters, it masks all but the last three characters of the value.
    If the value is a nested dictionary, recursively applies the same
    redaction rules. Otherwise, it retains the original key-value pair.

    Args:
        metadata (dict): The dictionary containing the metadata with potential
        API keys.

    Returns:
        dict: A new dictionary with sensitive API key information redacted.
    """
    new_metadata = {}
    for k, v in metadata.items():
        if isinstance(v, str) and k.endswith("api_key") and len(v) > 3:
            new_metadata[k] = f"****{v[-3:]}"  # Mask all but last 3 characters
        elif isinstance(v, dict):
            new_metadata[k] = redact_api_key_info(v)
        else:
            new_metadata[k] = v

    return new_metadata


def serialize_datetime(obj):
    """
    Serialize a datetime object into a string in ISO format.

    Args:
        obj: The object to serialize. If not a datetime object, returns the original object.

    Returns:
        str: The ISO-formatted string representation of the datetime object.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()


class MyCustomHandler(CustomLogger):
    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        payload = {
            "message": "Successful API Call",
            "level": "info",
            "kwargs": json.dumps(
                redact_api_key_info(kwargs), default=serialize_datetime
            ),
            "response_obj": json.dumps(
                response_obj.to_dict(), default=serialize_datetime
            ),
        }
        logger(payload)

    async def async_post_call_failure_hook(
        self,
        request_data,
        original_exception,
        user_api_key_dict,
    ):
        payload = {
            "message": "Failed API Call",
            "level": "error",
            "request_data": json.dumps(
                redact_api_key_info(request_data), default=serialize_datetime
            ),
            "original_exception": json.dumps(
                {
                    "error_type": type(original_exception).__name__,
                    "error_message": str(original_exception),
                    "error_args": original_exception.args,
                }
            ),
        }
        logger(payload)


proxy_handler_instance = MyCustomHandler()
