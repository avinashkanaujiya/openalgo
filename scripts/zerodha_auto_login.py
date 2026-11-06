"""Invoke OpenAlgo's local, bearer-protected Zerodha login endpoint once."""

import os
import sys
import uuid

import requests

ENDPOINT_URL = "http://127.0.0.1:5000/auth/broker/zerodha-auto-login"
REQUEST_TIMEOUT_SECONDS = 180


def main():
    token = os.environ.get("ZERODHA_AUTO_LOGIN_TOKEN", "")
    if not token:
        print("ok=false event_id=unavailable", flush=True)
        return 1
    correlation_id = uuid.uuid4().hex

    try:
        with requests.Session() as client:
            client.trust_env = False
            response = client.post(
                ENDPOINT_URL,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "X-Correlation-ID": correlation_id,
                },
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        event_id = payload.get("event_id")
        try:
            event_id = uuid.UUID(event_id).hex if isinstance(event_id, str) else "unavailable"
        except (ValueError, AttributeError):
            event_id = "unavailable"
        ok = (
            response.status_code == 200
            and payload.get("status") == "success"
            and event_id != "unavailable"
        )
    except requests.RequestException:
        ok = False
        event_id = "unavailable"

    if ok:
        print(f"ok=true event_id={event_id}", flush=True)
    else:
        print(f"ok=false event_id={event_id} correlation_id={correlation_id}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
