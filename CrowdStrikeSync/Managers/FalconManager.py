"""Thin client for the CrowdStrike Falcon Alerts API, used by the CrowdStrikeSync SecOps integration."""

import time

import requests

DEFAULT_API_ROOT = "https://api.crowdstrike.com"
TOKEN_EXPIRY_BUFFER_SECONDS = 60
DEFAULT_TIMEOUT_SECONDS = 60

TOKEN_PATH = "/oauth2/token"
# The legacy Detects API (/detects/entities/detects/v2) was decommissioned on 2025-09-30;
# detections are now Alerts addressed by composite ID.
GET_ALERTS_PATH = "/alerts/entities/alerts/v2"
UPDATE_ALERTS_PATH = "/alerts/entities/alerts/v3"

CLOSED_STATUS = "closed"


class FalconManagerError(Exception):
    pass


class FalconManager(object):
    def __init__(self, api_root, client_id, client_secret, verify_ssl=True,
                 timeout=DEFAULT_TIMEOUT_SECONDS, logger=None):
        self.api_root = (api_root or DEFAULT_API_ROOT).strip().rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.logger = logger
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self._token = None
        self._token_expires_at = 0

    def _get_token(self):
        if self._token and time.time() < self._token_expires_at - TOKEN_EXPIRY_BUFFER_SECONDS:
            return self._token

        response = self.session.post(
            self.api_root + TOKEN_PATH,
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            timeout=self.timeout,
        )
        if response.status_code not in (200, 201):
            raise FalconManagerError(
                "CrowdStrike authentication failed (HTTP {}): {}".format(response.status_code, response.text[:500]))

        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise FalconManagerError("CrowdStrike authentication response did not contain an access_token")

        self._token = token
        self._token_expires_at = time.time() + int(payload.get("expires_in", 1800))
        return token

    def _request(self, method, path, body):
        response = self.session.request(
            method,
            self.api_root + path,
            headers={
                "Authorization": "Bearer {}".format(self._get_token()),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json=body,
            timeout=self.timeout,
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        errors = payload.get("errors") or []
        if not 200 <= response.status_code < 300 or errors:
            messages = "; ".join(e.get("message", str(e)) for e in errors) or response.text[:500]
            raise FalconManagerError(
                "CrowdStrike API request failed (HTTP {}): {}".format(response.status_code, messages))
        return payload

    def get_alert(self, composite_id):
        payload = self._request("POST", GET_ALERTS_PATH, {"composite_ids": [composite_id]})
        resources = payload.get("resources") or []
        if not resources:
            raise FalconManagerError("CrowdStrike alert {} was not found".format(composite_id))
        return resources[0]

    def close_alert(self, composite_id, comment=None):
        action_parameters = [{"name": "update_status", "value": CLOSED_STATUS}]
        if comment:
            action_parameters.append({"name": "append_comment", "value": comment})
        return self._request("PATCH", UPDATE_ALERTS_PATH, {
            "composite_ids": [composite_id],
            "action_parameters": action_parameters,
        })
