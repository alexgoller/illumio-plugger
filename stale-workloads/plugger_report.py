"""
Plugger report publishing helper.

Copy this file into your plugin directory and call publish_report()
to send reports to configured output channels (Slack, email, webhook).

Requires env vars injected by plugger:
  PLUGGER_URL, PLUGGER_WEBHOOK_TOKEN, PLUGGER_PLUGIN_NAME
"""

import logging
import os

import requests

log = logging.getLogger(__name__)

PLUGGER_URL = os.environ.get("PLUGGER_URL", "")
PLUGGER_TOKEN = os.environ.get("PLUGGER_WEBHOOK_TOKEN", "")
PLUGIN_NAME = os.environ.get("PLUGGER_PLUGIN_NAME", "unknown")


def publish_report(title, body, severity="info", tags=None, data=None):
    if not PLUGGER_URL:
        return
    try:
        requests.post(
            f"{PLUGGER_URL}/api/reports/publish",
            headers={"Authorization": f"Bearer {PLUGGER_TOKEN}"},
            json={
                "plugin": PLUGIN_NAME,
                "title": title,
                "severity": severity,
                "body": body,
                "tags": tags or [],
                "data": data or {},
            },
            timeout=5,
        )
    except Exception as e:
        log.debug("Failed to publish report: %s", e)
