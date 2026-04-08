#!/usr/bin/env python3
"""
my-plugin — Plugger plugin for Illumio PCE.

PCE connection details are injected as environment variables:
  PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET
"""

import json
import logging
import os
import signal
import sys
import time

from illumio import PolicyComputeEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("my_plugin")


def get_pce() -> PolicyComputeEngine:
    """Create an authenticated PCE client from environment variables."""
    pce = PolicyComputeEngine(
        url=os.environ["PCE_HOST"],
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ["PCE_API_KEY"],
        password=os.environ["PCE_API_SECRET"],
    )
    pce.set_tls_settings(verify=False)
    return pce


# ============================================================
# YOUR PLUGIN LOGIC
# ============================================================

def do_work(pce: PolicyComputeEngine):
    """Main plugin logic — called periodically in daemon mode, once in cron mode."""
    log.info("Doing work...")

    # Example: list workloads
    # workloads = pce.workloads.get()
    # log.info("Found %d workloads", len(workloads))

    # Example: list labels
    # labels = pce.labels.get()
    # log.info("Found %d labels", len(labels))

    # Example: get workloads by enforcement mode
    # workloads = pce.workloads.get(params={"enforcement_mode": "visibility_only"})

    # TODO: Add your plugin logic here
    log.info("Work complete.")


def handle_event(pce: PolicyComputeEngine, event: dict):
    """Process a PCE event — called in event mode."""
    event_type = event.get("event_type", "unknown")
    log.info("Processing event: %s", event_type)

    # Example: react to workload creation
    # if event_type == "workload.create":
    #     workload_href = event["resource"]["href"]
    #     log.info("New workload: %s", workload_href)

    # TODO: Add your event handling logic here
    log.info("Event processed.")


# ============================================================
# PLUGIN RUNTIME — usually no changes needed below
# ============================================================

def run_daemon(pce: PolicyComputeEngine):
    """Run the plugin as a long-lived daemon."""
    interval = int(os.environ.get("POLL_INTERVAL", "60"))
    log.info("Running in daemon mode (interval=%ds)", interval)

    running = True

    def shutdown(signum, frame):
        nonlocal running
        log.info("Received signal %d, shutting down...", signum)
        running = False

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    while running:
        try:
            do_work(pce)
        except Exception:
            log.exception("Error during work cycle")
        time.sleep(interval)

    log.info("Plugin stopped.")


def run_cron(pce: PolicyComputeEngine):
    """Run the plugin once and exit (cron mode)."""
    log.info("Running in cron mode")
    do_work(pce)
    log.info("Done.")


def run_event(pce: PolicyComputeEngine):
    """Process a single event and exit (event mode)."""
    payload = os.environ.get("PLUGGER_EVENT_PAYLOAD")
    if not payload:
        log.error("No event payload (PLUGGER_EVENT_PAYLOAD is empty)")
        sys.exit(1)

    event = json.loads(payload)
    handle_event(pce, event)


def main():
    log.info("Starting my-plugin...")

    setting = os.environ.get("MY_PLUGIN_SETTING", "default-value")
    log.info("MY_PLUGIN_SETTING=%s", setting)

    pce = get_pce()
    log.info("Connected to PCE: %s", pce.base_url)

    mode = os.environ.get("PLUGIN_MODE", "daemon")
    if mode == "cron":
        run_cron(pce)
    elif mode == "event":
        run_event(pce)
    else:
        run_daemon(pce)


if __name__ == "__main__":
    main()
