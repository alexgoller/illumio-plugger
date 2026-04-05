#!/bin/sh
set -e

# ============================================================
# Plugger Shell Plugin Template
# ============================================================
# PCE connection details are injected as environment variables:
#   PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET
#
# For event-driven plugins, the triggering event is in:
#   PLUGGER_EVENT_PAYLOAD (JSON)
# ============================================================

echo "Starting plugin..."
echo "PCE: ${PCE_HOST}:${PCE_PORT} (org ${PCE_ORG_ID})"
echo "Setting: ${MY_PLUGIN_SETTING:-default-value}"

# Base URL for PCE API calls
PCE_BASE="https://${PCE_HOST}:${PCE_PORT}/api/v2/orgs/${PCE_ORG_ID}"

# Helper: make an authenticated PCE API call
pce_api() {
    local method="$1"
    local path="$2"
    shift 2
    curl -s -k -X "$method" \
        -u "${PCE_API_KEY}:${PCE_API_SECRET}" \
        -H "Content-Type: application/json" \
        "${PCE_BASE}${path}" "$@"
}

# ============================================================
# DAEMON MODE: Run a loop that periodically does work
# ============================================================
if [ "${PLUGIN_MODE:-daemon}" = "daemon" ]; then
    # Trap SIGTERM/SIGINT for graceful shutdown
    RUNNING=true
    trap 'echo "Shutting down..."; RUNNING=false' TERM INT

    while $RUNNING; do
        echo "[$(date -Iseconds)] Doing periodic work..."

        # Example: list workloads
        # pce_api GET /workloads | jq '.[] | .hostname'

        # YOUR PLUGIN LOGIC HERE

        # Sleep with interrupt support
        sleep "${POLL_INTERVAL:-60}" &
        wait $! 2>/dev/null || true
    done

    echo "Plugin stopped."
    exit 0
fi

# ============================================================
# CRON MODE: Do work once and exit
# ============================================================
if [ "$PLUGIN_MODE" = "cron" ]; then
    echo "Running one-shot task..."

    # Example: export workloads to a file
    # pce_api GET /workloads > /data/workloads.json

    # YOUR PLUGIN LOGIC HERE

    echo "Done."
    exit 0
fi

# ============================================================
# EVENT MODE: Process a PCE event and exit
# ============================================================
if [ "$PLUGIN_MODE" = "event" ]; then
    echo "Processing event..."

    if [ -z "$PLUGGER_EVENT_PAYLOAD" ]; then
        echo "ERROR: No event payload"
        exit 1
    fi

    EVENT_TYPE=$(echo "$PLUGGER_EVENT_PAYLOAD" | jq -r '.event_type')
    echo "Event type: $EVENT_TYPE"

    # Example: tag a newly created workload
    # WORKLOAD_HREF=$(echo "$PLUGGER_EVENT_PAYLOAD" | jq -r '.resource.href')
    # pce_api PUT "$WORKLOAD_HREF" -d '{"labels": [...]}'

    # YOUR PLUGIN LOGIC HERE

    echo "Event processed."
    exit 0
fi

echo "ERROR: Unknown PLUGIN_MODE: $PLUGIN_MODE"
exit 1
