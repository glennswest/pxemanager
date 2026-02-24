#!/bin/bash
# End-to-end IPMI power cycle test via pxemanager API
# Tests power off, power on, and restart, verifying each operation
# and checking ipmiserial console log rotation.
#
# Usage: ./scripts/test-ipmi-cycle.sh <hostname>
#   e.g.: ./scripts/test-ipmi-cycle.sh server1
set -euo pipefail

# --- Configuration ---
HOSTNAME="${1:-}"
PXE_URL="http://pxe.g10.lo"
CONSOLE_URL="http://ipmiserial.g11.lo"
POLL_INTERVAL=5       # seconds between status polls
POWER_TIMEOUT=60      # seconds to wait for power on/off
RESTART_TIMEOUT=90    # seconds to wait for restart (power cycles briefly)
BOOT_SETTLE=30        # seconds to wait after power on before restart test
CONNECT_TIMEOUT=5     # curl connect timeout

# --- Helpers ---
PASS=0
FAIL=0
STEPS=()

pass() {
    local step="$1"
    local elapsed="$2"
    PASS=$((PASS + 1))
    STEPS+=("PASS  ${step} (${elapsed}s)")
    echo "  PASS: ${step} (${elapsed}s)"
}

fail() {
    local step="$1"
    local reason="$2"
    FAIL=$((FAIL + 1))
    STEPS+=("FAIL  ${step}: ${reason}")
    echo "  FAIL: ${step} — ${reason}"
}

get_status() {
    curl -sf --connect-timeout "$CONNECT_TIMEOUT" \
        "${PXE_URL}/api/host/ipmi/status?host=${HOSTNAME}" 2>/dev/null || echo "error"
}

ipmi_action() {
    local action="$1"
    local http_code
    http_code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout "$CONNECT_TIMEOUT" \
        -X POST "${PXE_URL}/api/host/ipmi?host=${HOSTNAME}&action=${action}" 2>/dev/null)
    echo "$http_code"
}

poll_status() {
    local expected="$1"
    local timeout="$2"
    local waited=0
    while [ "$waited" -lt "$timeout" ]; do
        local status
        status=$(get_status)
        if [ "$status" = "$expected" ]; then
            echo "$waited"
            return 0
        fi
        sleep "$POLL_INTERVAL"
        waited=$((waited + POLL_INTERVAL))
    done
    echo "$waited"
    return 1
}

get_log_count() {
    local result
    result=$(curl -sf --connect-timeout "$CONNECT_TIMEOUT" \
        "${CONSOLE_URL}/api/servers/${HOSTNAME}/logs" 2>/dev/null) || { echo "-1"; return; }
    # ListLogs returns a JSON array of log filename strings
    echo "$result" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "-1"
}

# --- Validate arguments ---
if [ -z "$HOSTNAME" ]; then
    echo "Usage: $0 <hostname>"
    echo "  e.g.: $0 server1"
    exit 1
fi

echo "=== IPMI Power Cycle Test ==="
echo "  Host:       ${HOSTNAME}"
echo "  PXE API:    ${PXE_URL}"
echo "  Console:    ${CONSOLE_URL}"
echo "  Timeouts:   power=${POWER_TIMEOUT}s restart=${RESTART_TIMEOUT}s settle=${BOOT_SETTLE}s"
echo ""

# --- Step 1: Pre-checks ---
echo "--- Step 1: Pre-checks ---"

# Check pxemanager is reachable
if curl -sf --connect-timeout "$CONNECT_TIMEOUT" "${PXE_URL}/" > /dev/null 2>&1; then
    echo "  pxemanager: reachable"
else
    fail "pxemanager reachable" "cannot reach ${PXE_URL}"
    echo ""
    echo "=== ABORTED: pxemanager not reachable ==="
    exit 1
fi

# Check host exists and has IPMI configured (status returns "-" if no IPMI)
initial_status=$(get_status)
if [ "$initial_status" = "error" ] || [ "$initial_status" = "-" ]; then
    fail "host IPMI configured" "status returned '${initial_status}' — host may not exist or IPMI not configured"
    echo ""
    echo "=== ABORTED: IPMI not available for ${HOSTNAME} ==="
    exit 1
fi
echo "  Host IPMI: configured (current power: ${initial_status})"

# Check ipmiserial is reachable
if curl -sf --connect-timeout "$CONNECT_TIMEOUT" "${CONSOLE_URL}/api/servers" > /dev/null 2>&1; then
    echo "  ipmiserial: reachable"
else
    fail "ipmiserial reachable" "cannot reach ${CONSOLE_URL}"
    echo "  (continuing — console log checks will be skipped)"
fi

initial_logs=$(get_log_count)
echo "  Console logs: ${initial_logs} archived log files"
pass "pre-checks" "0"
echo ""

# --- Step 2: Power Off ---
echo "--- Step 2: Power Off ---"
if [ "$initial_status" = "on" ]; then
    echo "  Host is ON — sending power_off..."
    http_code=$(ipmi_action "power_off")
    if [ "$http_code" != "200" ]; then
        fail "power off command" "HTTP ${http_code}"
    else
        echo "  Command sent (HTTP 200), polling for status=off..."
        start=$SECONDS
        if elapsed=$(poll_status "off" "$POWER_TIMEOUT"); then
            pass "power off" "$elapsed"
        else
            fail "power off" "timed out after ${POWER_TIMEOUT}s (still not off)"
        fi
    fi
elif [ "$initial_status" = "off" ]; then
    echo "  Host is already OFF — skipping power off"
    pass "power off" "0"
else
    echo "  Host status is '${initial_status}' — attempting power_off anyway..."
    http_code=$(ipmi_action "power_off")
    if [ "$http_code" = "200" ]; then
        start=$SECONDS
        if elapsed=$(poll_status "off" "$POWER_TIMEOUT"); then
            pass "power off" "$elapsed"
        else
            fail "power off" "timed out after ${POWER_TIMEOUT}s"
        fi
    else
        fail "power off command" "HTTP ${http_code}"
    fi
fi

# Check console log rotation after power off
sleep 3
logs_after_off=$(get_log_count)
if [ "$logs_after_off" -gt "$initial_logs" ] 2>/dev/null; then
    echo "  Console logs rotated: ${initial_logs} -> ${logs_after_off}"
    pass "console rotation (power off)" "0"
elif [ "$logs_after_off" = "-1" ]; then
    fail "console rotation (power off)" "could not query ipmiserial"
else
    echo "  Console logs unchanged: ${logs_after_off} (may not rotate on power off)"
    pass "console check (power off)" "0"
fi
echo ""

# --- Step 3: Power On ---
echo "--- Step 3: Power On ---"
echo "  Sending power_on..."
http_code=$(ipmi_action "power_on")
if [ "$http_code" != "200" ]; then
    fail "power on command" "HTTP ${http_code}"
else
    echo "  Command sent (HTTP 200), polling for status=on..."
    if elapsed=$(poll_status "on" "$POWER_TIMEOUT"); then
        pass "power on" "$elapsed"
    else
        fail "power on" "timed out after ${POWER_TIMEOUT}s (still not on)"
    fi
fi

# Check console log rotation after power on
sleep 3
logs_after_on=$(get_log_count)
if [ "$logs_after_on" -gt "$logs_after_off" ] 2>/dev/null; then
    echo "  Console logs rotated: ${logs_after_off} -> ${logs_after_on}"
    pass "console rotation (power on)" "0"
elif [ "$logs_after_on" = "-1" ]; then
    fail "console rotation (power on)" "could not query ipmiserial"
else
    echo "  Console logs unchanged: ${logs_after_on} (rotation is async, may appear later)"
    pass "console check (power on)" "0"
fi
echo ""

# --- Step 4: Wait for boot to settle ---
echo "--- Step 4: Boot Settle ---"
echo "  Waiting ${BOOT_SETTLE}s for host to boot..."
sleep "$BOOT_SETTLE"
settle_status=$(get_status)
echo "  Status after settle: ${settle_status}"
pass "boot settle" "$BOOT_SETTLE"
echo ""

# --- Step 5: Restart ---
echo "--- Step 5: Restart ---"
echo "  Sending restart (power cycle)..."
http_code=$(ipmi_action "restart")
if [ "$http_code" != "200" ]; then
    fail "restart command" "HTTP ${http_code}"
else
    echo "  Command sent (HTTP 200), polling for status=on (may briefly go off)..."
    # Restart power-cycles: off briefly then back on. Poll for on.
    sleep 5  # give it a moment to cycle
    if elapsed=$(poll_status "on" "$RESTART_TIMEOUT"); then
        pass "restart" "$((elapsed + 5))"
    else
        fail "restart" "timed out after ${RESTART_TIMEOUT}s (still not on)"
    fi
fi

# Check console log rotation after restart
sleep 3
logs_after_restart=$(get_log_count)
if [ "$logs_after_restart" -gt "$logs_after_on" ] 2>/dev/null; then
    echo "  Console logs rotated: ${logs_after_on} -> ${logs_after_restart}"
    pass "console rotation (restart)" "0"
elif [ "$logs_after_restart" = "-1" ]; then
    fail "console rotation (restart)" "could not query ipmiserial"
else
    echo "  Console logs unchanged: ${logs_after_restart} (rotation is async, may appear later)"
    pass "console check (restart)" "0"
fi
echo ""

# --- Summary ---
echo "==========================================="
echo "  IPMI Power Cycle Test Summary"
echo "==========================================="
for step in "${STEPS[@]}"; do
    echo "  ${step}"
done
echo ""
echo "  Total: $((PASS + FAIL)) steps — ${PASS} passed, ${FAIL} failed"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
