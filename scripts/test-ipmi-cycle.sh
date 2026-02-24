#!/bin/bash
# End-to-end IPMI power cycle test via pxemanager API
# Tests power off, power on (with full boot verification), and restart.
#
# After power on, verifies:
#   - IPMI reports power on
#   - ipmiserial sees serial output (SOL connected)
#   - ipmiserial analytics shows boot complete
#   - baremetalservices REST API is reachable on the host
#   - Host has IPs on both g10 and g11 interfaces (DNS resolution)
#   - Console log rotation happened
#
# Usage: ./scripts/test-ipmi-cycle.sh <hostname>
#   e.g.: ./scripts/test-ipmi-cycle.sh server1
set -euo pipefail

# --- Configuration ---
HOSTNAME="${1:-}"
PXE_URL="http://pxe.g10.lo"
CONSOLE_URL="http://ipmiserial.g11.lo"
DNS_G10="192.168.10.252"
DNS_G11="192.168.11.252"
POLL_INTERVAL=5         # seconds between status polls
POWER_TIMEOUT=60        # seconds to wait for IPMI power state change
BOOT_TIMEOUT=180        # seconds to wait for full boot (analytics complete)
BMS_TIMEOUT=120         # seconds to wait for baremetalservices health
RESTART_TIMEOUT=180     # seconds to wait for restart + full boot
CONNECT_TIMEOUT=5       # curl connect timeout

# --- Helpers ---
PASS=0
FAIL=0
WARN=0
STEPS=()
TEST_START=$SECONDS

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

warn() {
    local step="$1"
    local reason="$2"
    WARN=$((WARN + 1))
    STEPS+=("WARN  ${step}: ${reason}")
    echo "  WARN: ${step} — ${reason}"
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
    echo "$result" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "-1"
}

# Get ipmiserial analytics — returns JSON with currentBoot, bootHistory, etc.
get_analytics() {
    curl -sf --connect-timeout "$CONNECT_TIMEOUT" \
        "${CONSOLE_URL}/api/servers/${HOSTNAME}/analytics" 2>/dev/null || echo "{}"
}

# Check if current boot is complete via analytics
# Returns: "true <duration> <os>" or "false"
get_boot_status() {
    local analytics
    analytics=$(get_analytics)
    echo "$analytics" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    cb = d.get('currentBoot', {})
    complete = cb.get('complete', False)
    duration = cb.get('bootDuration', 0)
    os = cb.get('detectedOS', 'unknown')
    if complete:
        print(f'true {duration:.1f} {os}')
    else:
        print('false')
except:
    print('false')
" 2>/dev/null || echo "false"
}

# Check if ipmiserial SOL is connected
get_sol_connected() {
    local result
    result=$(curl -sf --connect-timeout "$CONNECT_TIMEOUT" \
        "${CONSOLE_URL}/api/servers/${HOSTNAME}/status" 2>/dev/null) || { echo "false"; return; }
    echo "$result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('true' if d.get('connected', False) else 'false')
except:
    print('false')
" 2>/dev/null || echo "false"
}

# Get analytics reboot count to detect new boot cycle
get_reboot_count() {
    local analytics
    analytics=$(get_analytics)
    echo "$analytics" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('totalReboots', 0))
except:
    print(-1)
" 2>/dev/null || echo "-1"
}

# Poll until analytics shows boot complete (new boot cycle)
# Args: timeout, initial_reboot_count
poll_boot_complete() {
    local timeout="$1"
    local initial_reboots="$2"
    local waited=0
    while [ "$waited" -lt "$timeout" ]; do
        local boot_info
        boot_info=$(get_boot_status)
        local reboots
        reboots=$(get_reboot_count)
        if [ "${boot_info%% *}" = "true" ] && [ "$reboots" -gt "$initial_reboots" ] 2>/dev/null; then
            echo "$waited $boot_info"
            return 0
        fi
        sleep "$POLL_INTERVAL"
        waited=$((waited + POLL_INTERVAL))
    done
    echo "$waited"
    return 1
}

# Resolve hostname via DNS and return IP
dns_resolve() {
    local name="$1"
    local dns_server="$2"
    dig +short "$name" "@${dns_server}" 2>/dev/null | head -1
}

# Check baremetalservices health on the host (via g11 interface)
check_bms_health() {
    curl -sf --connect-timeout "$CONNECT_TIMEOUT" \
        "http://${HOSTNAME}.g11.lo:8080/health" > /dev/null 2>&1
}

# Poll baremetalservices until healthy
poll_bms_health() {
    local timeout="$1"
    local waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if check_bms_health; then
            echo "$waited"
            return 0
        fi
        sleep "$POLL_INTERVAL"
        waited=$((waited + POLL_INTERVAL))
    done
    echo "$waited"
    return 1
}

# Full boot verification: serial, analytics, baremetalservices, network
# Args: step_prefix, initial_reboot_count, initial_log_count
verify_full_boot() {
    local prefix="$1"
    local initial_reboots="$2"
    local initial_logs="$3"

    # 1. Check ipmiserial SOL is connected (serial output flowing)
    echo "  Checking serial console (SOL)..."
    local sol_waited=0
    while [ "$sol_waited" -lt 30 ]; do
        if [ "$(get_sol_connected)" = "true" ]; then
            break
        fi
        sleep 2
        sol_waited=$((sol_waited + 2))
    done
    if [ "$(get_sol_connected)" = "true" ]; then
        pass "${prefix}: serial console connected" "$sol_waited"
    else
        fail "${prefix}: serial console connected" "SOL not connected after 30s"
    fi

    # 2. Wait for boot to complete via analytics
    echo "  Waiting for boot to complete (analytics)..."
    local boot_result
    if boot_result=$(poll_boot_complete "$BOOT_TIMEOUT" "$initial_reboots"); then
        local bwait bdur bos
        bwait=$(echo "$boot_result" | awk '{print $1}')
        bdur=$(echo "$boot_result" | awk '{print $3}')
        bos=$(echo "$boot_result" | awk '{$1=$2=$3=""; print $0}' | sed 's/^ *//')
        pass "${prefix}: boot complete (${bos}, ${bdur}s boot)" "$bwait"
    else
        local bwait
        bwait=$(echo "$boot_result" | awk '{print $1}')
        fail "${prefix}: boot complete" "timed out after ${BOOT_TIMEOUT}s"
    fi

    # 3. Check console log rotation
    sleep 2
    local logs_now
    logs_now=$(get_log_count)
    if [ "$logs_now" -gt "$initial_logs" ] 2>/dev/null; then
        echo "  Console logs rotated: ${initial_logs} -> ${logs_now}"
        pass "${prefix}: console log rotation" "0"
    elif [ "$logs_now" = "-1" ]; then
        fail "${prefix}: console log rotation" "could not query ipmiserial"
    else
        warn "${prefix}: console log rotation" "logs unchanged (${logs_now}), may rotate later"
    fi

    # 4. Wait for baremetalservices REST API
    echo "  Waiting for baremetalservices health (${HOSTNAME}.g11.lo:8080)..."
    local bms_result
    if bms_result=$(poll_bms_health "$BMS_TIMEOUT"); then
        pass "${prefix}: baremetalservices health" "$bms_result"
    else
        fail "${prefix}: baremetalservices health" "not reachable after ${BMS_TIMEOUT}s"
    fi

    # 5. Check IPs on both interfaces via DNS
    echo "  Checking network interfaces via DNS..."
    local ip_g10 ip_g11
    ip_g10=$(dns_resolve "${HOSTNAME}.g10.lo" "$DNS_G10")
    ip_g11=$(dns_resolve "${HOSTNAME}.g11.lo" "$DNS_G11")

    if [ -n "$ip_g10" ]; then
        pass "${prefix}: g10 interface (${ip_g10})" "0"
    else
        fail "${prefix}: g10 interface" "no DNS record for ${HOSTNAME}.g10.lo"
    fi

    if [ -n "$ip_g11" ]; then
        pass "${prefix}: g11 interface (${ip_g11})" "0"
    else
        fail "${prefix}: g11 interface" "no DNS record for ${HOSTNAME}.g11.lo"
    fi

    # 6. Ping g11 interface (g10 not reachable from this workstation)
    if [ -n "$ip_g11" ]; then
        if ping -c 1 -W 2 "$ip_g11" > /dev/null 2>&1; then
            pass "${prefix}: ping g11 (${ip_g11})" "0"
        else
            fail "${prefix}: ping g11" "${ip_g11} not reachable"
        fi
    fi

    # Return current log count for next phase
    echo "$logs_now"
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
echo "  Timeouts:   power=${POWER_TIMEOUT}s boot=${BOOT_TIMEOUT}s bms=${BMS_TIMEOUT}s restart=${RESTART_TIMEOUT}s"
echo ""

# =========================================================================
# Step 1: Pre-checks
# =========================================================================
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
    echo ""
    echo "=== ABORTED: ipmiserial not reachable ==="
    exit 1
fi

initial_logs=$(get_log_count)
initial_reboots=$(get_reboot_count)
echo "  Console logs: ${initial_logs} archived, reboots tracked: ${initial_reboots}"
pass "pre-checks" "0"
echo ""

# =========================================================================
# Step 2: Power Off
# =========================================================================
echo "--- Step 2: Power Off ---"
if [ "$initial_status" = "on" ]; then
    echo "  Host is ON — sending power_off..."
    http_code=$(ipmi_action "power_off")
    if [ "$http_code" != "200" ]; then
        fail "power off command" "HTTP ${http_code}"
    else
        echo "  Command sent (HTTP 200), polling for status=off..."
        if elapsed=$(poll_status "off" "$POWER_TIMEOUT"); then
            pass "power off" "$elapsed"
        else
            fail "power off" "timed out after ${POWER_TIMEOUT}s (still not off)"
        fi
    fi
elif [ "$initial_status" = "off" ]; then
    echo "  Host is already OFF — skipping power off"
    pass "power off (already off)" "0"
else
    echo "  Host status is '${initial_status}' — attempting power_off..."
    http_code=$(ipmi_action "power_off")
    if [ "$http_code" = "200" ]; then
        if elapsed=$(poll_status "off" "$POWER_TIMEOUT"); then
            pass "power off" "$elapsed"
        else
            fail "power off" "timed out after ${POWER_TIMEOUT}s"
        fi
    else
        fail "power off command" "HTTP ${http_code}"
    fi
fi

# Brief pause after power off
sleep 5
off_status=$(get_status)
echo "  Power status after off: ${off_status}"

# Update log count after power off
sleep 2
logs_after_off=$(get_log_count)
if [ "$logs_after_off" -gt "$initial_logs" ] 2>/dev/null; then
    echo "  Console logs rotated on power off: ${initial_logs} -> ${logs_after_off}"
fi
echo ""

# =========================================================================
# Step 3: Power On + Full Boot Verification
# =========================================================================
echo "--- Step 3: Power On ---"
reboots_before_on=$(get_reboot_count)
echo "  Sending power_on..."
http_code=$(ipmi_action "power_on")
if [ "$http_code" != "200" ]; then
    fail "power on command" "HTTP ${http_code}"
    echo ""
    echo "=== ABORTED: power on failed ==="
    exit 1
fi
echo "  Command sent (HTTP 200)"

# Poll IPMI until it reports "on"
echo "  Polling IPMI for power=on..."
if elapsed=$(poll_status "on" "$POWER_TIMEOUT"); then
    pass "power on (IPMI)" "$elapsed"
else
    fail "power on (IPMI)" "timed out after ${POWER_TIMEOUT}s"
fi

# Full boot verification
echo ""
echo "--- Step 3a: Boot Verification (power on) ---"
logs_after_on=$(verify_full_boot "power-on" "$reboots_before_on" "$logs_after_off")
echo ""

# =========================================================================
# Step 4: Restart + Full Boot Verification
# =========================================================================
echo "--- Step 4: Restart ---"
reboots_before_restart=$(get_reboot_count)
logs_before_restart=$(get_log_count)
echo "  Sending restart (power cycle)..."
http_code=$(ipmi_action "restart")
if [ "$http_code" != "200" ]; then
    fail "restart command" "HTTP ${http_code}"
else
    echo "  Command sent (HTTP 200)"
    # Power cycle: briefly off then back on
    sleep 5
    echo "  Polling IPMI for power=on..."
    if elapsed=$(poll_status "on" "$POWER_TIMEOUT"); then
        pass "restart (IPMI power on)" "$((elapsed + 5))"
    else
        fail "restart (IPMI power on)" "timed out after ${POWER_TIMEOUT}s"
    fi
fi

# Full boot verification after restart
echo ""
echo "--- Step 4a: Boot Verification (restart) ---"
verify_full_boot "restart" "$reboots_before_restart" "$logs_before_restart" > /dev/null
echo ""

# =========================================================================
# Summary
# =========================================================================
total_elapsed=$((SECONDS - TEST_START))
echo "==========================================="
echo "  IPMI Power Cycle Test Summary"
echo "==========================================="
for step in "${STEPS[@]}"; do
    echo "  ${step}"
done
echo ""
echo "  Total: $((PASS + FAIL + WARN)) checks — ${PASS} passed, ${FAIL} failed, ${WARN} warnings"
echo "  Total time: ${total_elapsed}s"
echo "==========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
