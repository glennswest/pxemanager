#!/bin/bash
# Test DHCP reservation on microdns g10
# Run from any machine on the g10 network (192.168.10.x)
set -e

MICRODNS_URL="http://192.168.10.201:8080"
TEST_MAC="${1:-F4:52:14:84:B7:E0}"
EXPECTED_IP="${2:-192.168.10.20}"
EXPECTED_HOST="${3:-server1b}"

echo "=== MicroDNS g10 DHCP Reservation Test ==="
echo "  API:           $MICRODNS_URL"
echo "  Test MAC:      $TEST_MAC"
echo "  Expected IP:   $EXPECTED_IP"
echo "  Expected Host: $EXPECTED_HOST"
echo ""

# 1. Health check
echo "--- Health Check ---"
if curl -sf --connect-timeout 3 "$MICRODNS_URL/api/v1/health" > /dev/null 2>&1; then
    echo "  microdns: UP"
else
    echo "  microdns: DOWN (cannot reach $MICRODNS_URL)"
    exit 1
fi

# 2. DHCP status
echo ""
echo "--- DHCP Status ---"
STATUS=$(curl -sf --connect-timeout 3 "$MICRODNS_URL/api/v1/dhcp/status" 2>/dev/null)
if [ -n "$STATUS" ]; then
    echo "  $STATUS" | python3 -m json.tool 2>/dev/null || echo "  $STATUS"
else
    echo "  Could not fetch DHCP status"
fi

# 3. Active leases
echo ""
echo "--- Active Leases ---"
LEASES=$(curl -sf --connect-timeout 3 "$MICRODNS_URL/api/v1/leases" 2>/dev/null)
if [ -n "$LEASES" ]; then
    echo "$LEASES" | python3 -m json.tool 2>/dev/null || echo "$LEASES"
else
    echo "  No leases returned (or endpoint unavailable)"
fi

# 4. Check for our specific MAC in leases
echo ""
echo "--- Reservation Check for $TEST_MAC ---"
MAC_LOWER=$(echo "$TEST_MAC" | tr 'A-Z' 'a-z')
if echo "$LEASES" | grep -qi "$MAC_LOWER\|$TEST_MAC"; then
    echo "  FOUND: MAC $TEST_MAC has an active lease"
    echo "$LEASES" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, list):
        for l in data:
            mac = l.get('mac','').lower()
            if '$MAC_LOWER' in mac:
                print(f\"  IP: {l.get('ip','?')}  Hostname: {l.get('hostname','?')}  Expires: {l.get('expires','?')}\")
except: pass
" 2>/dev/null
else
    echo "  NOT FOUND: No active lease for $TEST_MAC"
    echo "  (The reservation exists in config but the client hasn't requested a lease yet)"
fi

# 5. DNS resolution check
echo ""
echo "--- DNS Resolution ---"
for name in "${EXPECTED_HOST}.g10.lo" "${EXPECTED_HOST}"; do
    RESOLVED=$(dig +short "$name" @192.168.10.201 2>/dev/null || nslookup "$name" 192.168.10.201 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tail -1)
    if [ -n "$RESOLVED" ]; then
        if [ "$RESOLVED" = "$EXPECTED_IP" ]; then
            echo "  $name -> $RESOLVED (CORRECT)"
        else
            echo "  $name -> $RESOLVED (MISMATCH: expected $EXPECTED_IP)"
        fi
    else
        echo "  $name -> NOT FOUND (no DNS record yet — client hasn't obtained lease)"
    fi
done

# 6. Ping test
echo ""
echo "--- Ping Test ---"
if ping -c 1 -W 2 "$EXPECTED_IP" > /dev/null 2>&1; then
    echo "  $EXPECTED_IP is REACHABLE"
else
    echo "  $EXPECTED_IP is NOT reachable (NIC may not have obtained lease yet)"
fi

echo ""
echo "=== Done ==="
