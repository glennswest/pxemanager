#!/bin/bash
# Build and deploy pxemanager to mkube via registry
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="192.168.200.2:5000"
REPO="pxemanager"

cd "$SCRIPT_DIR"

# Build
"$SCRIPT_DIR/build.sh"

IMAGE_EDGE="$REGISTRY/$REPO:edge"

echo "Pushing to $REGISTRY ..."
podman push --tls-verify=false "$IMAGE_EDGE"

# Trigger mkube registry poll for immediate update
echo "Triggering registry poll ..."
curl -s -X POST http://192.168.200.2:8082/api/v1/registry/poll

echo ""
echo "=== Deployed ==="
echo "  Image: $IMAGE_EDGE"
echo "  Pod:   pxe.g10 @ 192.168.10.200"
