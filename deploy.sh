#!/bin/bash
# Build and deploy pxemanager — just build + push, mkube auto-updates
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="registry.gt.lo:5000"
REPO="pxemanager"

cd "$SCRIPT_DIR"

# Build
"$SCRIPT_DIR/build.sh"

IMAGE_EDGE="$REGISTRY/$REPO:edge"

echo "Pushing to $REGISTRY ..."
podman push --tls-verify=false "$IMAGE_EDGE"

echo ""
echo "=== Deployed ==="
echo "  Image: $IMAGE_EDGE"
echo "  Pod:   pxe.g10 @ 192.168.10.200 (auto-updated by mkube)"
