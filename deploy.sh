#!/bin/bash
# Build and deploy pxemanager — just build + push, mkube auto-updates
# Usage:
#   ./deploy.sh          Build+push app image only (fast)
#   ./deploy.sh --data   Build+push data image only
#   ./deploy.sh --all    Build+push both
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="registry.gt.lo:5000"
REPO="pxemanager"

cd "$SCRIPT_DIR"

# Pass through flags to build.sh
"$SCRIPT_DIR/build.sh" "${1:-}"

IMAGE_EDGE="$REGISTRY/$REPO:edge"
DATA_IMAGE_EDGE="$REGISTRY/$REPO-data:edge"

case "${1:-}" in
    --data)
        echo "Pushing data image to $REGISTRY ..."
        podman push --tls-verify=false "$DATA_IMAGE_EDGE"
        echo ""
        echo "=== Deployed ==="
        echo "  Data image: $DATA_IMAGE_EDGE"
        ;;
    --all)
        echo "Pushing app image to $REGISTRY ..."
        podman push --tls-verify=false "$IMAGE_EDGE"
        echo "Pushing data image to $REGISTRY ..."
        podman push --tls-verify=false "$DATA_IMAGE_EDGE"
        echo ""
        echo "=== Deployed ==="
        echo "  App image:  $IMAGE_EDGE"
        echo "  Data image: $DATA_IMAGE_EDGE"
        echo "  Pod:   pxe.g10 @ 192.168.10.200 (auto-updated by mkube)"
        ;;
    *)
        echo "Pushing app image to $REGISTRY ..."
        podman push --tls-verify=false "$IMAGE_EDGE"
        echo ""
        echo "=== Deployed ==="
        echo "  Image: $IMAGE_EDGE"
        echo "  Pod:   pxe.g10 @ 192.168.10.200 (auto-updated by mkube)"
        ;;
esac
