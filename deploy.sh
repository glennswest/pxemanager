#!/bin/bash
# Deploy pxemanager to mkube on rose1
# Usage: deploy.sh [--build]
#   --build   Run build.sh first before deploying
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="192.168.200.2:5000"
REPO="pxemanager"
MKUBE_SERVER="http://api.rose1.gt.lo:8082"

cd "$SCRIPT_DIR"

# Optionally build first
if [ "$1" = "--build" ]; then
    "$SCRIPT_DIR/build.sh"
fi

VERSION=$(cat VERSION 2>/dev/null | tr -d '\n' || echo "0.0.0")
TAG="v${VERSION}"
IMAGE="$REGISTRY/$REPO:$TAG"

echo "Deploying $REPO $TAG ..."

# Update image tag in pxe.yaml so it tracks the deployed version
sed "s|image:.*$REPO:.*|image: $IMAGE|" pxe.yaml > pxe.yaml.tmp && mv pxe.yaml.tmp pxe.yaml

echo "Deleting old pod (if any)..."
oc --server="$MKUBE_SERVER" delete -f pxe.yaml 2>/dev/null || true
sleep 5

echo "Applying pxe.yaml with image $IMAGE ..."
oc --server="$MKUBE_SERVER" apply -f pxe.yaml

echo ""
echo "=== Deployed ==="
echo "  Image: $IMAGE"
echo "  Pod:   pxe.g10 @ 192.168.10.200"
