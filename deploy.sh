#!/bin/bash
# Build, push, and deploy pxemanager to mkube on rose1
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="192.168.200.2:5000"
IMAGE="$REGISTRY/pxemanager:edge"
MKUBE_SERVER="http://api.rose1.gt.lo:8082"
LAST_DEPLOY_FILE=".last-deploy"

cd "$SCRIPT_DIR"

# Get current version and git info
VERSION=$(cat VERSION 2>/dev/null | tr -d '\n' || echo "0.0.0")
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LAST_HASH=$(cat $LAST_DEPLOY_FILE 2>/dev/null | tr -d '\n' || echo "")

# Check if we need to bump version (changes since last deploy)
NEEDS_BUMP=false
if [ -n "$(git status --porcelain)" ]; then
    # Uncommitted changes
    NEEDS_BUMP=true
elif [ "$GIT_HASH" != "$LAST_HASH" ] && [ -n "$LAST_HASH" ]; then
    # New commits since last deploy
    NEEDS_BUMP=true
fi

if [ "$NEEDS_BUMP" = true ]; then
    # Bump patch version
    IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"
    PATCH=$((PATCH + 1))
    VERSION="${MAJOR}.${MINOR}.${PATCH}"
    echo "$VERSION" > VERSION
    echo "Bumped version to $VERSION"
fi

FULL_VERSION="${VERSION}+${GIT_HASH}"
echo "Building version: $FULL_VERSION"

echo "Building container image..."
podman build --build-arg VERSION="$FULL_VERSION" -t "$IMAGE" .

echo "Pushing to $REGISTRY..."
podman push --tls-verify=false "$IMAGE"

echo "Deploying to mkube..."
oc --server="$MKUBE_SERVER" apply -f pxe.yaml

# Save deployed hash for next comparison
echo "$GIT_HASH" > $LAST_DEPLOY_FILE

echo ""
echo "=== Done ==="
echo "Deployed pxemanager $FULL_VERSION to 192.168.10.200"
