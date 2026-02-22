#!/bin/bash
# Build and push pxemanager container image to the local registry
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="192.168.200.2:5000"
REPO="pxemanager"
LAST_BUILD_FILE=".last-build"

cd "$SCRIPT_DIR"

# Get current version and git info
VERSION=$(cat VERSION 2>/dev/null | tr -d '\n' || echo "0.0.0")
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LAST_HASH=$(cat $LAST_BUILD_FILE 2>/dev/null | tr -d '\n' || echo "")

# Check if we need to bump version (changes since last build)
NEEDS_BUMP=false
if [ -n "$(git status --porcelain)" ]; then
    NEEDS_BUMP=true
elif [ "$GIT_HASH" != "$LAST_HASH" ] && [ -n "$LAST_HASH" ]; then
    NEEDS_BUMP=true
fi

if [ "$NEEDS_BUMP" = true ]; then
    IFS='.' read -r MAJOR MINOR PATCH <<< "$VERSION"
    PATCH=$((PATCH + 1))
    VERSION="${MAJOR}.${MINOR}.${PATCH}"
    echo "$VERSION" > VERSION
    echo "Bumped version to $VERSION"
fi

FULL_VERSION="${VERSION}+${GIT_HASH}"
TAG="v${VERSION}"
IMAGE_EDGE="$REGISTRY/$REPO:edge"
IMAGE_TAG="$REGISTRY/$REPO:$TAG"

# Copy kernel/initrd from baremetalservices for baking into image
BMS_BOOT="../baremetalservices/pxeimage/boot"
if [ -f "$BMS_BOOT/vmlinuz" ] && [ -f "$BMS_BOOT/initramfs" ]; then
    cp "$BMS_BOOT/vmlinuz" vmlinuz
    cp "$BMS_BOOT/initramfs" initramfs
    echo "Copied vmlinuz + initramfs from baremetalservices"
else
    echo "WARNING: baremetalservices boot files not found at $BMS_BOOT"
fi

echo "Building $REPO $FULL_VERSION ..."

podman build --build-arg VERSION="$FULL_VERSION" -t "$IMAGE_EDGE" -t "$IMAGE_TAG" .

echo "Pushing to $REGISTRY ..."
podman push --tls-verify=false "$IMAGE_EDGE"
podman push --tls-verify=false "$IMAGE_TAG"

# Save build hash
echo "$GIT_HASH" > $LAST_BUILD_FILE

echo ""
echo "=== Build complete ==="
echo "  $IMAGE_EDGE"
echo "  $IMAGE_TAG"
echo "  Version: $FULL_VERSION"
