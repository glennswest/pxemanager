#!/bin/bash
# Build pxemanager: cross-compile locally, then podman build
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="192.168.200.2:5000"
REPO="pxemanager"

cd "$SCRIPT_DIR"

# Get current version and git info
VERSION=$(cat VERSION 2>/dev/null | tr -d '\n' || echo "0.0.0")
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
FULL_VERSION="${VERSION}+${GIT_HASH}"
IMAGE_EDGE="$REGISTRY/$REPO:edge"

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

# Cross-compile for ARM64 Linux
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.Version=${FULL_VERSION}" -o pxemanager .

# Build container image
podman build --platform linux/arm64 -t "$IMAGE_EDGE" .

# Clean up binary
rm -f pxemanager

echo ""
echo "=== Build complete ==="
echo "  $IMAGE_EDGE"
echo "  Version: $FULL_VERSION"
