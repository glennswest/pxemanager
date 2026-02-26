#!/bin/bash
# Build pxemanager: cross-compile locally, then podman build
# Usage:
#   ./build.sh          Build app image only (~13 MB)
#   ./build.sh --data   Build data image only (~1.3 GB, large boot files)
#   ./build.sh --all    Build both app and data images
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="registry.gt.lo:5000"
REPO="pxemanager"

cd "$SCRIPT_DIR"

# Get current version and git info
VERSION=$(cat VERSION 2>/dev/null | tr -d '\n' || echo "0.0.0")
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
FULL_VERSION="${VERSION}+${GIT_HASH}"
IMAGE_EDGE="$REGISTRY/$REPO:edge"
DATA_IMAGE_EDGE="$REGISTRY/$REPO-data:edge"

BUILD_APP=false
BUILD_DATA=false

case "${1:-}" in
    --data)
        BUILD_DATA=true
        ;;
    --all)
        BUILD_APP=true
        BUILD_DATA=true
        ;;
    *)
        BUILD_APP=true
        ;;
esac

# Ensure large boot files are present (needed for --data or --all)
ensure_boot_files() {
    # Copy kernel/initrd from baremetalservices
    BMS_BOOT="../baremetalservices/pxeimage/boot"
    if [ -f "$BMS_BOOT/vmlinuz" ] && [ -f "$BMS_BOOT/initramfs" ]; then
        cp "$BMS_BOOT/vmlinuz" vmlinuz
        cp "$BMS_BOOT/initramfs" initramfs
        echo "Copied vmlinuz + initramfs from baremetalservices"
    else
        echo "WARNING: baremetalservices boot files not found at $BMS_BOOT"
    fi

    # Download Fedora CoreOS PXE files if not present
    COREOS_STREAM="https://builds.coreos.fedoraproject.org/streams/stable.json"
    if [ ! -f coreos-kernel ] || [ ! -f coreos-initramfs ] || [ ! -f coreos-rootfs.img ]; then
        echo "Downloading Fedora CoreOS PXE files ..."
        STREAM_JSON=$(curl -sL "$COREOS_STREAM")
        COREOS_KERNEL_URL=$(echo "$STREAM_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['architectures']['x86_64']['artifacts']['metal']['formats']['pxe']['kernel']['location'])")
        COREOS_INITRAMFS_URL=$(echo "$STREAM_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['architectures']['x86_64']['artifacts']['metal']['formats']['pxe']['initramfs']['location'])")
        COREOS_ROOTFS_URL=$(echo "$STREAM_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['architectures']['x86_64']['artifacts']['metal']['formats']['pxe']['rootfs']['location'])")

        [ -f coreos-kernel ] || { echo "  Downloading kernel ..."; curl -sL -o coreos-kernel "$COREOS_KERNEL_URL"; }
        [ -f coreos-initramfs ] || { echo "  Downloading initramfs ..."; curl -sL -o coreos-initramfs "$COREOS_INITRAMFS_URL"; }
        [ -f coreos-rootfs.img ] || { echo "  Downloading rootfs (~900MB) ..."; curl -L -o coreos-rootfs.img "$COREOS_ROOTFS_URL"; }
        echo "CoreOS PXE files downloaded"
    else
        echo "CoreOS PXE files already present"
    fi
}

if $BUILD_DATA; then
    echo "=== Building data image ==="
    ensure_boot_files

    podman build --platform linux/arm64 -f Dockerfile.data -t "$DATA_IMAGE_EDGE" .

    echo ""
    echo "=== Data image built ==="
    echo "  $DATA_IMAGE_EDGE"
fi

if $BUILD_APP; then
    echo "=== Building app image ==="
    echo "Building $REPO $FULL_VERSION ..."

    # Cross-compile for ARM64 Linux
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.Version=${FULL_VERSION}" -o pxemanager .

    # Build container image
    podman build --platform linux/arm64 -t "$IMAGE_EDGE" .

    # Clean up binary
    rm -f pxemanager

    echo ""
    echo "=== App image built ==="
    echo "  $IMAGE_EDGE"
    echo "  Version: $FULL_VERSION"
fi
