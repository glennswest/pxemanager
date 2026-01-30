#!/bin/bash
set -e

TARGET_HOST="root@pxe.g10.lo"
BINARY_NAME="pxemanager"
REMOTE_PATH="/usr/local/bin/pxemanager"

# Get version from VERSION file
VERSION=$(cat VERSION 2>/dev/null | tr -d '\n' || echo "0.0.0")
GIT_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
FULL_VERSION="${VERSION}+${GIT_HASH}"
echo "Building version: $FULL_VERSION"

# Build for ARM64 (MikroTik)
echo "Building for ARM64..."
GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=$FULL_VERSION" -o ${BINARY_NAME}-arm64 .

# Stop remote service
echo "Stopping remote service..."
ssh $TARGET_HOST "pkill pxemanager 2>/dev/null || true"
sleep 1

# Deploy
echo "Deploying to $TARGET_HOST..."
scp ${BINARY_NAME}-arm64 $TARGET_HOST:$REMOTE_PATH

# Start remote service
echo "Starting remote service..."
ssh $TARGET_HOST "chmod +x $REMOTE_PATH && nohup $REMOTE_PATH > /var/log/pxemanager.log 2>&1 &"
sleep 2

# Verify
echo "Verifying..."
ssh $TARGET_HOST "pgrep -a pxemanager"

echo "Deployed $FULL_VERSION to $TARGET_HOST"
