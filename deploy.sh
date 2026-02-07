#!/bin/bash
set -e

TARGET_HOST="root@pxe.g10.lo"
BINARY_NAME="pxemanager"
REMOTE_PATH="/usr/local/bin/pxemanager"
LAST_DEPLOY_FILE=".last-deploy"

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

# Deploy boot files
echo "Deploying boot files..."
scp undionly-custom.kpxe $TARGET_HOST:/tftpboot/undionly.kpxe
scp boot.ipxe $TARGET_HOST:/tftpboot/boot.ipxe
scp memdisk $TARGET_HOST:/tftpboot/memdisk

# Start remote service
echo "Starting remote service..."
ssh $TARGET_HOST "chmod +x $REMOTE_PATH && nohup $REMOTE_PATH > /var/log/pxemanager.log 2>&1 &"
sleep 2

# Verify
echo "Verifying..."
ssh $TARGET_HOST "pgrep -a pxemanager"

# Save deployed hash for next comparison
echo "$GIT_HASH" > $LAST_DEPLOY_FILE

echo "Deployed $FULL_VERSION to $TARGET_HOST"
