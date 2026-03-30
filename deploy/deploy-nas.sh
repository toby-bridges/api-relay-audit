#!/bin/bash
# API Relay Audit - NAS Deployment Script
# Deploys the web dashboard to a NAS via Docker (nginx)
#
# Usage: ./deploy-nas.sh <HOST> <USER> <PASSWORD> <PORT>
# Example: ./deploy-nas.sh nas.example.com admin yourpassword 8080

set -e

if [ $# -ne 4 ]; then
    echo "Usage: $0 <HOST> <USER> <PASSWORD> <PORT>"
    echo "Example: $0 nas.example.com admin yourpassword 8080"
    exit 1
fi

NAS_HOST=$1
NAS_USER=$2
NAS_PASS=$3
PORT=$4

WEB_DIR="/vol2/docker/relay-audit-web"
CONTAINER_NAME="relay-audit-web"

echo "=========================================="
echo "  API Relay Audit - NAS Deployment"
echo "=========================================="
echo "Host: $NAS_HOST"
echo "Port: $PORT"
echo "Target: $WEB_DIR"
echo ""

# Check sshpass
if ! command -v sshpass &> /dev/null; then
    echo "ERROR: sshpass not installed"
    echo "macOS: brew install hudochenkov/sshpass/sshpass"
    echo "Linux: sudo apt-get install sshpass"
    exit 1
fi

# Create directory
echo "Creating directory..."
sshpass -p "$NAS_PASS" ssh -o StrictHostKeyChecking=no "$NAS_USER@$NAS_HOST" \
    "mkdir -p $WEB_DIR"

# Upload files
echo "Uploading files..."

echo "  - index.html"
cat web/index.html | sshpass -p "$NAS_PASS" ssh "$NAS_USER@$NAS_HOST" \
    "cat > $WEB_DIR/index.html"

echo "  - data-example.json -> data.json"
cat web/data-example.json | sshpass -p "$NAS_PASS" ssh "$NAS_USER@$NAS_HOST" \
    "cat > $WEB_DIR/data.json"

# Check existing container
echo "Checking Docker container..."
CONTAINER_EXISTS=$(sshpass -p "$NAS_PASS" ssh "$NAS_USER@$NAS_HOST" \
    "docker ps -a --filter name=$CONTAINER_NAME --format '{{.Names}}'" || echo "")

if [ "$CONTAINER_EXISTS" == "$CONTAINER_NAME" ]; then
    echo "  Container exists, stopping and removing..."
    sshpass -p "$NAS_PASS" ssh "$NAS_USER@$NAS_HOST" \
        "docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME"
fi

# Create and start container
echo "Creating container..."
sshpass -p "$NAS_PASS" ssh "$NAS_USER@$NAS_HOST" \
    "docker run -d \
        --name $CONTAINER_NAME \
        -p $PORT:80 \
        -v $WEB_DIR:/usr/share/nginx/html:ro \
        --restart unless-stopped \
        nginx:alpine"

# Verify
sleep 2
CONTAINER_STATUS=$(sshpass -p "$NAS_PASS" ssh "$NAS_USER@$NAS_HOST" \
    "docker ps --filter name=$CONTAINER_NAME --format '{{.Status}}'" || echo "")

if [ -z "$CONTAINER_STATUS" ]; then
    echo "ERROR: Container failed to start"
    exit 1
fi

echo ""
echo "=========================================="
echo "  Deployment complete!"
echo "=========================================="
echo "URL: http://$NAS_HOST:$PORT"
echo "Status: $CONTAINER_STATUS"
echo ""
echo "To sync data later:"
echo "  cat data.json | sshpass -p '\$PASS' ssh user@host 'cat > $WEB_DIR/data.json'"
echo ""
