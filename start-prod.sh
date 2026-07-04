#!/bin/bash
# start-prod.sh — Production startup script
# Run this on the production server
set -e
cd "$(dirname "$0")"
echo "🚀 Starting Ward 25 Supporter DB (PRODUCTION)..."
python3 server.py
