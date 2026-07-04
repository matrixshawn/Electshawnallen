#!/bin/bash
# Ward 25 Supporter DB Backup Script
# Creates timestamped backup of supporters.db and keeps last 30 days

set -e

DB="/root/supporter-db/supporters.db"
BACKUP_DIR="/root/supporter-db/backups"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +%Y-%m-%d_%H%M)
BACKUP_FILE="$BACKUP_DIR/supporters_$TIMESTAMP.db"

# Create backup using sqlite3 .backup (safe even during writes)
sqlite3 "$DB" ".backup '$BACKUP_FILE'"

# Compress
gzip -f "$BACKUP_FILE"

# Log
echo "[$(date)] Backup created: ${BACKUP_FILE}.gz ($(du -h ${BACKUP_FILE}.gz | cut -f1))"

# Cleanup old backups
find "$BACKUP_DIR" -name "supporters_*.db.gz" -mtime +$RETENTION_DAYS -delete

# Print backup count
COUNT=$(ls "$BACKUP_DIR"/*.db.gz 2>/dev/null | wc -l)
echo "[$(date)] Total backups: $COUNT"

# If more than 7 days without a backup, something's wrong — this script is designed for cron
