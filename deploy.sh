#!/bin/bash
# deploy.sh — Push code from DEV to PROD
# Stores code in git. Database NEVER pushed (.gitignored).

set -e
cd "$(dirname "$0")"

echo "📦 Deploy: Ward 25 Supporter DB"
echo "================================"
echo ""

# Step 1: Commit code changes
echo "📝 Staging code changes..."
git add -A
STATUS=$(git status --short)
if [ -z "$STATUS" ]; then
    echo "   Nothing to commit."
else
    echo "$STATUS"
    MSG="${1:-update: $(date +%Y-%m-%d_%H:%M)}"
    git commit -m "$MSG"
    echo "   ✓ Committed: $MSG"
fi

# Step 2: Push to git
echo ""
echo "🚀 Pushing to GitHub..."
git push origin main 2>/dev/null && echo "   ✓ Pushed to origin/main" || echo "   ⚠️  Push failed — check remote"

echo ""
echo "✅ Dev code saved to git."
echo ""
echo "Next: deploy to production:"
echo "  Railway/Render:  auto-deploys on push ✓"
echo "  VPS:             ssh user@host 'cd app && git pull && sudo systemctl restart ward25'"
echo "  PythonAnywhere:  upload changed files via web dashboard or git pull"
