# 🏗️ Production Deployment Guide

## Architecture

```
┌─────────────────────┐         git push          ┌─────────────────────┐
│   DEV (this VM)     │ ──────────────────────────→│   PROD (live site)  │
│                     │                             │                     │
│  server.py          │    code only (NO db)        │  server.py           │
│  index.html         │    supporters.db EXCLUDED   │  index.html          │
│  admin.html         │    via .gitignore           │  admin.html          │
│  supporters.db      │                             │  supporters.db       │
│  (test data)        │                             │  (live data)         │
└─────────────────────┘                             └─────────────────────┘
```

**Key rule:** Code goes to both. Database stays separate. Never overwrite the prod DB.

---

## Option 1: Railway / Render (Easiest)

### Setup (one time)
1. Push to GitHub:
   ```bash
   git remote add origin https://github.com/your-username/ward25-supporter-db.git
   git push -u origin main
   ```
2. On Railway or Render:
   - New Web Service → Connect GitHub repo
   - Start command: `python3 server.py`
   - Port: `8777`
   - Environment variables: `PORT=8777`

### Update (every time)
```bash
./deploy.sh "Added surveys completed stat"
```
Railway/Render auto-deploys on git push. Done.

---

## Option 2: Hetzner VPS (~$4/mo, full control)

### Setup (one time)
```bash
# On the VPS:
git clone https://github.com/your-username/ward25-supporter-db.git
cd ward25-supporter-db
# Copy the seed DB (optional — to have address data pre-loaded)
# Then start:
python3 server.py &
```

For auto-restart, create a systemd service:
```ini
# /etc/systemd/system/ward25.service
[Unit]
Description=Ward 25 Supporter DB
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/ward25-supporter-db
ExecStart=/usr/bin/python3 server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then: `sudo systemctl enable --now ward25`

### Update (every time)
```bash
# From DEV:
./deploy.sh "Added feature X"

# On VPS:
ssh user@vps "cd ward25-supporter-db && git pull && sudo systemctl restart ward25"
```

Or add this to `deploy.sh` for one-command deploys.

---

## Option 3: PythonAnywhere ($5/mo)

PythonAnywhere requires WSGI. The app uses raw HTTP, so wrap it:

### Setup (one time)
1. Upload files via the "Files" tab (or git clone)
2. On the "Web" tab, create a manual config:
   - Source code: `/home/youruser/ward25-supporter-db`
   - WSGI file contents:
     ```python
     import subprocess, os
     os.chdir('/home/youruser/ward25-supporter-db')
     subprocess.Popen(['python3', 'server.py'])
     ```
3. On the "Consoles" tab, start a console and run:
   ```bash
   python3 server.py &
   ```
   (Or use "Always-on tasks" on paid plan)

### Update (every time)
Use the Files tab to upload changed files, or:
```bash
ssh youruser@ssh.pythonanywhere.com "cd ward25-supporter-db && git pull"
```
Then reload the web app from the dashboard.

---

## 📋 Daily Workflow

```
1. Make changes in DEV (this VM)
2. Test: refresh the Cloudflare tunnel URL
3. When ready: ./deploy.sh "what changed"
4. Production auto-updates (or run the pull command)
5. Verify on the live URL
```

## ⚠️ Important

- **Never** `git add supporters.db` — it's in `.gitignore`
- **Never** rsync the DB file to production
- The prod DB manages itself — all inserts/updates happen via the API
- Initial prod DB: copy the dev DB ONCE during setup, then never again
- Backups: the `backup.sh` script runs on both dev and prod independently
