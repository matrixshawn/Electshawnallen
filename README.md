# Ward 25 Survey — Shawn Allen for Councillor 2026

Canvassing survey app for Ward 25 (Scarborough–Rouge Park) municipal election campaign.

## Setup

### 1. Create the Google Sheets backend
- Go to [sheets.new](https://sheets.new)
- Extensions → Apps Script
- Copy the contents of `apps-script.gs` into the editor
- Click **Deploy → New Deployment**
  - Type: **Web App**
  - Execute as: **Me**
  - Who has access: **Anyone**
- Copy the deployment URL

### 2. Configure the app
- Open `config.js`
- Replace `YOUR_GOOGLE_APPS_SCRIPT_URL_HERE` with your Apps Script URL

### 3. Deploy to GitHub Pages
- Push to a GitHub repo
- Settings → Pages → Source: main branch → Save
- Your site will be live at `https://<username>.github.io/<repo>/`

## Files
- `index.html` — Survey form for canvassers
- `dashboard.html` — Canvasser portal with leaderboard and stats
- `config.js` — API endpoint configuration
- `apps-script.gs` — Google Sheets backend script
- `manifest.json` — PWA manifest
