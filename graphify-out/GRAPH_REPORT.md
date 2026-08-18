# Graph Report - /root/supporter-db  (2026-08-04)

## Corpus Check
- Large corpus: 111 files · ~529,547 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 271 nodes · 560 edges · 28 communities (14 shown, 14 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 12 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- User & Agent Management
- Admin Dashboard UI
- Auth, Sessions & Server Core
- Password Reset Tests
- Campaign Website & Commitments
- Admin Data & Export Handlers
- Deployment & Production Scripts
- Core Request Handling
- Campaign Event Calendar
- Stats & Survey Handlers
- Supporter Engagement Emails
- Street Index & Poll Lookup
- Canvass Walk Assignments
- Admin Changes Feed
- Admin Changes Archive
- Admin Daily Activity
- Admin Drilldown
- Admin DB Export
- Admin Tasks
- Admin Team Export
- Admin Today
- Canvass Completion
- Canvass History
- My Stats
- Poll Streets
- Production Startup

## God Nodes (most connected - your core abstractions)
1. `Handler` - 80 edges
2. `get_db()` - 65 edges
3. `Admin Dashboard — Ward 25` - 23 edges
4. `dict_rows()` - 19 edges
5. `PasswordResetTests` - 18 edges
6. `Campaign Events — Shawn Allen for Ward 25` - 14 edges
7. `Production Deployment Guide` - 12 edges
8. `require_admin()` - 11 edges
9. `Shawn Allen Campaign Website — electshawnallen.ca` - 11 edges
10. `Ward 25 Canvassing Tool — Elect Shawn Allen` - 9 edges

## Surprising Connections (you probably didn't know these)
- `Campaign Events — Shawn Allen for Ward 25` --references--> `Campaign Calendar PDF (letter, printout)`  [INFERRED]
  calendar.html → shawn-allen-campaign-calendar.pdf
- `Campaign Events — Shawn Allen for Ward 25` --references--> `Campaign Calendar PDF (A4, printout)`  [INFERRED]
  calendar.html → www/shawn-allen-campaign-calendar.pdf
- `Ward 25 Canvassing Tool — Elect Shawn Allen` --semantically_similar_to--> `Admin Dashboard — Ward 25`  [INFERRED] [semantically similar]
  index.html → admin.html
- `Campaign Calendar PDF (letter, printout)` --semantically_similar_to--> `Campaign Calendar PDF (A4, printout)`  [INFERRED] [semantically similar]
  shawn-allen-campaign-calendar.pdf → www/shawn-allen-campaign-calendar.pdf
- `Commit to Vote Form` --conceptually_related_to--> `Commit to Vote — Dashboard`  [INFERRED]
  electshawnallen_index.html → commitments.html

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Summer 2026 Campaign Event Schedule** — calendar, calendar_event_canvass_tech_review, calendar_event_tshirt_merch_collection, calendar_event_kiddies_carnival_canvass, calendar_event_fifa_world_cup_launch, calendar_event_yacht_week_fundraiser, calendar_event_golf_fundraiser, calendar_event_campaign_office_launch, calendar_event_super_canvass_day [EXTRACTED 1.00]
- **Ward 25 Supporter Database Application** — index, admin, commitments, server, production_supporters_db [INFERRED 0.85]
- **Voter Engagement & Data Capture** — electshawnallen_index_commit_to_vote, electshawnallen_index_volunteer, commitments, index_ward25_survey [INFERRED 0.75]

## Communities (28 total, 14 thin omitted)

### Community 0 - "User & Agent Management"
Cohesion: 0.09
Nodes (17): consume_password_reset(), hash_password(), Assign a poll walk to a canvasser., Consume a valid reset token once, change the password, and revoke sessions., Accept a walk assignment (canvasser)., Delete a canvass assignment., Admin report on canvass assignments., Check auth header; set handler.current_user or send 401. (+9 more)

### Community 1 - "Admin Dashboard UI"
Cohesion: 0.08
Nodes (29): Admin Dashboard — Ward 25, Agents Management, Admin JWT Login Gate, SQLite Database Backups, Canvass Management by Poll, Optimized Canvass Walks, Canvasser Leaderboard, Change Log (Today / Archive) (+21 more)

### Community 2 - "Auth, Sessions & Server Core"
Cohesion: 0.10
Nodes (19): HTTPServer, create_password_reset(), create_session(), dict_row(), find_password_reset_user(), get_user_from_token(), load_election_results(), Handle requests in separate threads. (+11 more)

### Community 4 - "Campaign Website & Commitments"
Cohesion: 0.12
Nodes (19): Commit to Vote — Dashboard, Commitments API Feed, Volunteer & Lawn Sign Badges, Commitment Stats Cards, Commitments CSV Export, Shawn Allen Campaign Website — electshawnallen.ca, Commit to Vote Form, Donate — Square Checkout & Rebates (+11 more)

### Community 5 - "Admin Data & Export Handlers"
Cohesion: 0.18
Nodes (6): dict_rows(), Return all records for a poll, sorted for walking routes., Get records for a specific assignment (for View button)., List Keep Taxes Down petition and Pocketbook submissions., Team dashboard: breakdown by category., Return all records at the same address as the given supporter.

### Community 6 - "Deployment & Production Scripts"
Cohesion: 0.15
Nodes (12): backup.sh script, deploy.sh script, Production Deployment Guide, backup.sh Backup Script, Cloudflare Tunnel Test URL, Git-Push Deploy Workflow, Dev/Prod Split — Code Both Ways, DB Separate, Electshawnallen GitHub Repository (+4 more)

### Community 7 - "Core Request Handling"
Cohesion: 0.14
Nodes (7): BaseHTTPRequestHandler, Handler, Serve a static file from WWW_DIR., Export all survey responses as CSV., Return commitments from the commit-to-vote API database., Export commitments as CSV., Return per-canvasser stats: daily (static) + cumulative totals. Supports…

### Community 8 - "Campaign Event Calendar"
Cohesion: 0.16
Nodes (14): Campaign Events — Shawn Allen for Ward 25, Election Day — October 26, 2026, Campaign Office Launch (Aug 5, 2026), Campaign Canvass & Tech Review (Jul 13-14, 2026), FIFA & World Cup Soft Launch (Jul 19, 2026), Golf Fundraiser (Jul 29, 2026), Kiddies Carnival Super Canvass (Jul 18, 2026), Super Canvass Day (Aug 8, 2026) (+6 more)

### Community 9 - "Stats & Survey Handlers"
Cohesion: 0.15
Nodes (6): get_db(), Return daily support gained/lost per poll., List survey responses with pagination., Export Keep Taxes Down petition and Pocketbook submissions as CSV., Return the public petition total: launch count plus verified web signatures., Export current search results as CSV.

### Community 10 - "Supporter Engagement Emails"
Cohesion: 0.18
Nodes (5): Save commit-to-vote form submission (public endpoint)., Save volunteer signup form submission (public endpoint)., Email commit-to-vote form to info@electshawnallen.ca via AgentMail., Email volunteer signup to info@electshawnallen.ca via AgentMail., Send an email from info@electshawnallen.ca via Microsoft Graph.

### Community 11 - "Street Index & Poll Lookup"
Cohesion: 0.29
Nodes (10): backfill_polls(), get_poll_order(), _load_index(), lookup_poll(), _normalize_street(), Return the canonical poll order from the street index file (first appearance)., Backfill poll data for all existing supporter records., Normalize street name for matching: uppercase, strip, collapse spaces. (+2 more)

### Community 12 - "Canvass Walk Assignments"
Cohesion: 0.25
Nodes (4): Load optimized canvass walks generated from the supporter route plan., Return optimized walks plus current assignment state for the admin Canvass…, Assign one optimized walk packet to a canvasser., Get assignments for the logged-in canvasser.

## Knowledge Gaps
- **48 isolated node(s):** `backup.sh script`, `deploy.sh script`, `start-prod.sh script`, `supporters.db Live Database`, `Electshawnallen GitHub Repository` (+43 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **14 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Handler` connect `Core Request Handling` to `User & Agent Management`, `Auth, Sessions & Server Core`, `Admin Data & Export Handlers`, `Stats & Survey Handlers`, `Supporter Engagement Emails`, `Canvass Walk Assignments`, `Admin Changes Feed`, `Admin Changes Archive`, `Admin Daily Activity`, `Admin Drilldown`, `Admin DB Export`, `Admin Tasks`, `Admin Team Export`, `Admin Today`, `Canvass Completion`, `Canvass History`, `My Stats`, `Poll Streets`?**
  _High betweenness centrality (0.320) - this node is a cross-community bridge._
- **Why does `Admin Dashboard — Ward 25` connect `Admin Dashboard UI` to `Auth, Sessions & Server Core`, `Campaign Website & Commitments`?**
  _High betweenness centrality (0.236) - this node is a cross-community bridge._
- **Why does `Commit to Vote — Dashboard` connect `Campaign Website & Commitments` to `Admin Dashboard UI`?**
  _High betweenness centrality (0.202) - this node is a cross-community bridge._
- **What connects `backup.sh script`, `deploy.sh script`, `start-prod.sh script` to the rest of the system?**
  _48 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `User & Agent Management` be split into smaller, more focused modules?**
  _Cohesion score 0.08717948717948718 - nodes in this community are weakly interconnected._
- **Should `Admin Dashboard UI` be split into smaller, more focused modules?**
  _Cohesion score 0.0812807881773399 - nodes in this community are weakly interconnected._
- **Should `Auth, Sessions & Server Core` be split into smaller, more focused modules?**
  _Cohesion score 0.09538461538461539 - nodes in this community are weakly interconnected._