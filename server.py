#!/usr/bin/env python3
"""Supporter Database Server — Ward 25 Campaign
Serves HTML frontend + REST API for supporter lookup, editing, and change tracking.
"""
import os, json, sqlite3, time, re, csv, hashlib, secrets, subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads."""
    daemon_threads = True
from urllib.parse import urlparse, parse_qs, unquote_plus
from urllib.request import Request, urlopen
from urllib.error import URLError
from datetime import datetime
import street_index

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'supporters.db')
WWW_DIR = os.path.dirname(os.path.abspath(__file__))
ELECTION_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'election_results.json')
CANVASS_WALKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'canvass_walks.json')
PORT = 8777

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=5000')
    # Migration: ensure users table has status column
    try:
        conn.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")
    except sqlite3.OperationalError:
        pass
    # Migration: email-backed self-service password reset
    try:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    except sqlite3.OperationalError:
        pass
    conn.execute("UPDATE users SET email = username WHERE (email IS NULL OR trim(email) = '') AND username LIKE '%@%'")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users(LOWER(email)) WHERE email IS NOT NULL AND trim(email) <> ''")
    conn.execute('''
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at INTEGER
        )
    ''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_tokens(user_id)')
    # Migration: tasks table for standalone task management
    conn.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            supporter_id INTEGER,
            task_text TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT DEFAULT (datetime('now', 'localtime')),
            due_date TEXT,
            completed_at TEXT,
            completed_by TEXT,
            archived_at TEXT,
            status TEXT DEFAULT 'open'
        )
    ''')
    conn.commit()
    return conn

def load_election_results():
    """Load election results JSON, return None if not available."""
    if not os.path.exists(ELECTION_PATH):
        return None
    with open(ELECTION_PATH) as f:
        return json.load(f)

def dict_row(row):
    return dict(row) if row else None

def dict_rows(rows):
    return [dict(r) for r in rows]

# ── Auth helpers ──────────────────────────────────────────

def verify_password(password, stored_hash):
    """Verify a password against stored salt:hash. Case-insensitive."""
    try:
        salt_hex, h = stored_hash.split(':', 1)
        salt = bytes.fromhex(salt_hex)
        computed = hashlib.sha256(salt + password.lower().encode()).hexdigest()
        return computed == h
    except Exception:
        return False

def hash_password(password):
    """Hash a password with random salt (case-insensitive)."""
    salt = secrets.token_bytes(16)
    return salt.hex() + ':' + hashlib.sha256(salt + password.lower().encode()).hexdigest()

def find_password_reset_user(conn, identifier):
    """Find a resettable account by username or registered email."""
    value = (identifier or '').strip().lower()
    if not value:
        return None
    row = conn.execute('''
        SELECT id, username, email, display_name
        FROM users
        WHERE LOWER(username) = ? OR LOWER(COALESCE(email, '')) = ?
        LIMIT 1
    ''', (value, value)).fetchone()
    return dict_row(row)

def create_password_reset(conn, user_id, now=None, ttl_seconds=3600):
    """Create a reset token, storing only its digest; throttle to one per five minutes."""
    now = int(time.time()) if now is None else int(now)
    recent = conn.execute('''
        SELECT id FROM password_reset_tokens
        WHERE user_id = ? AND created_at > ?
        LIMIT 1
    ''', (user_id, now - 300)).fetchone()
    if recent:
        return None
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    conn.execute(
        'UPDATE password_reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL',
        (now, user_id)
    )
    conn.execute('''
        INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at)
        VALUES (?,?,?,?)
    ''', (user_id, token_hash, now, now + int(ttl_seconds)))
    conn.commit()
    return raw_token

def consume_password_reset(conn, raw_token, new_password, now=None):
    """Consume a valid reset token once, change the password, and revoke sessions."""
    if len(new_password or '') < 8:
        raise ValueError('Password must be at least 8 characters')
    now = int(time.time()) if now is None else int(now)
    token_hash = hashlib.sha256((raw_token or '').encode()).hexdigest()
    row = conn.execute('''
        SELECT id, user_id FROM password_reset_tokens
        WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?
        LIMIT 1
    ''', (token_hash, now)).fetchone()
    if not row:
        return None
    conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                 (hash_password(new_password), row['user_id']))
    conn.execute('UPDATE password_reset_tokens SET used_at = ? WHERE id = ?',
                 (now, row['id']))
    conn.execute('DELETE FROM sessions WHERE user_id = ?', (row['user_id'],))
    conn.commit()
    return row['user_id']

def create_session(user_id):
    """Create a session token and return it."""
    token = secrets.token_hex(32)
    conn = get_db()
    conn.execute('INSERT INTO sessions (token, user_id) VALUES (?,?)', (token, user_id))
    conn.commit()
    conn.close()
    return token

def get_user_from_token(token):
    """Get user dict from session token, or None."""
    if not token:
        return None
    conn = get_db()
    row = conn.execute('''
        SELECT u.id, u.username, u.role, u.display_name
        FROM sessions s JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
    ''', (token,)).fetchone()
    conn.close()
    return dict_row(row)

def require_auth(handler):
    """Check auth header; set handler.current_user or send 401."""
    auth = handler.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token = auth[7:]
        user = get_user_from_token(token)
        if user:
            handler.current_user = user
            return True
    handler._json({'error': 'Authentication required'}, 401)
    return False

def require_admin(handler):
    """Check auth + admin role."""
    if not require_auth(handler):
        return False
    if handler.current_user.get('role') != 'admin':
        handler._json({'error': 'Admin access required'}, 403)
        return False
    return True

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        qs = parse_qs(parsed.query)

        # API: Auth — get current user
        if path == '/api/auth/me':
            if require_auth(self):
                self._json({'user': self.current_user})
            return

        # API: Personal canvasser stats
        if path == '/api/my-stats':
            if require_auth(self):
                self.handle_my_stats()
            return

        # API: Admin — list users (admin only)
        if path == '/api/admin/users':
            if require_admin(self):
                self.handle_admin_list_users()
            return

        # API: Admin — list agents (admin only)
        if path == '/api/admin/agents':
            if require_admin(self):
                self.handle_admin_list_agents()
            return

        # API: Admin daily activity
        if path == '/api/admin/daily-activity':
            self.handle_admin_daily_activity()
            return

        # API: Admin export database (admin only)
        if path == '/api/admin/export-db':
            # Also check token from query param for direct downloads
            token_qs = qs.get('token', [''])[0]
            if token_qs:
                user = get_user_from_token(token_qs)
                if user and user.get('role') == 'admin':
                    self.current_user = user
                else:
                    self._json({'error': 'Admin access required'}, 403)
                    return
            elif not require_admin(self):
                return
            self.handle_admin_export_db()
            return

        # API: Admin today stats
        if path == '/api/admin/today':
            self.handle_admin_today()
            return

        # API: Admin stat-card drill-down records/changes
        if path == '/api/admin/drilldown':
            self.handle_admin_drilldown(qs)
            return

        # API: Admin team dashboard
        if path == '/api/admin/team':
            self.handle_admin_team()
            return

        # API: Admin team dashboard export (CSV)
        if path == '/api/admin/team/export':
            self.handle_admin_team_export()
            return

        # API: Admin canvasser stats (daily + custom date range)
        if path == '/api/admin/canvasser-stats':
            self.handle_canvasser_stats(qs)
            return

        # API: Tasks list
        if path == '/api/admin/tasks':
            self.handle_admin_tasks(qs)
            return

        # API: Surveys list
        if path == '/api/admin/surveys':
            self.handle_admin_surveys(qs)
            return

        # API: Surveys export CSV
        if path == '/api/admin/surveys/export':
            self.handle_admin_surveys_export(qs)
            return

        # API: Keep Taxes Down website submissions (admin only)
        if path == '/api/admin/web-submissions':
            if require_admin(self):
                self.handle_admin_web_submissions(qs)
            return

        # API: Keep Taxes Down website submissions export (admin only)
        if path == '/api/admin/web-submissions/export':
            if require_admin(self):
                self.handle_admin_web_submissions_export(qs)
            return

        # API: Advance voters list (admin only)
        if path == '/api/admin/advance-voters':
            if require_admin(self):
                self.handle_admin_advance_voters(qs)
            return

        # API: Advance voters stats (admin only)
        if path == '/api/admin/advance-voters/stats':
            if require_admin(self):
                self.handle_admin_advance_voters_stats()
            return

        # API: Advance voters export CSV (admin only)
        if path == '/api/admin/advance-voters/export':
            if require_admin(self):
                self.handle_admin_advance_voters_export(qs)
            return

        # API: Advance voter update result (admin only)
        if path == '/api/admin/advance-voters/update':
            if require_admin(self):
                self.handle_admin_advance_voter_update()
            return

        # API: Unified street search across Advance Voters / Supporters / Conservative (admin only)
        if path == '/api/admin/street-search':
            if require_admin(self):
                self.handle_admin_street_search(qs)
            return

        # API: Supporters list (admin only)
        if path == '/api/admin/supporters':
            if require_admin(self):
                self.handle_admin_supporters(qs)
            return

        # API: Supporters stats (admin only)
        if path == '/api/admin/supporters/stats':
            if require_admin(self):
                self.handle_admin_supporters_stats()
            return

        # API: Supporters export (admin only)
        if path == '/api/admin/supporters/export':
            if require_admin(self):
                self.handle_admin_supporters_export(qs)
            return

        # API: Supporters update (admin only)
        if path == '/api/admin/supporters/update':
            if require_admin(self):
                self.handle_admin_supporter_update()
            return

        # API: Recent Changes (today, paginated)
        if path == '/api/admin/changes':
            self.handle_admin_changes(qs)
            return

        # API: Archived Changes (all previous days, paginated)
        if path == '/api/admin/changes/archive':
            self.handle_admin_changes_archive(qs)
            return

        # Admin dashboard page
        if path == '/admin':
            self._serve_file('/admin.html')
            return

        # Commit to Vote dashboard page
        if path == '/admin/commitments':
            self._serve_file('/commitments.html')
            return

        # API: Commitments data
        if path == '/api/admin/commitments':
            if require_admin(self):
                self.handle_commitments(qs)
            return

        # API: Commitments CSV export
        if path == '/api/admin/commitments/export':
            if require_admin(self):
                self.handle_commitments_export(qs)
            return

        # Calendar page
        if path == '/calendar':
            self._serve_file('/calendar.html')
            return

        # API: Search
        if path == '/api/search':
            self.handle_search(qs)
            return

        # API: Poll stats
        if path == '/api/polls':
            self.handle_poll_stats()
            return

        # API: Support trends by poll (daily deltas)
        if path == '/api/poll-support-trends':
            self.handle_poll_support_trends(qs)
            return

        # API: Canvass list by poll
        if path == '/api/poll-canvass':
            self.handle_poll_canvass(qs)
            return

        # API: Unique streets for a poll
        if path == '/api/poll-streets':
            self.handle_poll_streets(qs)
            return

        # API: Canvass walks generated from optimized supporter route plan
        if path == '/api/canvass/walks':
            if require_admin(self):
                self.handle_canvass_walks()
            return

        # API: Canvass assignments
        if path == '/api/canvass/assign':
            self.handle_canvass_assign(qs)
            return
        if path == '/api/canvass/my-assignments':
            if require_auth(self):
                self.handle_canvass_my_assignments()
            return
        if path == '/api/canvass/my-history':
            if require_auth(self):
                self.handle_canvass_my_history()
            return
        if path == '/api/canvass/assignment-records':
            if require_auth(self):
                self.handle_canvass_assignment_records(qs)
            return
        if path == '/api/canvass/complete':
            if require_auth(self):
                self.handle_canvass_complete(qs)
            return
        if path == '/api/canvass/report':
            self.handle_canvass_report(qs)
            return

        # API: Delete canvass assignment
        if path.startswith('/api/canvass/assignment/') and path.count('/') == 4:
            try:
                aid = int(path.split('/')[-1])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            self.handle_canvass_delete(aid)
            return

        # API: Search export as CSV
        if path == '/api/search/export':
            self.handle_search_export(qs)
            return

        # API: Get single supporter
        if path.startswith('/api/supporter/'):
            try:
                sid = int(path.split('/')[-2] if path.endswith('/history') or path.endswith('/household') else path.split('/')[-1])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return

            if path.endswith('/history'):
                self.handle_history(sid)
            elif path.endswith('/household'):
                self.handle_household(sid)
            else:
                self.handle_get_supporter(sid)
            return

        # API: Stats
        if path == '/api/stats':
            self.handle_stats()
            return

        # API: Export changes as CSV
        if path == '/api/export':
            self.handle_export()
            return

        # API: Recent changes
        if path == '/api/recent-changes':
            self.handle_recent_changes(qs)
            return

        # Public: Keep Taxes Down petition signature tracker
        if path == '/api/petition-count':
            self.handle_petition_count()
            return

        # SMS Outbox API
        if path == '/api/sms-outbox':
            if require_admin(self):
                self.handle_sms_outbox(qs)
            return

        # Twilio SMS status callback (public — called by Twilio, GET with query params)
        if path == '/api/twilio/sms-status':
            # Twilio sends status GET with query params like ?MessageSid=...&MessageStatus=...
            self.handle_twilio_sms_status(qs)
            return

        # Serve static files
        if path == '' or path == '/':
            path = '/index.html'

        file_path = os.path.join(WWW_DIR, path.lstrip('/'))
        if not os.path.commonpath([os.path.abspath(file_path), WWW_DIR]) == WWW_DIR:
            self._json({'error': 'Forbidden'}, 403)
            return

        if os.path.isfile(file_path):
            content_type = {
                '.html': 'text/html; charset=utf-8',
                '.css': 'text/css; charset=utf-8',
                '.js': 'application/javascript; charset=utf-8',
                '.json': 'application/json',
                '.png': 'image/png',
                '.jpg': 'image/jpeg',
                '.svg': 'image/svg+xml',
                '.ico': 'image/x-icon',
            }.get(os.path.splitext(file_path)[1], 'application/octet-stream')
            with open(file_path, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(data))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(data)
        else:
            self._json({'error': 'Not found'}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        body = self._read_body()

        # Auth: Login
        if path == '/api/auth/login':
            self.handle_login(body)
            return

        # Auth: Request/confirm a self-service password reset
        if path == '/api/auth/password-reset/request':
            self.handle_password_reset_request(body)
            return
        if path == '/api/auth/password-reset/confirm':
            self.handle_password_reset_confirm(body)
            return

        # Auth: Register (self-serve signup)
        if path == '/api/auth/register':
            self.handle_register(body)
            return

        # Auth: Logout
        if path == '/api/auth/logout':
            self.handle_logout()
            return

        # Survey: Save response
        if path == '/api/survey':
            self.handle_survey_save(body)
            return

        # Canvass: Assign walk (admin)
        if path == '/api/canvass/assign':
            self.handle_canvass_assign(body if body else {})
            return

        # Canvass: Assign an optimized route walk (admin)
        if path == '/api/canvass/assign-walk':
            if require_admin(self):
                self.handle_canvass_assign_walk(body if body else {})
            return

        # Canvass: Accept walk (canvasser)
        if path == '/api/canvass/accept':
            if require_auth(self):
                self.handle_canvass_accept(body if body else {})
            return

        # Canvass: Complete walk
        if path == '/api/canvass/complete':
            if require_auth(self):
                self.handle_canvass_complete(body if body else {})
            return

        # Admin: Create user (admin only)
        if path == '/api/admin/users':
            if require_admin(self):
                self.handle_admin_create_user(body)
            return

        # Admin: Create agent (admin only)
        if path == '/api/admin/agents':
            if require_admin(self):
                self.handle_admin_create_agent(body)
            return

        # Admin: Advance voter update (admin only)
        if path == '/api/admin/advance-voters/update':
            if require_admin(self):
                self.handle_admin_advance_voter_update(body if body else {})
            return

        # Admin: Supporter update (admin only)
        if path == '/api/admin/supporters/update':
            if require_admin(self):
                self.handle_admin_supporter_update(body if body else {})
            return

        # Admin: Attach/update a user's password-recovery email
        if path.startswith('/api/admin/users/') and path.endswith('/email'):
            if not require_admin(self):
                return
            try:
                uid = int(path.split('/')[-2])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            self.handle_admin_update_user_email(uid, body)
            return

        # Admin: Reset user password
        if path.startswith('/api/admin/users/') and path.endswith('/reset-password'):
            if not require_admin(self):
                return
            try:
                uid = int(path.split('/')[-2])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            self.handle_admin_reset_password(uid, body)
            return

        if path == '/api/supporter':
            self.handle_create(body)
            return

        # Task: Set a task/reminder on a supporter
        import re as _re
        m = _re.match(r'/api/supporter/(\d+)/task', path)
        if m:
            self.handle_supporter_task(int(m.group(1)), body if body else {})
            return

        # Admin: Tasks actions (complete, archive, reopen)
        if path == '/api/admin/tasks/complete':
            if require_auth(self):
                self.handle_admin_task_complete(body if body else {})
            return
        if path == '/api/admin/tasks/archive':
            if require_auth(self):
                self.handle_admin_task_archive(body if body else {})
            return
        if path == '/api/admin/tasks/reopen':
            if require_auth(self):
                self.handle_admin_task_reopen(body if body else {})
            return

        # Public: Commit-to-vote submission
        if path == '/api/commit-to-vote':
            self.handle_commit_to_vote(body if body else {})
            return

        # Public: Volunteer signup
        if path == '/api/volunteer-signup':
            self.handle_volunteer_signup(body if body else {})
            return

        # Twilio SMS status callback (public — called by Twilio, POST with form data)
        if path == '/api/twilio/sms-status':
            self.handle_twilio_sms_status(body)
            return

        self._json({'error': 'Not found'}, 404)

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path.startswith('/api/supporter/'):
            try:
                sid = int(path.split('/')[-1])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            body = self._read_body()
            self.handle_update(sid, body)
            return

        self._json({'error': 'Not found'}, 404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        # Admin: Delete user
        if path.startswith('/api/admin/users/'):
            if not require_admin(self):
                return
            try:
                uid = int(path.split('/')[-1])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            self.handle_admin_delete_user(uid)
            return

        # Admin: Delete agent
        if path.startswith('/api/admin/agents/'):
            if not require_admin(self):
                return
            try:
                aid = int(path.split('/')[-1])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            self.handle_admin_delete_agent(aid)
            return

        # Canvass: Delete assignment
        if path.startswith('/api/canvass/assignment/'):
            try:
                aid = int(path.split('/')[-1])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            self.handle_canvass_delete(aid)
            return

        self._json({'error': 'Not found'}, 404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_PATCH(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        # Admin: Activate user (activate pending account)
        if path.startswith('/api/admin/users/') and path.endswith('/activate'):
            if not require_admin(self):
                return
            try:
                uid = int(path.split('/')[-2])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            self.handle_admin_activate_user(uid)
            return

        # Touch: update timestamp on action
        if path.startswith('/api/supporter/') and path.endswith('/touch'):
            try:
                sid = int(path.split('/')[-2])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return
            conn = get_db()
            conn.execute("UPDATE supporters SET updated_at = datetime('now','localtime') WHERE id = ?", (sid,))
            conn.commit()
            conn.close()
            self._json({'success': True, 'touched': sid})
            return

        self._json({'error': 'Not found'}, 404)

    # ── API handlers ────────────────────────────────────────────

    def handle_search(self, qs):
        query = qs.get('q', [''])[0].strip()
        limit = min(int(qs.get('limit', [50])[0]), 200)
        offset = int(qs.get('offset', [0])[0])
        support_level = qs.get('support_level', [''])[0].strip()
        sign_request = qs.get('sign_request', [''])[0].strip()
        poll_filter = qs.get('poll', [''])[0].strip()

        conn = get_db()

        # Special: id:NNN search for direct record lookup
        if query.startswith('id:') and query[3:].strip().isdigit():
            sid = int(query[3:].strip())
            row = conn.execute('''SELECT id, poll, sign_request, apartment, street_number, street,
                full_name, first_name, last_name, support_level, result, phone, email, city, postal_code,
                notes, candidate_conversation_request, updated_at, created_at
                FROM supporters WHERE id = ?''', (sid,)).fetchone()
            conn.close()
            if row:
                d = dict_row(row)
                d['is_original'] = False
                self._json({'results': [d], 'total': 1, 'query': query,
                    'counts': {'supporters': 1 if d.get('support_level') == 'Supporter' else 0}})
            else:
                self._json({'results': [], 'total': 0, 'query': query, 'counts': {}})
            return

        # If filters provided but no search query, allow listing by filter
        if not query or len(query) < 2:
            if not support_level and not sign_request and not poll_filter:
                conn.close()
                self._json({'results': [], 'total': 0, 'message': 'Enter 2+ characters to search'})
                return

        # Base WHERE clauses
        where_parts = []
        params = []

        if query and len(query) >= 2:
            like = f'%{query}%'
            query_nospace = query.replace(' ', '')
            like_nospace = f'%{query_nospace}%'
            # Strip common street suffixes for fuzzy matching
            import re as _re
            query_nosuffix = _re.sub(r'\b(Dr|Drive|St|Street|Ave|Avenue|Blvd|Rd|Road|Crt|Ct|Court|Ln|Way|Cir|Pl|Terr|Gate|Gt)\b', '', query, flags=_re.IGNORECASE).strip()
            query_nosuffix = _re.sub(r'\s+', ' ', query_nosuffix)
            like_nosuffix = f'%{query_nosuffix.replace(" ", "")}%' if query_nosuffix else None
            where_parts.append('''(
                REPLACE(street, ' ', '') LIKE ? OR full_name LIKE ? OR phone LIKE ?
                OR REPLACE(street_number || street, ' ', '') LIKE ?''' +
                (''' OR REPLACE(street_number || street, ' ', '') LIKE ?''' if like_nosuffix else '') +
                '''\n                OR postal_code LIKE ?
                OR sign_request LIKE ?
                OR support_level LIKE ?
            )''')
            p = [like_nospace, like, like, like_nospace]
            if like_nosuffix:
                p.append(like_nosuffix)
            p.extend([like, like, like])
            params.extend(p)
            order_params = [like_nospace, like, like]
        else:
            order_params = []

        if support_level:
            where_parts.append('support_level = ?')
            params.append(support_level)

        if sign_request:
            where_parts.append('sign_request = ?')
            params.append(sign_request)

        if poll_filter:
            where_parts.append('poll = ?')
            params.append(poll_filter)

        where_clause = ' AND '.join(where_parts) if where_parts else '1=1'

        # Build ORDER BY
        if order_params:
            order_clause = '''ORDER BY
                CASE
                    WHEN REPLACE(street_number || street, ' ', '') LIKE ? THEN 1
                    WHEN full_name LIKE ? THEN 2
                    WHEN phone LIKE ? THEN 3
                    ELSE 4
                END,
                street, CAST(street_number AS INTEGER), street_number'''
        else:
            order_clause = 'ORDER BY street, CAST(street_number AS INTEGER), street_number'

        rows = conn.execute(f'''
            SELECT * FROM supporters
            WHERE {where_clause}
            {order_clause}
            LIMIT ? OFFSET ?
        ''', params + order_params + [limit, offset]).fetchall()

        total = conn.execute(f'''
            SELECT COUNT(*) FROM supporters WHERE {where_clause}
        ''', params).fetchone()[0]
        conn.close()

        self._json({
            'results': dict_rows(rows),
            'total': total,
            'query': query,
            'support_level': support_level,
            'sign_request': sign_request,
            'poll': poll_filter
        })

    def handle_search_export(self, qs):
        """Export current search results as CSV."""
        query = qs.get('q', [''])[0].strip()
        support_level = qs.get('support_level', [''])[0].strip()
        sign_request = qs.get('sign_request', [''])[0].strip()
        poll_filter = qs.get('poll', [''])[0].strip()

        # Require at least a filter or search term
        if (not query or len(query) < 2) and not support_level and not sign_request and not poll_filter:
            self._json({'error': 'Enter a search query or filter to export'}, 400)
            return

        conn = get_db()
        where_parts = []
        params = []

        order_params = []
        if query and len(query) >= 2:
            like = f'%{query}%'
            query_nospace = query.replace(' ', '')
            like_nospace = f'%{query_nospace}%'
            import re as _re2
            query_nosuffix = _re2.sub(r'\b(Dr|Drive|St|Street|Ave|Avenue|Blvd|Rd|Road|Crt|Ct|Court|Ln|Way|Cir|Pl|Terr|Gate|Gt)\b', '', query, flags=_re2.IGNORECASE).strip()
            query_nosuffix = _re2.sub(r'\s+', ' ', query_nosuffix)
            like_nosuffix = f'%{query_nosuffix.replace(" ", "")}%' if query_nosuffix else None
            where_parts.append('''(
                REPLACE(street, ' ', '') LIKE ? OR full_name LIKE ? OR phone LIKE ?
                OR REPLACE(street_number || street, ' ', '') LIKE ?''' +
                (''' OR REPLACE(street_number || street, ' ', '') LIKE ?''' if like_nosuffix else '') +
                '''\n                OR postal_code LIKE ?
                OR sign_request LIKE ?
                OR support_level LIKE ?
            )''')
            p = [like_nospace, like, like, like_nospace]
            if like_nosuffix:
                p.append(like_nosuffix)
            p.extend([like, like, like])
            params.extend(p)

        if support_level:
            where_parts.append('support_level = ?')
            params.append(support_level)

        if sign_request:
            where_parts.append('sign_request = ?')
            params.append(sign_request)

        if poll_filter:
            where_parts.append('poll = ?')
            params.append(poll_filter)

        where_clause = ' AND '.join(where_parts) if where_parts else '1=1'

        if order_params:
            order_clause = '''ORDER BY
                CASE
                    WHEN REPLACE(street_number || street, ' ', '') LIKE ? THEN 1
                    WHEN full_name LIKE ? THEN 2
                    WHEN phone LIKE ? THEN 3
                    ELSE 4
                END,
                street, CAST(street_number AS INTEGER), street_number'''
        else:
            order_clause = 'ORDER BY street, CAST(street_number AS INTEGER), street_number'

        # Export ALL matching results (no pagination)
        rows = conn.execute(f'''
            SELECT * FROM supporters
            WHERE {where_clause}
            {order_clause}
        ''', params + order_params).fetchall()
        conn.close()

        import io
        from datetime import datetime as dt
        output = io.StringIO()
        writer = csv.writer(output)

        if rows:
            writer.writerow(rows[0].keys())
            for row in rows:
                writer.writerow([str(v) if v is not None else '' for v in row])
        else:
            writer.writerow(['No results found'])

        csv_data = output.getvalue().encode('utf-8')
        # Sanitize query for filename
        safe_query = re.sub(r'[^a-zA-Z0-9]', '_', query or 'filtered')[:40]
        filename = f'ward25_search_{safe_query}_{dt.now().strftime("%Y-%m-%d")}.csv'

        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', len(csv_data))
        self.end_headers()
        self.wfile.write(csv_data)

    def handle_get_supporter(self, sid):
        conn = get_db()
        row = conn.execute('SELECT * FROM supporters WHERE id = ?', (sid,)).fetchone()
        if row:
            # Also get recent changes for context
            changes = conn.execute(
                'SELECT * FROM change_log WHERE supporter_id = ? ORDER BY changed_at DESC LIMIT 10',
                (sid,)
            ).fetchall()
            self._json({'supporter': dict_row(row), 'recent_changes': dict_rows(changes)})
        else:
            self._json({'error': 'Not found'}, 404)
        conn.close()

    def handle_household(self, sid):
        """Return all records at the same address as the given supporter."""
        conn = get_db()
        row = conn.execute('SELECT street_number, street FROM supporters WHERE id = ?', (sid,)).fetchone()
        if not row:
            self._json({'error': 'Not found'}, 404)
            conn.close()
            return
        members = conn.execute(
            'SELECT id, full_name, first_name, last_name, support_level, phone, email, apartment, is_original FROM supporters WHERE street_number = ? AND street = ? AND id != ? ORDER BY is_original DESC, full_name',
            (row['street_number'], row['street'], sid)
        ).fetchall()
        conn.close()
        self._json({'members': dict_rows(members)})

    def handle_update(self, sid, body):
        allowed_fields = {
            'full_name', 'first_name', 'last_name', 'phone', 'email',
            'street_number', 'street', 'apartment', 'city', 'postal_code',
            'support_level', 'notes', 'sign_request', 'candidate_conversation_request', 'poll', 'result'
        }

        # Get user from auth
        user_id = None
        username = 'system'
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            user = get_user_from_token(auth[7:])
            if user:
                user_id = user['id']
                username = user['username']

        conn = get_db()
        old = conn.execute('SELECT * FROM supporters WHERE id = ?', (sid,)).fetchone()
        if not old:
            conn.close()
            self._json({'error': 'Not found'}, 404)
            return

        updates = {}
        changes_logged = []
        # Use a single timestamp for all changes in this save
        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for field, new_val in body.items():
            if field not in allowed_fields:
                continue
            old_val = str(old[field] or '')
            new_val_str = str(new_val or '')
            if old_val != new_val_str:
                updates[field] = new_val
                conn.execute(
                    'INSERT INTO change_log (supporter_id, field_name, old_value, new_value, user_id, changed_by, changed_at) VALUES (?,?,?,?,?,?,?)',
                    (sid, field, old_val, new_val_str, user_id, username, now_ts)
                )
                changes_logged.append({
                    'field': field,
                    'old': old_val,
                    'new': new_val_str,
                    'changed_at': now_ts,
                    'by': username
                })

        if updates:
            # Auto-populate poll when address changes
            if 'street' in updates or 'street_number' in updates:
                updated_street = updates.get('street', str(old['street'] or ''))
                updated_num = updates.get('street_number', str(old['street_number'] or ''))
                auto_poll = street_index.lookup_poll(updated_street, updated_num)
                if auto_poll is not None:
                    updates['poll'] = str(auto_poll)
            
            set_clause = ', '.join(f'{k} = ?' for k in updates)
            values = list(updates.values()) + [sid]
            conn.execute(f'UPDATE supporters SET {set_clause}, updated_at = datetime("now","localtime") WHERE id = ?', values)
            conn.commit()

        updated = conn.execute('SELECT * FROM supporters WHERE id = ?', (sid,)).fetchone()
        conn.close()

        self._json({
            'success': True,
            'supporter': dict_row(updated),
            'changes': changes_logged,
            'changes_count': len(changes_logged)
        })

    def handle_history(self, sid):
        conn = get_db()
        changes = conn.execute(
            'SELECT * FROM change_log WHERE supporter_id = ? ORDER BY changed_at DESC LIMIT 100',
            (sid,)
        ).fetchall()
        conn.close()
        self._json({'supporter_id': sid, 'history': dict_rows(changes)})

    def handle_create(self, body):
        conn = get_db()
        fields = ['full_name', 'first_name', 'last_name', 'street_number', 'street',
                  'phone', 'email', 'city', 'postal_code', 'support_level', 'notes',
                  'apartment', 'sign_request', 'candidate_conversation_request', 'poll']
        values = {f: body.get(f, '') for f in fields}
        values['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M')

        # Auto-populate poll from street index
        street_name = values.get('street', '')
        street_num = values.get('street_number', '')
        if street_name and street_num:
            auto_poll = street_index.lookup_poll(street_name, street_num)
            if auto_poll is not None and not values.get('poll'):
                values['poll'] = str(auto_poll)

        cols = ', '.join(values.keys())
        placeholders = ', '.join('?' * len(values))
        conn.execute(f'INSERT INTO supporters ({cols}) VALUES ({placeholders})', list(values.values()))
        conn.commit()
        new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        row = conn.execute('SELECT * FROM supporters WHERE id = ?', (new_id,)).fetchone()
        # Log creation so it shows up in Changes (Today + Archive)
        created_label = (values.get('full_name') or values.get('first_name') or '').strip()
        conn.execute(
            "INSERT INTO change_log (supporter_id, field_name, old_value, new_value, changed_by, changed_at) VALUES (?,?,?,?,?,?)",
            (new_id, 'created', '', created_label, 'admin', values['created_at'])
        )
        conn.commit()
        conn.close()
        self._json({'success': True, 'supporter': dict_row(row)}, 201)

    def handle_supporter_task(self, sid, body):
        task = (body.get('task') or '').strip()
        due = (body.get('due_date') or '').strip()
        if not task:
            self._json({'error': 'Task description required'}, 400)
            return

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db()
        # Fetch full supporter record
        supporter = conn.execute('SELECT * FROM supporters WHERE id = ?', (sid,)).fetchone()
        if not supporter:
            conn.close()
            self._json({'error': 'Not found'}, 404)
            return
        s_name = supporter['full_name'] or supporter['first_name'] or ''
        s_phone = supporter['phone'] or ''
        s_email = supporter['email'] or ''
        s_addr = ' '.join(filter(None, [supporter['street_number'], supporter['street']]))
        if supporter['apartment']:
            s_addr += ', Apt ' + supporter['apartment']
        s_city = supporter['city'] or ''
        s_poll = supporter['poll'] or ''
        s_support = supporter['support_level'] or ''

        old_notes = supporter['notes'] or ''
        task_note = f'[TASK: {task}]' + (f' Due: {due}' if due else '') + f' (set {now})'
        new_notes = (old_notes + ' | ' + task_note) if old_notes else task_note
        conn.execute('UPDATE supporters SET notes = ?, updated_at = ? WHERE id = ?', (new_notes, now, sid))
        # Log the change
        conn.execute(
            'INSERT INTO change_log (supporter_id, field_name, old_value, new_value, changed_by, changed_at) VALUES (?,?,?,?,?,?)',
            (sid, 'notes', old_notes, new_notes, 'admin', now)
        )
        # Also insert into tasks table
        conn.execute(
            'INSERT INTO tasks (supporter_id, task_text, created_by, created_at, due_date, status) VALUES (?,?,?,?,?,?)',
            (sid, task, 'admin', now, due if due else None, 'open')
        )
        conn.commit()
        conn.close()

        # Send email notification via Microsoft Graph as info@electshawnallen.ca
        email_sent = False
        try:
            contact = f'Name: {s_name}\nPhone: {s_phone}\nEmail: {s_email}\nAddress: {s_addr}\nCity: {s_city}\nPoll: {s_poll}\nSupport: {s_support}'
            self._agentmail_send(
                'info@electshawnallen.ca',
                f'📋 Task: {task} — {s_name}',
                f'Task assigned from Ward 25 admin:\n\n━━ Supporter Details ━━\n{contact}\n\n━━ Task ━━\n{task}\nDue: {due or "Not set"}\n\nSet by admin on {now}\n\nJessica will follow up on this.'
            )
            email_sent = True
        except Exception as e:
            print(f'[Task] Email send failed: {e}')

        self._json({
            'success': True,
            'task': task,
            'due_date': due,
            'email_sent': email_sent,
            'recipient': 'info@electshawnallen.ca'
        })

    def handle_stats(self):
        conn = get_db()
        total = conn.execute('SELECT COUNT(*) FROM supporters').fetchone()[0]
        with_phone = conn.execute("SELECT COUNT(*) FROM supporters WHERE phone != '' AND phone IS NOT NULL").fetchone()[0]
        supporters = conn.execute("SELECT COUNT(*) FROM supporters WHERE support_level='Supporter'").fetchone()[0]
        changes = conn.execute('SELECT COUNT(*) FROM change_log').fetchone()[0]
        recent = conn.execute(
            "SELECT COUNT(*) FROM change_log WHERE changed_at > datetime('now', '-7 days', 'localtime')"
        ).fetchone()[0]
        conn.close()
        self._json({
            'total': total, 'with_phone': with_phone, 'supporters': supporters,
            'total_changes': changes, 'recent_changes': recent
        })

    def handle_poll_stats(self):
        """Return breakdown of records by poll (sub-area)."""
        conn = get_db()
        polls = conn.execute('''
            SELECT poll, COUNT(*) as total,
                   SUM(CASE WHEN support_level='Supporter' THEN 1 ELSE 0 END) as supporters,
                   SUM(CASE WHEN sign_request='Requested' THEN 1 ELSE 0 END) as signs_requested,
                   SUM(CASE WHEN sign_request='Declined' THEN 1 ELSE 0 END) as signs_declined
            FROM supporters
            WHERE poll IS NOT NULL AND poll != '' AND poll != 'None'
            GROUP BY poll
        ''').fetchall()
        # Sort by file order from street index
        poll_order = street_index.get_poll_order()
        poll_map = {str(p['poll']): dict_row(p) for p in polls}
        sorted_polls = [poll_map[str(p)] for p in poll_order if str(p) in poll_map]
        # Overall counts
        total = conn.execute('SELECT COUNT(*) FROM supporters').fetchone()[0]
        with_poll = conn.execute("SELECT COUNT(*) FROM supporters WHERE poll IS NOT NULL AND poll != '' AND poll != 'None'").fetchone()[0]
        without_poll = total - with_poll
        # Compute rank counts: how many polls at each position (1-5) modulo the order
        rank_colors = ['green', 'yellow', 'blue', 'orange', 'purple']
        rank_counts = [0, 0, 0, 0, 0]
        rank_polls = [[], [], [], [], []]
        for i, p in enumerate(sorted_polls):
            rank_idx = i % 5
            rank_counts[rank_idx] += 1
            rank_polls[rank_idx].append(p['poll'])
        rank_summary = []
        for i in range(5):
            rank_summary.append({
                'rank': i + 1,
                'color': rank_colors[i],
                'count': rank_counts[i],
                'polls': rank_polls[i]
            })
        
        # Merge election results if available
        election = load_election_results()
        election_rank_counts = {}
        allen_position_summary = []
        election_poll_ranks = {}  # poll -> allen_rank for frontend color coding
        election_polls_by_position = {str(pos): [] for pos in range(1, 7)}
        if election and election.get('polls'):
            epolls = election['polls']
            from collections import Counter
            pos_counter = Counter()
            for poll_id, er in epolls.items():
                ar = er.get('allen_rank')
                if not ar:
                    continue
                pos_counter[ar] += 1
                election_poll_ranks[str(poll_id)] = ar
                pos_key = str(ar if ar <= 5 else 6)
                election_polls_by_position.setdefault(pos_key, []).append({
                    'poll': str(poll_id),
                    'position': ar,
                    'label': f"{ar}{'st' if ar==1 else 'nd' if ar==2 else 'rd' if ar==3 else 'th'}",
                    'allen_votes': er.get('allen_votes'),
                    'winner': er.get('winner'),
                    'winner_votes': er.get('winner_votes'),
                    'total_votes': er.get('total_votes')
                })
            for pos in sorted(pos_counter):
                election_rank_counts[pos] = pos_counter[pos]
            for pos in range(1, 6):
                allen_position_summary.append({
                    'position': pos,
                    'label': f"{pos}{'st' if pos==1 else 'nd' if pos==2 else 'rd' if pos==3 else 'th'}",
                    'count': pos_counter.get(pos, 0)
                })
            for rows in election_polls_by_position.values():
                rows.sort(key=lambda x: int(x['poll']) if str(x['poll']).isdigit() else 999)
        
        conn.close()
        self._json({
            'polls': sorted_polls,
            'total': total,
            'with_poll': with_poll,
            'without_poll': without_poll,
            'rank_summary': rank_summary,
            'election': {
                'available': election is not None,
                'total_votes': election['total_votes'] if election else None,
                'allen_total': election['candidates'][2]['votes'] if election and len(election['candidates'])>2 else None,
                'allen_position': 3 if election else None,
                'allen_position_summary': allen_position_summary,
                'poll_ranks': election_poll_ranks,
                'polls_by_position': election_polls_by_position,
            } if election else {'available': False}
        })

    def handle_poll_support_trends(self, qs):
        """Return daily support gained/lost per poll."""
        days = int(qs.get('days', ['7'])[0])
        from datetime import datetime, timedelta
        cutoff = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        conn = get_db()
        rows = conn.execute('''
            SELECT date(cl.changed_at) as day, s.poll,
                   SUM(CASE WHEN cl.new_value = 'Supporter' AND (cl.old_value IS NULL OR cl.old_value != 'Supporter') THEN 1 ELSE 0 END) as gained,
                   SUM(CASE WHEN cl.old_value = 'Supporter' AND cl.new_value != 'Supporter' THEN 1 ELSE 0 END) as lost
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
            WHERE cl.field_name = 'support_level'
              AND cl.changed_at >= ?
              AND s.poll IS NOT NULL AND s.poll != '' AND s.poll != 'None'
            GROUP BY day, s.poll
            ORDER BY day DESC, CAST(s.poll AS INTEGER)
        ''', (cutoff,)).fetchall()
        
        # Build per-day, per-poll structure
        trends = {}
        poll_set = set()
        for r in rows:
            day = r['day']
            poll = r['poll']
            poll_set.add(poll)
            if day not in trends:
                trends[day] = {}
            net = (r['gained'] or 0) - (r['lost'] or 0)
            trends[day][poll] = {
                'gained': r['gained'] or 0,
                'lost': r['lost'] or 0,
                'net': net
            }
        
        # Build ordered poll list from street index
        poll_order = street_index.get_poll_order()
        sorted_polls = [p for p in poll_order if str(p) in poll_set]
        
        conn.close()
        self._json({
            'days': sorted(trends.keys(), reverse=True),
            'polls': sorted_polls,
            'trends': trends
        })

    def handle_poll_canvass(self, qs):
        """Return all records for a poll, sorted for walking routes."""
        poll_num = qs.get('poll', [''])[0].strip()
        fmt = qs.get('format', [''])[0].strip()
        street_filter = qs.get('street', [''])[0].strip()
        
        if not poll_num:
            self._json({'error': 'Poll number required'}, 400)
            return
        
        conn = get_db()
        if street_filter:
            rows = conn.execute('''
                SELECT id, street_number, street, apartment, full_name, phone,
                       support_level, sign_request, notes, poll, postal_code
                FROM supporters
                WHERE poll = ? AND street = ? COLLATE NOCASE
                ORDER BY street, CAST(street_number AS INTEGER)
            ''', (poll_num, street_filter)).fetchall()
        else:
            rows = conn.execute('''
                SELECT id, street_number, street, apartment, full_name, phone,
                       support_level, sign_request, notes, poll, postal_code
                FROM supporters
                WHERE poll = ?
                ORDER BY street, CAST(street_number AS INTEGER)
            ''', (poll_num,)).fetchall()
        conn.close()
        
        if fmt == 'csv':
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Address','Name','Phone','Support','Sign','Notes','Poll'])
            for r in rows:
                addr = ' '.join(filter(None, [str(r['street_number'] or ''), str(r['street'] or '')]))
                if r['apartment']:
                    addr += ' Apt ' + str(r['apartment'])
                writer.writerow([
                    addr, r['full_name'] or '', r['phone'] or '',
                    r['support_level'] or '', r['sign_request'] or '',
                    r['notes'] or '', r['poll'] or ''
                ])
            csv_data = output.getvalue().encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="poll_{poll_num}_canvass.csv"')
            self.send_header('Content-Length', len(csv_data))
            self.end_headers()
            self.wfile.write(csv_data)
            return
        
        self._json({
            'poll': poll_num,
            'count': len(rows),
            'records': dict_rows(rows)
        })

    def handle_poll_streets(self, qs):
        """Return unique streets for a poll."""
        poll_num = qs.get('poll', [''])[0].strip()
        if not poll_num:
            self._json({'error': 'Poll number required'}, 400)
            return
        
        conn = get_db()
        rows = conn.execute('''
            SELECT DISTINCT UPPER(street) as street_norm, street
            FROM supporters
            WHERE poll = ? AND street != ''
            ORDER BY UPPER(street)
        ''', (poll_num,)).fetchall()
        conn.close()
        # Deduplicate case-insensitively, keeping first encountered
        seen = set()
        streets = []
        for r in rows:
            norm = r['street_norm']
            if norm not in seen:
                seen.add(norm)
                streets.append(r['street'])
        self._json({'poll': poll_num, 'streets': streets})

    def handle_canvass_assign(self, body):
        """Assign a poll walk to a canvasser."""
        poll = body.get('poll', '').strip()
        canvasser = body.get('canvasser', '').strip()
        streets = body.get('streets', '').strip()
        
        if not poll or not canvasser:
            self._json({'error': 'Poll and canvasser required'}, 400)
            return
        
        if not require_admin(self):
            return
        assigned_by = self.current_user.get('username', 'admin')
        
        conn = get_db()
        conn.execute('''
            INSERT INTO canvass_assignments (poll, streets, assigned_to, assigned_by, status)
            VALUES (?, ?, ?, ?, 'assigned')
        ''', (poll, streets, canvasser, assigned_by))
        conn.commit()
        aid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        
        self._json({'success': True, 'assignment_id': aid, 'message': f'Poll {poll} assigned to {canvasser}'})

    def _load_canvass_walks(self):
        """Load optimized canvass walks generated from the supporter route plan."""
        if not os.path.exists(CANVASS_WALKS_PATH):
            return []
        try:
            with open(CANVASS_WALKS_PATH, 'r', encoding='utf-8') as f:
                return json.load(f).get('walks', [])
        except Exception:
            return []

    def _assignment_walk_meta(self, notes):
        try:
            meta = json.loads(notes or '{}')
            if isinstance(meta, dict) and meta.get('type') == 'canvass_walk':
                return meta
        except Exception:
            pass
        return None

    def handle_canvass_walks(self):
        """Return optimized walks plus current assignment state for the admin Canvass Management section."""
        walks = self._load_canvass_walks()
        conn = get_db()
        assigned = {}
        for r in conn.execute('SELECT id, assigned_to, status, created_at, completed_at, notes FROM canvass_assignments ORDER BY created_at DESC'):
            meta = self._assignment_walk_meta(r['notes'])
            if meta and meta.get('walk_id') and meta.get('walk_id') not in assigned:
                assigned[meta.get('walk_id')] = dict(r)
        conn.close()
        for w in walks:
            a = assigned.get(w.get('walk_id'))
            w['assignment'] = {
                'id': a['id'], 'assigned_to': a['assigned_to'], 'status': a['status'],
                'created_at': a['created_at'], 'completed_at': a['completed_at']
            } if a else None
            w.pop('stops', None)
            w.pop('supporter_ids', None)
        self._json({'walks': walks, 'count': len(walks)})

    def handle_canvass_assign_walk(self, body):
        """Assign one optimized walk packet to a canvasser."""
        walk_id = (body.get('walk_id') or '').strip()
        canvasser = (body.get('canvasser') or '').strip()
        if not walk_id or not canvasser:
            self._json({'error': 'Walk and canvasser required'}, 400)
            return
        walks = self._load_canvass_walks()
        walk = next((w for w in walks if w.get('walk_id') == walk_id), None)
        if not walk:
            self._json({'error': 'Walk not found'}, 404)
            return
        assigned_by = self.current_user.get('username', 'admin')
        streets = ', '.join((walk.get('streets') or [])[:6])
        if len(walk.get('streets') or []) > 6:
            streets += '…'
        meta = {
            'type': 'canvass_walk', 'walk_id': walk_id, 'route': walk.get('route'),
            'seq': walk.get('seq'), 'date': walk.get('date'), 'time': walk.get('time'),
            'poll': walk.get('poll'), 'doors': walk.get('doors'),
            'priority_doors': walk.get('priority_doors'),
            'supporter_ids': walk.get('supporter_ids') or []
        }
        conn = get_db()
        existing = None
        for r in conn.execute("SELECT id, notes FROM canvass_assignments WHERE status != 'completed' ORDER BY created_at DESC"):
            m = self._assignment_walk_meta(r['notes'])
            if m and m.get('walk_id') == walk_id:
                existing = r['id']
                break
        if existing:
            conn.execute("""
                UPDATE canvass_assignments
                SET assigned_to = ?, assigned_by = ?, poll = ?, streets = ?, status = 'assigned',
                    accepted_at = NULL, completed_at = NULL, notes = ?
                WHERE id = ?
            """, (canvasser, assigned_by, str(walk.get('poll') or ''), streets or (walk.get('route') or ''), json.dumps(meta), existing))
            aid = existing
        else:
            conn.execute("""
                INSERT INTO canvass_assignments (poll, streets, assigned_to, assigned_by, status, notes)
                VALUES (?, ?, ?, ?, 'assigned', ?)
            """, (str(walk.get('poll') or ''), streets or (walk.get('route') or ''), canvasser, assigned_by, json.dumps(meta)))
            aid = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.commit()
        conn.close()
        self._json({'success': True, 'assignment_id': aid, 'message': f'{walk_id} assigned to {canvasser}'})

    def handle_canvass_my_assignments(self):
        """Get assignments for the logged-in canvasser."""
        if not hasattr(self, 'current_user') or not self.current_user:
            self._json({'error': 'Not authenticated'}, 401)
            return
        
        username = self.current_user.get('username', '')
        
        conn = get_db()
        assignments = conn.execute('''
            SELECT id, poll, streets, status, created_at, accepted_at, completed_at, notes
            FROM canvass_assignments
            WHERE assigned_to = ? AND status != 'completed'
            ORDER BY created_at DESC
        ''', (username,)).fetchall()
        
        result = []
        for a in assignments:
            item = dict(a)
            # Count records without loading all of them; optimized walk assignments carry exact supporter IDs in notes.
            meta = self._assignment_walk_meta(a['notes'] if 'notes' in a.keys() else None)
            if meta and meta.get('supporter_ids'):
                item['count'] = len(meta.get('supporter_ids') or [])
                item['walk_id'] = meta.get('walk_id')
                item['route'] = meta.get('route')
            else:
                count_row = conn.execute(
                    'SELECT COUNT(*) FROM supporters WHERE poll = ?',
                    (a['poll'],)
                ).fetchone()
                item['count'] = count_row[0]
            result.append(item)
        
        conn.close()
        self._json({'assignments': result})

    def handle_canvass_accept(self, body):
        """Accept a walk assignment (canvasser)."""
        assignment_id = body.get('assignment_id', '').strip()
        
        if not assignment_id:
            self._json({'error': 'Assignment ID required'}, 400)
            return
        
        if not hasattr(self, 'current_user') or not self.current_user:
            self._json({'error': 'Not authenticated'}, 401)
            return
        
        conn = get_db()
        # Verify ownership
        owner = conn.execute(
            'SELECT assigned_to FROM canvass_assignments WHERE id = ?',
            (assignment_id,)
        ).fetchone()
        if not owner or owner[0] != self.current_user.get('username', ''):
            conn.close()
            self._json({'error': 'Not your assignment'}, 403)
            return
        
        conn.execute('''
            UPDATE canvass_assignments 
            SET status = 'accepted', accepted_at = datetime('now', 'localtime')
            WHERE id = ? AND status = 'assigned'
        ''', (assignment_id,))
        conn.commit()
        conn.close()
        
        self._json({'success': True, 'message': 'Walk accepted!'})

    def handle_canvass_my_history(self):
        """Get completed walk history for the logged-in canvasser."""
        if not hasattr(self, 'current_user') or not self.current_user:
            self._json({'error': 'Not authenticated'}, 401)
            return
        
        username = self.current_user.get('username', '')
        conn = get_db()
        history = conn.execute('''
            SELECT id, poll, streets, status, created_at, accepted_at, completed_at, notes
            FROM canvass_assignments
            WHERE assigned_to = ? AND status = 'completed'
            ORDER BY completed_at DESC
            LIMIT 50
        ''', (username,)).fetchall()
        conn.close()
        
        self._json({'history': dict_rows(history)})

    def handle_canvass_assignment_records(self, qs):
        """Get records for a specific assignment (for View button)."""
        assignment_id = qs.get('id', [''])[0]
        if not assignment_id:
            self._json({'error': 'Assignment ID required'}, 400)
            return
        
        if not hasattr(self, 'current_user') or not self.current_user:
            self._json({'error': 'Not authenticated'}, 401)
            return
        
        conn = get_db()
        a = conn.execute(
            'SELECT poll, assigned_to, notes FROM canvass_assignments WHERE id = ?',
            (assignment_id,)
        ).fetchone()
        
        if not a or a['assigned_to'] != self.current_user.get('username', ''):
            conn.close()
            self._json({'error': 'Not your assignment'}, 403)
            return
        
        meta = self._assignment_walk_meta(a['notes'])
        ids = (meta or {}).get('supporter_ids') or []
        if ids:
            placeholders = ','.join(['?'] * len(ids))
            rows_raw = conn.execute(f'''
                SELECT id, street_number, street, apartment, full_name, phone,
                       support_level, sign_request, notes, poll
                FROM supporters
                WHERE id IN ({placeholders})
            ''', ids).fetchall()
            by_id = {r['id']: r for r in rows_raw}
            rows = [by_id[i] for i in ids if i in by_id]
        else:
            rows = conn.execute('''
                SELECT id, street_number, street, apartment, full_name, phone,
                       support_level, sign_request, notes, poll
                FROM supporters
                WHERE poll = ?
                ORDER BY street, CAST(street_number AS INTEGER)
            ''', (a['poll'],)).fetchall()
        conn.close()
        
        self._json({'poll': a['poll'], 'records': dict_rows(rows), 'count': len(rows), 'walk': meta})

    def handle_canvass_complete(self, body):
        """Mark an assignment as complete."""
        assignment_id = body.get('assignment_id', '').strip()
        
        if not assignment_id:
            self._json({'error': 'Assignment ID required'}, 400)
            return
        
        conn = get_db()
        conn.execute('''
            UPDATE canvass_assignments 
            SET status = 'completed', completed_at = datetime('now', 'localtime')
            WHERE id = ?
        ''', (assignment_id,))
        conn.commit()
        conn.close()
        
        self._json({'success': True, 'message': 'Walk marked as complete'})

    def handle_canvass_delete(self, assignment_id):
        """Delete a canvass assignment."""
        if not require_admin(self):
            return
        conn = get_db()
        conn.execute('DELETE FROM canvass_assignments WHERE id = ?', (assignment_id,))
        conn.commit()
        conn.close()
        self._json({'success': True})

    def handle_canvass_report(self, qs):
        """Admin report on canvass assignments."""
        if not require_admin(self):
            return
        conn = get_db()
        
        total = conn.execute('SELECT COUNT(*) FROM canvass_assignments').fetchone()[0]
        completed = conn.execute("SELECT COUNT(*) FROM canvass_assignments WHERE status='completed'").fetchone()[0]
        assigned = conn.execute("SELECT COUNT(*) FROM canvass_assignments WHERE status='assigned'").fetchone()[0]
        
        by_canvasser = conn.execute('''
            SELECT assigned_to, 
                   COUNT(*) as total,
                   SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,
                   SUM(CASE WHEN status='assigned' THEN 1 ELSE 0 END) as assigned
            FROM canvass_assignments
            GROUP BY assigned_to
            ORDER BY completed DESC
        ''').fetchall()
        
        recent = conn.execute('''
            SELECT id, poll, streets, assigned_to, assigned_by, status, created_at, completed_at, notes
            FROM canvass_assignments
            ORDER BY created_at DESC
            LIMIT 50
        ''').fetchall()
        
        conn.close()
        
        self._json({
            'summary': {'total': total, 'completed': completed, 'assigned': assigned},
            'by_canvasser': dict_rows(by_canvasser),
            'recent': dict_rows(recent)
        })

    def handle_my_stats(self):
        """Return personal stats for the logged-in canvasser."""
        uid = self.current_user['id']
        conn = get_db()

        # Changes made today
        today_changes = conn.execute(
            "SELECT COUNT(*) FROM change_log WHERE user_id = ? AND date(changed_at) = date('now','localtime')",
            (uid,)
        ).fetchone()[0]

        # Changes made this week
        week_changes = conn.execute(
            "SELECT COUNT(*) FROM change_log WHERE user_id = ? AND changed_at > datetime('now', '-7 days', 'localtime')",
            (uid,)
        ).fetchone()[0]

        # Records touched today (updated_at matches today + user made a change)
        touched_today = conn.execute('''
            SELECT COUNT(DISTINCT supporter_id) FROM change_log
            WHERE user_id = ? AND date(changed_at) = date('now','localtime')
        ''', (uid,)).fetchone()[0]

        # Surveys completed today (notes updated with "Survey")
        surveys_today = conn.execute('''
            SELECT COUNT(*) FROM change_log
            WHERE user_id = ? AND date(changed_at) = date('now','localtime')
            AND field_name = 'notes' AND new_value LIKE '%Survey%'
        ''', (uid,)).fetchone()[0]

        # Total surveys (all time)
        total_surveys = conn.execute('''
            SELECT COUNT(*) FROM change_log
            WHERE user_id = ? AND field_name = 'notes' AND new_value LIKE '%Survey%'
        ''', (uid,)).fetchone()[0]

        # Supporters marked (all time)
        supporters_marked = conn.execute('''
            SELECT COUNT(*) FROM change_log
            WHERE user_id = ? AND field_name = 'support_level' AND new_value = 'Supporter'
        ''', (uid,)).fetchone()[0]

        # Supporters marked today
        supporters_today = conn.execute('''
            SELECT COUNT(*) FROM change_log
            WHERE user_id = ? AND field_name = 'support_level' AND new_value = 'Supporter'
            AND date(changed_at) = date('now','localtime')
        ''', (uid,)).fetchone()[0]

        # Signs marked (requested)
        signs_completed = conn.execute('''
            SELECT COUNT(*) FROM change_log
            WHERE user_id = ? AND field_name = 'sign_request' AND new_value = 'Requested'
        ''', (uid,)).fetchone()[0]

        # Signs requested today
        signs_today = conn.execute('''
            SELECT COUNT(*) FROM change_log
            WHERE user_id = ? AND field_name = 'sign_request' AND new_value = 'Requested'
            AND date(changed_at) = date('now','localtime')
        ''', (uid,)).fetchone()[0]

        conn.close()

        self._json({
            'today_changes': today_changes,
            'week_changes': week_changes,
            'touched_today': touched_today,
            'surveys_today': surveys_today,
            'total_surveys': total_surveys,
            'supporters_marked': supporters_marked,
            'supporters_today': supporters_today,
            'signs_completed': signs_completed,
            'signs_today': signs_today,
            'display_name': self.current_user.get('display_name', '')
        })

    def handle_recent_changes(self, qs):
        limit = min(int(qs.get('limit', [20])[0]), 100)
        conn = get_db()
        # Group changes that happened at the same time to the same record by the same user
        rows = conn.execute('''
            SELECT cl.supporter_id, s.full_name, s.street_number || ' ' || s.street as address,
                   GROUP_CONCAT(cl.field_name || ': ' || cl.old_value || ' → ' || cl.new_value, '; ') as changes_summary,
                   MAX(cl.changed_at) as changed_at,
                   MAX(cl.user_id) as user_id,
                   MAX(cl.changed_by) as changed_by,
                   COUNT(*) as field_count
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
            GROUP BY cl.supporter_id, strftime('%Y-%m-%d %H:%M', cl.changed_at), cl.user_id
            ORDER BY changed_at DESC
            LIMIT ?
        ''', (limit,)).fetchall()
        conn.close()
        self._json({'changes': dict_rows(rows)})

    def handle_export(self):
        conn = get_db()
        changes = conn.execute('''
            SELECT cl.*, s.full_name, s.street_number || ' ' || s.street as address
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
            ORDER BY cl.changed_at DESC
        ''').fetchall()

        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename="supporter_changes.csv"')
        self.end_headers()

        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Change ID', 'Supporter ID', 'Name', 'Address', 'Field', 'Old Value', 'New Value', 'Changed At'])
        for c in changes:
            writer.writerow([c['id'], c['supporter_id'], c['full_name'], c['address'],
                           c['field_name'], c['old_value'], c['new_value'], c['changed_at']])
        self.wfile.write(output.getvalue().encode('utf-8'))
        conn.close()

    # ── Helpers ─────────────────────────────────────────────────

    def _serve_file(self, filepath):
        """Serve a static file from WWW_DIR."""
        fp = os.path.join(WWW_DIR, filepath.lstrip('/'))
        if not os.path.isfile(fp):
            self._json({'error': 'Not found'}, 404)
            return
        ct = {
            '.html': 'text/html; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.js': 'application/javascript; charset=utf-8',
            '.json': 'application/json',
            '.png': 'image/png',
            '.svg': 'image/svg+xml',
        }.get(os.path.splitext(fp)[1], 'application/octet-stream')
        with open(fp, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', len(data))
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.end_headers()
        self.wfile.write(data)

    # ── Survey handler ──────────────────────────────────────

    def handle_survey_save(self, body):
        """Save survey response to the database."""
        conn = get_db()
        supporter_id = body.get('supporter_id')
        fields = ['voter_name','phone','email','address','years_in_ward','top_issue',
                  'top_issue_other','downsize_home','chow_rating','fair_share',
                  'lives_in_ward','heard_of_shawn','voting_plan','decided_support',
                  'involvement','street_concern','canvasser_notes','eligible_voters']
        values = {f: body.get(f, '') for f in fields}
        values['supporter_id'] = supporter_id

        # Convert arrays to pipe-separated strings
        for f in ['top_issue', 'involvement']:
            if isinstance(values[f], list):
                values[f] = '|'.join(values[f])

        cols = ', '.join(values.keys())
        placeholders = ', '.join('?' * len(values))
        conn.execute(f'INSERT INTO survey_responses ({cols}) VALUES ({placeholders})', list(values.values()))
        conn.commit()
        conn.close()
        self._json({'success': True, 'message': 'Survey saved'}, 201)

    # ── Auth handlers ────────────────────────────────────────

    def handle_password_reset_request(self, body):
        """Email a one-hour reset link without revealing whether an account exists."""
        generic = {
            'success': True,
            'message': 'If that account has a registered email, a reset link has been sent.'
        }
        identifier = (body.get('identifier') or '').strip()
        if identifier:
            conn = get_db()
            user = find_password_reset_user(conn, identifier)
            email = ((user or {}).get('email') or '').strip()
            if user and email and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
                token = create_password_reset(conn, user['id'])
                name = user.get('display_name') or user.get('username') or 'Canvasser'
                if token:
                    reset_url = f'https://db.electshawnallen.ca/?reset_token={token}'
                    text = (
                        f'Hello {name},\n\n'
                        'A password reset was requested for your Ward 25 canvassing account.\n\n'
                        f'Reset your password: {reset_url}\n\n'
                        'This link expires in one hour and can only be used once. '
                        'If you did not request this, you can ignore this email.'
                    )
                    try:
                        self._agentmail_send(email, 'Reset your Ward 25 canvassing password', text)
                    except Exception as exc:
                        print(f'[Password Reset Email] Failed: {exc}')
            conn.close()
        self._json(generic)

    def handle_password_reset_confirm(self, body):
        token = (body.get('token') or '').strip()
        password = body.get('password') or ''
        if not token:
            self._json({'error': 'Reset link is invalid or expired'}, 400)
            return
        conn = get_db()
        try:
            user_id = consume_password_reset(conn, token, password)
        except ValueError as exc:
            conn.close()
            self._json({'error': str(exc)}, 400)
            return
        conn.close()
        if not user_id:
            self._json({'error': 'Reset link is invalid or expired'}, 400)
            return
        self._json({'success': True, 'message': 'Password reset complete. You can now sign in.'})

    def handle_login(self, body):
        username = body.get('username', '').strip().lower()
        password = body.get('password', '')
        if not username or not password:
            self._json({'error': 'Username and password required'}, 400)
            return
        conn = get_db()
        row = conn.execute('SELECT * FROM users WHERE LOWER(username) = ?', (username,)).fetchone()
        if not row or not verify_password(password, row['password_hash']):
            conn.close()
            self._json({'error': 'Invalid credentials'}, 401)
            return
        if row['status'] == 'pending':
            conn.close()
            self._json({'error': 'Account pending approval — an admin must activate it'}, 403)
            return
        # Record last login
        conn.execute('UPDATE users SET last_login = ? WHERE id = ?',
                     (datetime.now().strftime('%Y-%m-%d %H:%M'), row['id']))
        conn.commit()
        conn.close()
        token = create_session(row['id'])
        self._json({
            'token': token,
            'user': {'id': row['id'], 'username': row['username'], 'role': row['role'], 'display_name': row['display_name']}
        })

    def handle_register(self, body):
        username = body.get('username', '').strip()
        password = body.get('password', '')
        display_name = body.get('display_name', '').strip() or username
        email = body.get('email', '').strip().lower()
        if not username or not password or not email:
            self._json({'error': 'Username, email and password required'}, 400)
            return
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            self._json({'error': 'Enter a valid email address'}, 400)
            return
        if len(username) < 2:
            self._json({'error': 'Username must be at least 2 characters'}, 400)
            return
        if len(password) < 8:
            self._json({'error': 'Password must be at least 8 characters'}, 400)
            return
        conn = get_db()
        existing = conn.execute('''
            SELECT id FROM users
            WHERE LOWER(username) = ? OR LOWER(COALESCE(email, '')) = ?
        ''', (username.lower(), email)).fetchone()
        if existing:
            conn.close()
            self._json({'error': 'Username or email already registered'}, 409)
            return
        try:
            conn.execute(
                'INSERT INTO users (username, password_hash, role, display_name, status, email) VALUES (?,?,?,?,?,?)',
                (username, hash_password(password), 'canvasser', display_name, 'pending', email))
            conn.commit()
            conn.close()
            self._json({'success': True, 'message': 'Registration submitted! An admin will activate your account.'}, 201)
        except Exception as e:
            conn.close()
            self._json({'error': 'Registration failed: ' + str(e)}, 500)

    def handle_logout(self):
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            conn = get_db()
            conn.execute('DELETE FROM sessions WHERE token = ?', (token,))
            conn.commit()
            conn.close()
        self._json({'success': True})

    def handle_admin_list_users(self):
        conn = get_db()
        users = conn.execute('SELECT id, username, role, display_name, email, created_at, last_login, status FROM users ORDER BY id').fetchall()
        conn.close()
        self._json({'users': dict_rows(users)})

    def handle_admin_create_user(self, body):
        username = body.get('username', '').strip()
        password = body.get('password', '')
        role = body.get('role', 'canvasser')
        display_name = body.get('display_name', username)
        email = body.get('email', '').strip().lower()
        if not username or not password or not email:
            self._json({'error': 'Username, email and password required'}, 400)
            return
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            self._json({'error': 'Enter a valid email address'}, 400)
            return
        if len(password) < 8:
            self._json({'error': 'Password must be at least 8 characters'}, 400)
            return
        if role not in ('admin', 'canvasser'):
            self._json({'error': 'Invalid role'}, 400)
            return
        try:
            conn = get_db()
            conn.execute('INSERT INTO users (username, password_hash, role, display_name, email) VALUES (?,?,?,?,?)',
                        (username, hash_password(password), role, display_name, email))
            conn.commit()
            new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
            conn.close()
            self._json({'success': True, 'user': {'id': new_id, 'username': username, 'role': role, 'display_name': display_name, 'email': email}}, 201)
        except sqlite3.IntegrityError:
            self._json({'error': 'Username already exists'}, 409)

    def handle_admin_activate_user(self, uid):
        conn = get_db()
        user = conn.execute('SELECT id, username, status FROM users WHERE id = ?', (uid,)).fetchone()
        if not user:
            conn.close()
            self._json({'error': 'User not found'}, 404)
            return
        if user['status'] == 'active':
            conn.close()
            self._json({'error': 'User is already active'}, 400)
            return
        conn.execute("UPDATE users SET status = 'active' WHERE id = ?", (uid,))
        conn.commit()
        conn.close()
        self._json({'success': True, 'message': 'User ' + user['username'] + ' activated'})

    def handle_admin_update_user_email(self, uid, body):
        email = body.get('email', '').strip().lower()
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            self._json({'error': 'Enter a valid email address'}, 400)
            return
        conn = get_db()
        user = conn.execute('SELECT id FROM users WHERE id = ?', (uid,)).fetchone()
        if not user:
            conn.close()
            self._json({'error': 'User not found'}, 404)
            return
        duplicate = conn.execute(
            'SELECT id FROM users WHERE LOWER(COALESCE(email, "")) = ? AND id <> ?',
            (email, uid)).fetchone()
        if duplicate:
            conn.close()
            self._json({'error': 'Email already registered'}, 409)
            return
        conn.execute('UPDATE users SET email = ? WHERE id = ?', (email, uid))
        conn.commit()
        conn.close()
        self._json({'success': True, 'email': email})

    def handle_admin_delete_user(self, uid):
        conn = get_db()
        if hasattr(self, 'current_user') and self.current_user.get('id') == uid:
            conn.close()
            self._json({'error': 'Cannot delete yourself'}, 400)
            return
        conn.execute('DELETE FROM sessions WHERE user_id = ?', (uid,))
        conn.execute('DELETE FROM users WHERE id = ?', (uid,))
        conn.commit()
        conn.close()
        self._json({'success': True})

    def handle_admin_list_agents(self):
        conn = get_db()
        agents = conn.execute('SELECT id, name, phone, email, agent_code, created_at FROM agents ORDER BY id').fetchall()
        conn.close()
        self._json({'agents': dict_rows(agents)})

    def handle_admin_create_agent(self, body):
        name = body.get('name', '').strip()
        phone = body.get('phone', '').strip()
        email = body.get('email', '').strip()
        agent_code = body.get('agent_code', '').strip()
        if not name:
            self._json({'error': 'Name is required'}, 400)
            return
        conn = get_db()
        conn.execute('INSERT INTO agents (name, phone, email, agent_code) VALUES (?,?,?,?)',
                     (name, phone, email, agent_code))
        conn.commit()
        new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        self._json({'success': True, 'agent': {'id': new_id, 'name': name}}, 201)

    def handle_admin_delete_agent(self, aid):
        conn = get_db()
        conn.execute('DELETE FROM agents WHERE id = ?', (aid,))
        conn.commit()
        conn.close()
        self._json({'success': True})

    def handle_admin_reset_password(self, uid, body):
        """Admin resets a user's password."""
        new_password = body.get('password', '').strip()
        if not new_password:
            self._json({'error': 'New password required'}, 400)
            return
        conn = get_db()
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                    (hash_password(new_password), uid))
        conn.commit()
        # Invalidate all sessions for this user
        conn.execute('DELETE FROM sessions WHERE user_id = ?', (uid,))
        conn.commit()
        conn.close()
        self._json({'success': True})

    # ── Admin endpoints ──────────────────────────────────────

    def handle_admin_daily_activity(self):
        """Return daily change counts for last 30 days."""
        conn = get_db()
        rows = conn.execute('''
            SELECT date(changed_at) as day, COUNT(*) as count
            FROM change_log
            WHERE changed_at > datetime('now', '-30 days', 'localtime')
            GROUP BY day
            ORDER BY day
        ''').fetchall()
        conn.close()
        self._json({'daily': dict_rows(rows)})

    def handle_admin_today(self):
        """Today's activity summary."""
        conn = get_db()
        today_changes = conn.execute(
            "SELECT COUNT(*) FROM change_log WHERE date(changed_at) = date('now','localtime')"
        ).fetchone()[0]
        today_touched = conn.execute(
            "SELECT COUNT(*) FROM supporters WHERE date(updated_at) = date('now','localtime')"
        ).fetchone()[0]
        week_changes = conn.execute(
            "SELECT COUNT(*) FROM change_log WHERE changed_at > datetime('now', '-7 days', 'localtime')"
        ).fetchone()[0]
        total_records = conn.execute('SELECT COUNT(*) FROM supporters').fetchone()[0]
        # Recent changes (last 20, grouped by same-timestamp updates)
        recent = conn.execute('''
            SELECT cl.supporter_id, s.full_name, s.street_number || ' ' || s.street as address,
                   GROUP_CONCAT(cl.field_name || ': ' || cl.old_value || ' → ' || cl.new_value, '; ') as changes_summary,
                   MAX(cl.changed_at) as changed_at,
                   MAX(cl.user_id) as user_id,
                   MAX(cl.changed_by) as changed_by,
                   COUNT(*) as field_count
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
            GROUP BY cl.supporter_id, strftime('%Y-%m-%d %H:%M', cl.changed_at), cl.user_id
            ORDER BY changed_at DESC LIMIT 20
        ''').fetchall()
        # Backup info
        backup_dir = os.path.join(os.path.dirname(DB_PATH), 'backups')
        backups = []
        if os.path.isdir(backup_dir):
            for f in sorted(os.listdir(backup_dir), reverse=True)[:5]:
                fp = os.path.join(backup_dir, f)
                backups.append({'name': f, 'size': os.path.getsize(fp), 'mtime': os.path.getmtime(fp)})
        conn.close()
        self._json({
            'today_changes': today_changes,
            'today_touched': today_touched,
            'week_changes': week_changes,
            'total_records': total_records,
            'recent': dict_rows(recent),
            'backups': backups,
            'db_size': os.path.getsize(DB_PATH)
        })

    def handle_admin_drilldown(self, qs):
        """Return the rows behind clickable admin/team stat cards."""
        drill_type = qs.get('type', [''])[0].strip()
        limit = min(int(qs.get('limit', [200])[0]), 500)
        conn = get_db()

        record_select = '''
            SELECT id, poll, sign_request, apartment, street_number, street,
                   full_name, first_name, last_name, support_level, phone, email,
                   notes, updated_at, created_at
            FROM supporters
        '''

        change_select = '''
            SELECT cl.supporter_id, s.id, s.poll, s.sign_request, s.apartment,
                   s.street_number, s.street, s.full_name, s.phone, s.email,
                   s.support_level, s.updated_at,
                   GROUP_CONCAT(cl.field_name || ': ' || COALESCE(cl.old_value,'') || ' → ' || COALESCE(cl.new_value,''), '; ') as changes_summary,
                   MAX(cl.changed_at) as changed_at,
                   MAX(cl.user_id) as user_id,
                   MAX(cl.changed_by) as changed_by,
                   COUNT(*) as field_count
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
        '''

        title = 'Details'
        mode = 'records'
        rows = []

        if drill_type == 'today_changes':
            title = 'Changes Today'
            mode = 'changes'
            rows = conn.execute(change_select + '''
                WHERE date(cl.changed_at) = date('now','localtime')
                GROUP BY cl.supporter_id, strftime('%Y-%m-%d %H:%M', cl.changed_at), cl.user_id
                ORDER BY changed_at DESC
                LIMIT ?
            ''', (limit,)).fetchall()
        elif drill_type == 'week_changes':
            title = 'Changes This Week'
            mode = 'changes'
            rows = conn.execute(change_select + '''
                WHERE cl.changed_at > datetime('now', '-7 days', 'localtime')
                GROUP BY cl.supporter_id, strftime('%Y-%m-%d %H:%M', cl.changed_at), cl.user_id
                ORDER BY changed_at DESC
                LIMIT ?
            ''', (limit,)).fetchall()
        elif drill_type in ('today_touched', 'team_touched'):
            title = 'Records Touched Today'
            rows = conn.execute(record_select + '''
                WHERE date(updated_at) = date('now','localtime')
                ORDER BY updated_at DESC
                LIMIT ?
            ''', (limit,)).fetchall()
        elif drill_type == 'surveys_completed':
            title = 'Surveys Completed'
            rows = conn.execute(record_select + '''
                WHERE id IN (
                    SELECT DISTINCT supporter_id FROM change_log
                    WHERE field_name='notes' AND new_value LIKE '%Survey%'
                )
                ORDER BY updated_at DESC
                LIMIT ?
            ''', (limit,)).fetchall()
        elif drill_type == 'signs_requested':
            title = 'Signs Requested'
            rows = conn.execute(record_select + '''
                WHERE sign_request='Requested'
                ORDER BY street, CAST(street_number AS INTEGER), street_number
                LIMIT ?
            ''', (limit,)).fetchall()
        elif drill_type == 'signs_declined':
            title = 'Signs Declined'
            rows = conn.execute(record_select + '''
                WHERE sign_request='Declined'
                ORDER BY street, CAST(street_number AS INTEGER), street_number
                LIMIT ?
            ''', (limit,)).fetchall()
        elif drill_type == 'supporters':
            title = 'Supporters'
            rows = conn.execute(record_select + '''
                WHERE support_level='Supporter'
                ORDER BY street, CAST(street_number AS INTEGER), street_number
                LIMIT ?
            ''', (limit,)).fetchall()
        else:
            conn.close()
            self._json({'error': 'Unknown drilldown type'}, 400)
            return

        # Count total separately for accurate footer, even when rows are limited.
        count_sql = {
            'today_changes': "SELECT COUNT(*) FROM change_log WHERE date(changed_at)=date('now','localtime')",
            'week_changes': "SELECT COUNT(*) FROM change_log WHERE changed_at > datetime('now', '-7 days', 'localtime')",
            'today_touched': "SELECT COUNT(*) FROM supporters WHERE date(updated_at)=date('now','localtime')",
            'team_touched': "SELECT COUNT(*) FROM supporters WHERE date(updated_at)=date('now','localtime')",
            'surveys_completed': "SELECT COUNT(DISTINCT supporter_id) FROM change_log WHERE field_name='notes' AND new_value LIKE '%Survey%'",
            'signs_requested': "SELECT COUNT(*) FROM supporters WHERE sign_request='Requested'",
            'signs_declined': "SELECT COUNT(*) FROM supporters WHERE sign_request='Declined'",
            'supporters': "SELECT COUNT(*) FROM supporters WHERE support_level='Supporter'",
        }[drill_type]
        total = conn.execute(count_sql).fetchone()[0]
        conn.close()
        self._json({'type': drill_type, 'title': title, 'mode': mode, 'total': total, 'limit': limit, 'rows': dict_rows(rows)})

    def handle_admin_export_db(self):
        """Download all supporter records as CSV (admin only)."""
        conn = get_db()
        rows = conn.execute('SELECT * FROM supporters ORDER BY id').fetchall()
        conn.close()

        from datetime import datetime as dt
        import io
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        if rows:
            writer.writerow(rows[0].keys())

        # Data
        for row in rows:
            writer.writerow([str(v) if v is not None else '' for v in row])

        csv_data = output.getvalue().encode('utf-8')
        filename = f'ward25_supporters_{dt.now().strftime("%Y-%m-%d")}.csv'

        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', len(csv_data))
        self.end_headers()
        self.wfile.write(csv_data)

    def handle_admin_tasks(self, qs=None):
        """List tasks from the tasks table with optional status filter."""
        status = (qs.get('status') or ['open'])[0] if qs else 'open'
        conn = get_db()
        rows = conn.execute("""
            SELECT t.id, t.supporter_id, t.task_text, t.created_by, t.created_at,
                   t.due_date, t.completed_at, t.completed_by, t.archived_at, t.status,
                   s.full_name, s.street_number, s.street, s.apartment
            FROM tasks t
            LEFT JOIN supporters s ON t.supporter_id = s.id
            WHERE t.status = ?
            ORDER BY t.created_at DESC
            LIMIT 500
        """, (status,)).fetchall()
        conn.close()
        tasks = []
        for r in rows:
            tasks.append({
                'id': r['id'],
                'supporter_id': r['supporter_id'],
                'full_name': r['full_name'] or '—',
                'address': ' '.join(filter(None, [r['street_number'], r['street']])),
                'apartment': r['apartment'],
                'task_text': r['task_text'],
                'created_by': r['created_by'] or '',
                'created_at': r['created_at'] or '',
                'due_date': r['due_date'] or '',
                'completed_at': r['completed_at'] or '',
                'completed_by': r['completed_by'] or '',
                'archived_at': r['archived_at'] or '',
                'status': r['status'],
            })
        self._json({'tasks': tasks, 'count': len(tasks)})

    def handle_admin_task_complete(self, body):
        """Mark a task as completed."""
        task_id = body.get('task_id')
        if not task_id:
            self._json({'error': 'task_id required'}, 400)
            return
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        completed_by = self.current_user.get('display_name') or self.current_user.get('username', 'unknown')
        conn = get_db()
        conn.execute(
            'UPDATE tasks SET status = ?, completed_at = ?, completed_by = ? WHERE id = ?',
            ('completed', now, completed_by, task_id)
        )
        conn.commit()
        conn.close()
        self._json({'success': True, 'completed_at': now, 'completed_by': completed_by})

    def handle_admin_task_archive(self, body):
        """Archive a task (completed or open)."""
        task_id = body.get('task_id')
        if not task_id:
            self._json({'error': 'task_id required'}, 400)
            return
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = get_db()
        # If not already completed, set completed_at too
        task = conn.execute('SELECT status FROM tasks WHERE id = ?', (task_id,)).fetchone()
        if not task:
            conn.close()
            self._json({'error': 'Task not found'}, 404)
            return
        if task['status'] != 'completed':
            completed_by = self.current_user.get('display_name') or self.current_user.get('username', 'unknown')
            conn.execute(
                'UPDATE tasks SET status = ?, completed_at = ?, completed_by = ?, archived_at = ? WHERE id = ?',
                ('archived', now, completed_by, now, task_id)
            )
        else:
            conn.execute(
                'UPDATE tasks SET status = ?, archived_at = ? WHERE id = ?',
                ('archived', now, task_id)
            )
        conn.commit()
        conn.close()
        self._json({'success': True, 'archived_at': now})

    def handle_admin_task_reopen(self, body):
        """Re-open a completed or archived task."""
        task_id = body.get('task_id')
        if not task_id:
            self._json({'error': 'task_id required'}, 400)
            return
        conn = get_db()
        conn.execute(
            'UPDATE tasks SET status = ?, completed_at = NULL, completed_by = NULL, archived_at = NULL WHERE id = ?',
            ('open', task_id)
        )
        conn.commit()
        conn.close()
        self._json({'success': True})

    def handle_admin_surveys(self, qs=None):
        """List survey responses with pagination."""
        import urllib.parse as _up
        limit = min(int(qs.get('limit', ['50'])[0]), 500) if qs else 50
        offset = int(qs.get('offset', ['0'])[0]) if qs else 0
        conn = get_db()
        total = conn.execute('SELECT COUNT(*) FROM survey_responses').fetchone()[0]
        rows = conn.execute('''
            SELECT sr.*, s.full_name as supporter_name, s.street_number, s.street, s.apartment
            FROM survey_responses sr
            LEFT JOIN supporters s ON sr.supporter_id = s.id
            ORDER BY sr.created_at DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset)).fetchall()
        conn.close()
        surveys = []
        for r in rows:
            d = dict(r)
            # Build address string
            addr = ' '.join(filter(None, [d.get('street_number'), d.get('street')]))
            if d.get('apartment'):
                addr += ', Apt ' + d['apartment']
            d['full_address'] = addr or d.get('address', '')
            surveys.append(d)
        self._json({'surveys': surveys, 'total': total, 'limit': limit, 'offset': offset})

    def handle_admin_surveys_export(self, qs=None):
        """Export all survey responses as CSV."""
        conn = get_db()
        rows = conn.execute('''
            SELECT sr.*, s.full_name as supporter_name, s.street_number, s.street, s.apartment
            FROM survey_responses sr
            LEFT JOIN supporters s ON sr.supporter_id = s.id
            ORDER BY sr.created_at DESC
        ''').fetchall()
        conn.close()
        import io, csv
        output = io.StringIO()
        if rows:
            keys = list(rows[0].keys())
            writer = csv.writer(output)
            writer.writerow(keys)
            for r in rows:
                writer.writerow([str(v) if v is not None else '' for v in r])
        else:
            output.write('No surveys found')
        csv_data = output.getvalue().encode('utf-8')
        from datetime import datetime as dt
        filename = f'ward25_surveys_{dt.now().strftime("%Y-%m-%d")}.csv'
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', len(csv_data))
        self.end_headers()
        self.wfile.write(csv_data)

    def handle_admin_advance_voters(self, qs=None):
        """List advance voters with filters: poll, result, street, search, pagination."""
        limit = min(max(int(qs.get('limit', ['100'])[0]), 1), 2000) if qs else 100
        offset = max(int(qs.get('offset', ['0'])[0]), 0) if qs else 0
        poll = qs.get('poll', [''])[0] if qs else ''
        result = qs.get('result', [''])[0] if qs else ''
        street = qs.get('street', [''])[0] if qs else ''
        search = qs.get('search', [''])[0] if qs else ''
        vid = qs.get('id', [''])[0] if qs else ''

        where = []
        params = []
        if vid:
            where.append('id = ?')
            params.append(vid)
        if poll:
            where.append('poll = ?')
            params.append(poll)
        if result:
            where.append('result = ?')
            params.append(result)
        if street:
            where.append('street LIKE ?')
            params.append(f'%{street}%')
        if search:
            where.append('(full_name LIKE ? OR address LIKE ?)')
            params.extend([f'%{search}%', f'%{search}%'])
        where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''

        conn = get_db()
        total = conn.execute(f'SELECT COUNT(*) FROM advance_voters {where_sql}', params).fetchone()[0]
        rows = conn.execute(f'''
            SELECT * FROM advance_voters {where_sql}
            ORDER BY poll, street, walk_num
            LIMIT ? OFFSET ?
        ''', params + [limit, offset]).fetchall()
        conn.close()
        voters = [dict(r) for r in rows]
        self._json({'voters': voters, 'total': total, 'limit': limit, 'offset': offset})

    def handle_admin_advance_voters_stats(self):
        """Stats for advance voters: total, contacted, by result."""
        conn = get_db()
        total = conn.execute('SELECT COUNT(*) FROM advance_voters').fetchone()[0]
        contacted = conn.execute("SELECT COUNT(*) FROM advance_voters WHERE result IS NOT NULL AND result != ''").fetchone()[0]
        by_result = {}
        for r in conn.execute("SELECT result, COUNT(*) c FROM advance_voters WHERE result IS NOT NULL AND result != '' GROUP BY result"):
            by_result[r['result']] = r['c']
        by_poll = {}
        for r in conn.execute('SELECT poll, COUNT(*) c FROM advance_voters GROUP BY poll ORDER BY c DESC'):
            by_poll[r['poll']] = r['c']
        conn.close()
        self._json({'total': total, 'contacted': contacted, 'remaining': total - contacted,
                    'by_result': by_result, 'by_poll': by_poll})

    def handle_admin_advance_voters_export(self, qs=None):
        """Export advance voters as CSV (optionally filtered)."""
        poll = qs.get('poll', [''])[0] if qs else ''
        result = qs.get('result', [''])[0] if qs else ''
        street = qs.get('street', [''])[0] if qs else ''

        where = []
        params = []
        if poll:
            where.append('poll = ?'); params.append(poll)
        if result:
            where.append('result = ?'); params.append(result)
        if street:
            where.append('street = ?'); params.append(street)
        where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''

        conn = get_db()
        rows = conn.execute(f'''
            SELECT id, poll, street, walk_num, address, postal_code, full_name,
                   first_name, last_name, phone, email, support_level, sign_request,
                   result, notes, contacted_at
            FROM advance_voters {where_sql}
            ORDER BY poll, street, walk_num
        ''', params).fetchall()
        conn.close()

        import io
        output = io.StringIO()
        writer = csv.writer(output)
        if rows:
            writer.writerow(['id','poll','street','walk_num','address','postal_code','full_name',
                            'first_name','last_name','phone','email','support_level','sign_request','result','notes','contacted_at'])
            for r in rows:
                writer.writerow([r['id'], r['poll'], r['street'], r['walk_num'], r['address'], r['postal_code'], r['full_name'],
                               r['first_name'], r['last_name'], r['phone'], r['email'], r['support_level'], r['sign_request'],
                               r['result'], r['notes'], r['contacted_at']])
        else:
            output.write('No advance voters found')
        csv_data = output.getvalue().encode('utf-8')
        filename = f'ward25_advance_voters_{datetime.now().strftime("%Y-%m-%d")}.csv'
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', len(csv_data))
        self.end_headers()
        self.wfile.write(csv_data)

    def handle_admin_advance_voter_update(self, body=None):
        """Update a single advance voter's result/notes/phone/email (admin only).

        Cascade rule: when a voter is marked 'No Answer' (not home), every other
        still-unmarked voter at the same address is auto-marked 'No Answer' too,
        since a single knock covers the whole household. Only NULL (uncontacted)
        records are overwritten, so any prior Supporter/Neutral marks are preserved.
        """
        body = body or {}
        voter_id = body.get('id')
        if not voter_id:
            self._json({'error': 'Missing voter id'}, 400)
            return
        conn = get_db()
        row = conn.execute('SELECT * FROM advance_voters WHERE id = ?', (voter_id,)).fetchone()
        if not row:
            conn.close()
            self._json({'error': 'Voter not found'}, 404)
            return
        result = body.get('result', row['result'])
        notes = body.get('notes', row['notes'])
        phone = body.get('phone', row['phone'])
        email = body.get('email', row['email'])
        full_name = body.get('full_name', row['full_name'])
        first_name = body.get('first_name', row['first_name'])
        last_name = body.get('last_name', row['last_name'])
        apartment = body.get('apartment', row['apartment'])
        support_level = body.get('support_level', row['support_level'])
        sign_request = body.get('sign_request', row['sign_request'])
        conn.execute('''
            UPDATE advance_voters
            SET result = ?, notes = ?, phone = ?, email = ?, full_name = ?,
                first_name = ?, last_name = ?, apartment = ?,
                support_level = ?, sign_request = ?,
                contacted_at = datetime('now', 'localtime')
            WHERE id = ?
        ''', (result or None, notes or None, phone or None, email or None,
              full_name or None, first_name or None, last_name or None,
              apartment or None, support_level or None, sign_request or None,
              voter_id))
        cascaded = 0
        if result == 'No Answer' and row['address']:
            cur = conn.execute('''
                UPDATE advance_voters
                SET result = 'No Answer', contacted_at = datetime('now', 'localtime')
                WHERE address = ? AND id != ? AND result IS NULL
            ''', (row['address'], voter_id))
            cascaded = cur.rowcount
        conn.commit()
        conn.close()
        self._json({'ok': True, 'id': voter_id, 'result': result, 'notes': notes,
                    'phone': phone, 'email': email, 'cascaded': cascaded})

    def handle_admin_supporters(self, qs=None):
        """List supporters with filters: poll, support_level, sign_request, result, conservative, search, pagination, sorting."""
        limit = min(max(int(qs.get('limit', ['100'])[0]), 1), 2000) if qs else 100
        offset = max(int(qs.get('offset', ['0'])[0]), 0) if qs else 0
        poll = qs.get('poll', [''])[0] if qs else ''
        support_level = qs.get('support_level', [''])[0] if qs else ''
        sign_request = qs.get('sign_request', [''])[0] if qs else ''
        result = qs.get('result', [''])[0] if qs else ''
        conservative = qs.get('conservative', [''])[0] if qs else ''
        search = qs.get('search', [''])[0] if qs else ''
        sort_by = qs.get('sort_by', ['poll'])[0] if qs else 'poll'
        sort_dir = qs.get('sort_dir', ['asc'])[0] if qs else 'asc'

        where = []
        params = []
        if poll:
            where.append('poll = ?'); params.append(poll)
        if support_level:
            where.append('support_level = ?'); params.append(support_level)
        if sign_request:
            where.append('sign_request = ?'); params.append(sign_request)
        if result:
            where.append('result = ?'); params.append(result)
        if conservative:
            where.append('is_conservative = ?'); params.append(1 if conservative.lower() in ('1','true','yes') else 0)
        if search:
            where.append('(full_name LIKE ? OR street LIKE ? OR street_number LIKE ? OR phone LIKE ?)')
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'])
        where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''

        # Validate sort column
        allowed_cols = {
            'id': ('id', 'id'),
            'poll': ('CAST(poll AS INTEGER)', 'poll'),
            'full_name': ('full_name', 'full_name'),
            'street': ('street', 'street'),
            'street_number': ('CAST(street_number AS INTEGER)', 'street_number'),
            'postal': ('postal_code', 'postal_code'),
            'support_level': ('support_level', 'support_level'),
            'result': ('result', 'result'),
            'sign_request': ('sign_request', 'sign_request'),
            'phone': ('phone', 'phone'),
            'email': ('email', 'email'),
            'updated_at': ('updated_at', 'updated_at'),
        }
        sort_expr, sort_raw = allowed_cols.get(sort_by, ('CAST(poll AS INTEGER)', 'poll'))
        sort_dir_sql = 'DESC' if sort_dir.lower() == 'desc' else 'ASC'

        conn = get_db()
        total = conn.execute(f'SELECT COUNT(*) FROM supporters {where_sql}', params).fetchone()[0]
        rows = conn.execute(f'''
            SELECT * FROM supporters {where_sql}
            ORDER BY (CASE WHEN {sort_raw} IS NULL OR {sort_raw} = '' THEN 1 ELSE 0 END),
                     {sort_expr} {sort_dir_sql},
                     poll, street, CAST(street_number AS INTEGER), street_number
            LIMIT ? OFFSET ?
        ''', params + [limit, offset]).fetchall()
        conn.close()
        supporters = [dict(r) for r in rows]
        self._json({'supporters': supporters, 'total': total, 'limit': limit, 'offset': offset, 'sort_by': sort_by, 'sort_dir': sort_dir})

    def handle_admin_supporters_stats(self):
        """Stats for supporters: total, by support_level, by poll, by sign_request."""
        conn = get_db()
        total = conn.execute('SELECT COUNT(*) FROM supporters').fetchone()[0]
        by_level = {}
        for r in conn.execute("SELECT support_level, COUNT(*) c FROM supporters WHERE support_level IS NOT NULL AND support_level != '' GROUP BY support_level"):
            by_level[r['support_level']] = r['c']
        by_poll = {}
        for r in conn.execute('SELECT poll, COUNT(*) c FROM supporters WHERE poll IS NOT NULL AND poll != \"\" GROUP BY poll ORDER BY c DESC'):
            by_poll[r['poll']] = r['c']
        by_sign = {}
        for r in conn.execute("SELECT sign_request, COUNT(*) c FROM supporters WHERE sign_request IS NOT NULL AND sign_request != '' GROUP BY sign_request"):
            by_sign[r['sign_request']] = r['c']
        conn.close()
        self._json({'total': total, 'by_support_level': by_level, 'by_poll': by_poll, 'by_sign_request': by_sign})

    def handle_admin_supporters_export(self, qs=None):
        """Export supporters as CSV (optionally filtered)."""
        poll = qs.get('poll', [''])[0] if qs else ''
        support_level = qs.get('support_level', [''])[0] if qs else ''
        sign_request = qs.get('sign_request', [''])[0] if qs else ''
        result = qs.get('result', [''])[0] if qs else ''
        conservative = qs.get('conservative', [''])[0] if qs else ''
        search = qs.get('search', [''])[0] if qs else ''

        where = []
        params = []
        if poll:
            where.append('poll = ?'); params.append(poll)
        if support_level:
            where.append('support_level = ?'); params.append(support_level)
        if sign_request:
            where.append('sign_request = ?'); params.append(sign_request)
        if result:
            where.append('result = ?'); params.append(result)
        if conservative:
            where.append('is_conservative = ?'); params.append(1 if conservative.lower() in ('1','true','yes') else 0)
        if search:
            where.append('(full_name LIKE ? OR street LIKE ? OR street_number LIKE ? OR phone LIKE ?)')
            params.extend([f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'])
        where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''

        conn = get_db()
        rows = conn.execute(f'''
            SELECT id, poll, street_number, street, apartment, full_name, first_name, last_name,
                   support_level, phone, email, city, postal_code, sign_request, result, notes, updated_at, created_at
            FROM supporters {where_sql}
            ORDER BY poll, street, CAST(street_number AS INTEGER), street_number
        ''', params).fetchall()
        conn.close()

        import io, csv
        from datetime import datetime
        output = io.StringIO()
        writer = csv.writer(output)
        if rows:
            writer.writerow(['id','poll','street_number','street','apartment','full_name','first_name','last_name',
                           'support_level','phone','email','city','postal_code','sign_request','result','notes','updated_at','created_at'])
            for r in rows:
                writer.writerow([r['id'], r['poll'], r['street_number'], r['street'], r['apartment'],
                               r['full_name'], r['first_name'], r['last_name'], r['support_level'],
                               r['phone'], r['email'], r['city'], r['postal_code'], r['sign_request'],
                               r['result'], r['notes'], r['updated_at'], r['created_at']])
        else:
            output.write('No supporters found')
        csv_data = output.getvalue().encode('utf-8')
        filename = f'ward25_supporters_{datetime.now().strftime("%Y-%m-%d")}.csv'
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', str(len(csv_data)))
        self.end_headers()
        self.wfile.write(csv_data)

    def handle_admin_supporter_update(self, body=None):
        """Update a supporter's fields (admin only)."""
        body = body or {}
        sid = body.get('id')
        if not sid:
            self._json({'error': 'Missing supporter id'}, 400)
            return
        conn = get_db()
        row = conn.execute('SELECT * FROM supporters WHERE id = ?', (sid,)).fetchone()
        if not row:
            conn.close()
            self._json({'error': 'Supporter not found'}, 404)
            return
        # Fields that can be updated via this endpoint
        allowed = ['poll', 'support_level', 'sign_request', 'phone', 'email', 'notes',
                   'street_number', 'street', 'apartment', 'result',
                   'first_name', 'last_name', 'full_name']
        updates = {}
        changes_logged = []
        user_id = None
        username = 'admin'
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            user = get_user_from_token(auth[7:])
            if user:
                user_id = user['id']
                username = user['username']
        now_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        for f in allowed:
            if f in body:
                old_val = str(row[f] or '')
                new_val = body[f] or None
                new_val_str = str(new_val or '')
                if old_val != new_val_str:
                    updates[f] = new_val
                    conn.execute(
                        'INSERT INTO change_log (supporter_id, field_name, old_value, new_value, user_id, changed_by, changed_at) VALUES (?,?,?,?,?,?,?)',
                        (sid, f, old_val, new_val_str, user_id, username, now_ts)
                    )
                    changes_logged.append({'field': f, 'old': old_val, 'new': new_val_str})
        if not updates:
            conn.close()
            self._json({'ok': True, 'supporter': dict(row), 'changes': []})
            return
        # Auto-populate poll when address changes
        if 'street' in updates or 'street_number' in updates:
            updated_street = updates.get('street', str(row['street'] or ''))
            updated_num = updates.get('street_number', str(row['street_number'] or ''))
            auto_poll = street_index.lookup_poll(updated_street, updated_num)
            if auto_poll is not None:
                updates['poll'] = str(auto_poll)
        # Auto-sync full_name when first/last name changes
        if 'first_name' in updates or 'last_name' in updates:
            fn = updates.get('first_name', str(row['first_name'] or ''))
            ln = updates.get('last_name', str(row['last_name'] or ''))
            updates['full_name'] = (fn + ' ' + ln).strip()
        set_clause = ', '.join(f'{k} = ?' for k in updates)
        values = list(updates.values()) + [sid]
        conn.execute(f'UPDATE supporters SET {set_clause}, updated_at = datetime("now","localtime") WHERE id = ?', values)
        conn.commit()
        updated = conn.execute('SELECT * FROM supporters WHERE id = ?', (sid,)).fetchone()
        conn.close()
        self._json({'ok': True, 'supporter': dict(updated), 'changes': changes_logged})

    def handle_admin_street_search(self, qs=None):
        """Unified search across Advance Voters, Supporters and Conservative voters by street/name.

        Params:
          q         search term (street, name, or partial address)
          lists     comma-list of which lists to include:
                    'advance' (advance voters), 'supporters' (all), 'conservative' (conservative-only)
                    default: all three
          limit     max rows per list (default 100)
        Returns grouped arrays keyed by list.
        """
        q = (qs.get('q', [''])[0] if qs else '').strip()
        lists = (qs.get('lists', ['all'])[0] if qs else 'all').strip().lower()
        if not q:
            self._json({'ok': True, 'q': q, 'results': {'advance': [], 'supporters': [], 'conservative': []}})
            return
        include = set(lists.split(',')) if lists != 'all' else {'advance', 'supporters', 'conservative'}
        limit = min(max(int(qs.get('limit', ['100'])[0]), 1), 500) if qs else 100

        conn = get_db()
        out = {'advance': [], 'supporters': [], 'conservative': []}

        if 'advance' in include:
            rows = conn.execute('''
                SELECT id, poll, full_name, address, postal_code, result, notes
                FROM advance_voters
                WHERE full_name LIKE ? OR address LIKE ? OR street LIKE ?
                ORDER BY poll, street, walk_num
                LIMIT ?
            ''', (f'%{q}%', f'%{q}%', f'%{q}%', limit)).fetchall()
            out['advance'] = [dict(r) for r in rows]

        if 'supporters' in include:
            rows = conn.execute('''
                SELECT id, poll, full_name, street_number, street, apartment, postal_code,
                       support_level, result, sign_request, phone, email, notes, is_conservative
                FROM supporters
                WHERE full_name LIKE ? OR street LIKE ? OR street_number LIKE ? OR phone LIKE ?
                ORDER BY poll, street, CAST(street_number AS INTEGER), street_number
                LIMIT ?
            ''', (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%', limit)).fetchall()
            out['supporters'] = [dict(r) for r in rows]

        if 'conservative' in include:
            rows = conn.execute('''
                SELECT id, poll, full_name, street_number, street, apartment, postal_code,
                       support_level, result, sign_request, phone, email, notes
                FROM supporters
                WHERE is_conservative = 1
                  AND (full_name LIKE ? OR street LIKE ? OR street_number LIKE ? OR phone LIKE ?)
                ORDER BY poll, street, CAST(street_number AS INTEGER), street_number
                LIMIT ?
            ''', (f'%{q}%', f'%{q}%', f'%{q}%', f'%{q}%', limit)).fetchall()
            out['conservative'] = [dict(r) for r in rows]

        conn.close()
        self._json({'ok': True, 'q': q, 'lists': sorted(include), 'results': out})

    def handle_admin_web_submissions(self, qs=None):
        """List Keep Taxes Down petition and Pocketbook submissions."""
        limit = min(max(int(qs.get('limit', ['100'])[0]), 1), 500) if qs else 100
        offset = max(int(qs.get('offset', ['0'])[0]), 0) if qs else 0
        source_filter = qs.get('source', ['all'])[0] if qs else 'all'
        source_map = {
            'campaign': 'electshawnallen',
            'petition': 'keeptaxesdown-petition',
            'pocketbook': 'keeptaxesdown-pocketbook',
        }
        params = []
        where = "WHERE source IN ('electshawnallen','keeptaxesdown-petition','keeptaxesdown-pocketbook')"
        if source_filter in source_map:
            where += ' AND source = ?'
            params.append(source_map[source_filter])

        conn = get_db()
        counts_rows = conn.execute('''
            SELECT source, COUNT(*) AS count
            FROM commit_to_vote
            WHERE source IN ('electshawnallen','keeptaxesdown-petition','keeptaxesdown-pocketbook')
            GROUP BY source
        ''').fetchall()
        counts = {'campaign': 0, 'petition': 0, 'pocketbook': 0}
        for row in counts_rows:
            if row['source'] == 'electshawnallen':
                counts['campaign'] = row['count']
            elif row['source'] == 'keeptaxesdown-petition':
                counts['petition'] = row['count']
            elif row['source'] == 'keeptaxesdown-pocketbook':
                counts['pocketbook'] = row['count']
        total = conn.execute(f'SELECT COUNT(*) FROM commit_to_vote {where}', params).fetchone()[0]
        rows = conn.execute(f'''
            SELECT id, first_name, last_name, email, phone, address, postal,
                   top_issue, registration_status, pledge, town_hall, volunteer,
                   lawn_sign, email_consent, sms_consent, source, submitted_at
            FROM commit_to_vote
            {where}
            ORDER BY datetime(submitted_at) DESC, id DESC
            LIMIT ? OFFSET ?
        ''', params + [limit, offset]).fetchall()
        conn.close()
        self._json({
            'submissions': dict_rows(rows),
            'total': total,
            'counts': counts,
            'limit': limit,
            'offset': offset,
            'source': source_filter,
        })

    def handle_admin_web_submissions_export(self, qs=None):
        """Export Keep Taxes Down petition and Pocketbook submissions as CSV."""
        source_filter = qs.get('source', ['all'])[0] if qs else 'all'
        source_map = {
            'campaign': 'electshawnallen',
            'petition': 'keeptaxesdown-petition',
            'pocketbook': 'keeptaxesdown-pocketbook',
        }
        params = []
        where = "WHERE source IN ('electshawnallen','keeptaxesdown-petition','keeptaxesdown-pocketbook')"
        if source_filter in source_map:
            where += ' AND source = ?'
            params.append(source_map[source_filter])
        conn = get_db()
        rows = conn.execute(f'''
            SELECT id, source, first_name, last_name, email, phone, address, postal,
                   top_issue, registration_status, pledge, town_hall, volunteer,
                   lawn_sign, email_consent, sms_consent, submitted_at
            FROM commit_to_vote
            {where}
            ORDER BY datetime(submitted_at) DESC, id DESC
        ''', params).fetchall()
        conn.close()
        import io, csv
        output = io.StringIO()
        keys = ['id','source','first_name','last_name','email','phone','address','postal',
                'top_issue','registration_status','pledge','town_hall','volunteer',
                'lawn_sign','email_consent','sms_consent','submitted_at']
        writer = csv.writer(output)
        writer.writerow(keys)
        for row in rows:
            writer.writerow([str(row[k]) if row[k] is not None else '' for k in keys])
        csv_data = output.getvalue().encode('utf-8')
        from datetime import datetime as dt
        filename = f'keeptaxesdown_submissions_{source_filter}_{dt.now().strftime("%Y-%m-%d")}.csv'
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', str(len(csv_data)))
        self.end_headers()
        self.wfile.write(csv_data)

    def handle_commitments(self, qs=None):
        """Return commitments from the commit-to-vote API database."""
        page = max(0, int(qs.get('page', ['0'])[0]))
        limit = max(1, min(200, int(qs.get('limit', ['50'])[0])))
        offset = page * limit
        search = qs.get('search', [''])[0].strip()
        volunteer = qs.get('volunteer', [''])[0]
        sign = qs.get('sign', [''])[0]

        COMMIT_DB = os.path.expanduser('~/.hermes/scripts/commitments.db')
        if not os.path.exists(COMMIT_DB):
            self._json({'records': [], 'total': 0, 'page': page})
            return

        conn = sqlite3.connect(COMMIT_DB)
        conn.row_factory = sqlite3.Row
        where = []
        params = []
        if search:
            where.append("(first || ' ' || last LIKE ? OR email LIKE ? OR address LIKE ?)")
            s = f'%{search}%'
            params.extend([s, s, s])
        if volunteer == '1':
            where.append('volunteer = 1')
        elif volunteer == '0':
            where.append('volunteer = 0')
        if sign == '1':
            where.append('"sign" = 1')
        elif sign == '0':
            where.append('"sign" = 0')

        where_clause = ('WHERE ' + ' AND '.join(where)) if where else ''
        total = conn.execute(f'SELECT COUNT(*) FROM commitments {where_clause}', params).fetchone()[0]
        rows = conn.execute(
            f'SELECT * FROM commitments {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?',
            params + [limit, offset]
        ).fetchall()
        conn.close()
        self._json({'records': [dict(r) for r in rows], 'total': total, 'page': page})

    def handle_commitments_export(self, qs=None):
        """Export commitments as CSV."""
        COMMIT_DB = os.path.expanduser('~/.hermes/scripts/commitments.db')
        if not os.path.exists(COMMIT_DB):
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', 'attachment; filename="commitments.csv"')
            self.end_headers()
            self.wfile.write(b'No data yet')
            return
        conn = sqlite3.connect(COMMIT_DB)
        rows = conn.execute('SELECT * FROM commitments ORDER BY id DESC').fetchall()
        conn.close()
        import io, csv
        output = io.StringIO()
        keys = ['id','first','last','email','phone','address','postal','volunteer','sign','created_at']
        writer = csv.writer(output)
        writer.writerow(keys)
        for r in rows:
            writer.writerow([str(r[k]) if r[k] is not None else '' for k in keys])
        csv_data = output.getvalue().encode('utf-8')
        from datetime import datetime as dt
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="commitments_{dt.now().strftime("%Y-%m-%d")}.csv"')
        self.send_header('Content-Length', str(len(csv_data)))
        self.end_headers()
        self.wfile.write(csv_data)

    def handle_admin_changes(self, qs=None):
        """Return today's changes paginated (10 per page). Supports search by name."""
        page = max(1, int(qs.get('page', ['1'])[0]))
        per_page = max(1, min(100, int(qs.get('per_page', ['10'])[0])))
        offset = (page - 1) * per_page
        search = (qs.get('search', [''])[0] if qs else '').strip()
        where = ["date(cl.changed_at) = date('now','localtime')"]
        params = []
        if search:
            where.append("(s.full_name LIKE ? OR s.first_name LIKE ? OR s.last_name LIKE ? OR s.street LIKE ? OR s.phone LIKE ? OR s.postal_code LIKE ?)")
            like = f'%{search}%'
            params.extend([like, like, like, like, like, like])
        where_sql = ' AND '.join(where)
        conn = get_db()
        total = conn.execute(f"SELECT COUNT(*) FROM change_log cl JOIN supporters s ON cl.supporter_id = s.id WHERE {where_sql}", params).fetchone()[0]
        rows = conn.execute(f'''
            SELECT cl.supporter_id, s.full_name, s.street_number || ' ' || s.street as address,
                   GROUP_CONCAT(cl.field_name || ': ' || COALESCE(cl.old_value,'') || ' → ' || COALESCE(cl.new_value,''), '; ') as changes_summary,
                   MAX(cl.changed_at) as changed_at,
                   MAX(cl.user_id) as user_id,
                   MAX(cl.changed_by) as changed_by,
                   COUNT(*) as field_count
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
            WHERE {where_sql}
            GROUP BY cl.supporter_id, strftime('%Y-%m-%d %H:%M', cl.changed_at), cl.user_id
            ORDER BY changed_at DESC
            LIMIT ? OFFSET ?
        ''', params + [per_page, offset]).fetchall()
        conn.close()
        self._json({
            'changes': dict_rows(rows),
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (total + per_page - 1) // per_page)
        })

    def handle_admin_changes_archive(self, qs=None):
        """Return all previous days' changes paginated. Supports search by name + date range."""
        page = max(1, int(qs.get('page', ['1'])[0]))
        per_page = max(1, min(100, int(qs.get('per_page', ['10'])[0])))
        offset = (page - 1) * per_page
        search = (qs.get('search', [''])[0] if qs else '').strip()
        date_from = (qs.get('date_from', [''])[0] if qs else '').strip()
        date_to = (qs.get('date_to', [''])[0] if qs else '').strip()
        where = ["date(cl.changed_at) < date('now','localtime')"]
        params = []
        if search:
            where.append("(s.full_name LIKE ? OR s.first_name LIKE ? OR s.last_name LIKE ? OR s.street LIKE ? OR s.phone LIKE ? OR s.postal_code LIKE ?)")
            like = f'%{search}%'
            params.extend([like, like, like, like, like, like])
        if date_from:
            where.append("date(cl.changed_at) >= ?"); params.append(date_from)
        if date_to:
            where.append("date(cl.changed_at) <= ?"); params.append(date_to)
        where_sql = ' AND '.join(where)
        conn = get_db()
        total = conn.execute(f"SELECT COUNT(*) FROM change_log cl JOIN supporters s ON cl.supporter_id = s.id WHERE {where_sql}", params).fetchone()[0]
        rows = conn.execute(f'''
            SELECT cl.supporter_id, s.full_name, s.street_number || ' ' || s.street as address,
                   GROUP_CONCAT(cl.field_name || ': ' || COALESCE(cl.old_value,'') || ' → ' || COALESCE(cl.new_value,''), '; ') as changes_summary,
                   MAX(cl.changed_at) as changed_at,
                   MAX(cl.user_id) as user_id,
                   MAX(cl.changed_by) as changed_by,
                   COUNT(*) as field_count
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
            WHERE {where_sql}
            GROUP BY cl.supporter_id, strftime('%Y-%m-%d %H:%M', cl.changed_at), cl.user_id
            ORDER BY changed_at DESC
            LIMIT ? OFFSET ?
        ''', params + [per_page, offset]).fetchall()
        conn.close()
        self._json({
            'changes': dict_rows(rows),
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': max(1, (total + per_page - 1) // per_page)
        })

    def handle_admin_team(self):
        """Team dashboard: breakdown by category."""
        conn = get_db()
        # Overall counts
        total = conn.execute('SELECT COUNT(*) FROM supporters').fetchone()[0]
        supporters = conn.execute("SELECT COUNT(*) FROM supporters WHERE support_level='Supporter'").fetchone()[0]
        surveys_completed = conn.execute("SELECT COUNT(DISTINCT supporter_id) FROM change_log WHERE field_name='notes' AND new_value LIKE '%Survey%'").fetchone()[0]
        signs_completed = conn.execute("SELECT COUNT(*) FROM supporters WHERE sign_request='Requested'").fetchone()[0]
        signs_pending = conn.execute("SELECT COUNT(*) FROM supporters WHERE sign_request='Declined'").fetchone()[0]
        # Records touched today
        touched_today = conn.execute("SELECT COUNT(*) FROM supporters WHERE date(updated_at)=date('now','localtime')").fetchone()[0]
        # By-user breakdown (last 30 days) — uses changed_by (stored at write time, survives deletion)
        user_activity = conn.execute('''
            SELECT COALESCE(cl.changed_by, u.username, 'User #' || cl.user_id) as username,
                   COALESCE(cl.changed_by, u.display_name, 'Deleted User') as display_name,
                   COUNT(cl.id) as changes
            FROM change_log cl
            LEFT JOIN users u ON cl.user_id = u.id
            WHERE cl.changed_at > datetime('now', '-30 days', 'localtime')
            GROUP BY cl.changed_by, cl.user_id
            ORDER BY changes DESC
        ''').fetchall()
        # Support level breakdown
        levels = conn.execute('''
            SELECT support_level, COUNT(*) as cnt
            FROM supporters
            WHERE support_level IS NOT NULL AND support_level != ''
            GROUP BY support_level ORDER BY cnt DESC
        ''').fetchall()
        conn.close()
        self._json({
            'total': total,
            'supporters': supporters,
            'surveys_completed': surveys_completed,
            'signs_completed': signs_completed,
            'signs_pending': signs_pending,
            'touched_today': touched_today,
            'user_activity': dict_rows(user_activity),
            'levels': dict_rows(levels)
        })

    def handle_admin_team_export(self):
        """Export team dashboard data as CSV."""
        conn = get_db()
        total = conn.execute('SELECT COUNT(*) FROM supporters').fetchone()[0]
        supporters = conn.execute("SELECT COUNT(*) FROM supporters WHERE support_level='Supporter'").fetchone()[0]
        surveys_completed = conn.execute("SELECT COUNT(DISTINCT supporter_id) FROM change_log WHERE field_name='notes' AND new_value LIKE '%Survey%'").fetchone()[0]
        signs_completed = conn.execute("SELECT COUNT(*) FROM supporters WHERE sign_request='Requested'").fetchone()[0]
        signs_pending = conn.execute("SELECT COUNT(*) FROM supporters WHERE sign_request='Declined'").fetchone()[0]
        touched_today = conn.execute("SELECT COUNT(*) FROM supporters WHERE date(updated_at)=date('now','localtime')").fetchone()[0]

        levels = conn.execute('''
            SELECT support_level, COUNT(*) as cnt
            FROM supporters
            WHERE support_level IS NOT NULL AND support_level != ''
            GROUP BY support_level ORDER BY cnt DESC
        ''').fetchall()

        user_activity = conn.execute('''
            SELECT COALESCE(cl.changed_by, u.username, 'User #' || cl.user_id) as username,
                   COALESCE(cl.changed_by, u.display_name, 'Deleted User') as display_name,
                   COUNT(cl.id) as changes
            FROM change_log cl
            LEFT JOIN users u ON cl.user_id = u.id
            WHERE cl.changed_at > datetime('now', '-30 days', 'localtime')
            GROUP BY cl.changed_by, cl.user_id
            ORDER BY changes DESC
        ''').fetchall()
        conn.close()

        import io
        from datetime import datetime as dt
        output = io.StringIO()
        writer = csv.writer(output)

        # Summary section
        writer.writerow(['WARD 25 TEAM DASHBOARD', dt.now().strftime('%Y-%m-%d %H:%M')])
        writer.writerow([])
        writer.writerow(['METRIC', 'COUNT'])
        writer.writerow(['Total Records', total])
        writer.writerow(['Supporters', supporters])
        writer.writerow(['Surveys Completed', surveys_completed])
        writer.writerow(['Signs Requested', signs_completed])
        writer.writerow(['Signs Declined', signs_pending])
        writer.writerow(['Touched Today', touched_today])
        writer.writerow([])
        writer.writerow(['SUPPORT LEVEL', 'COUNT', 'PERCENTAGE'])
        for lvl in levels:
            pct = f"{(lvl['cnt']/total*100):.1f}%" if total > 0 else '0%'
            writer.writerow([lvl['support_level'] or 'Unknown', lvl['cnt'], pct])
        writer.writerow([])
        writer.writerow(['USER', 'DISPLAY NAME', 'CHANGES (30d)'])
        for ua in user_activity:
            writer.writerow([ua['username'], ua['display_name'], ua['changes']])

        csv_data = output.getvalue().encode('utf-8')
        filename = f'ward25_team_dashboard_{dt.now().strftime("%Y-%m-%d")}.csv'

        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
        self.send_header('Content-Length', len(csv_data))
        self.end_headers()
        self.wfile.write(csv_data)

    # ── Canvasser Stats ───────────────────────────────────────

    def handle_canvasser_stats(self, qs):
        """Return per-canvasser stats: daily (static) + cumulative totals.
        Supports optional ?start=YYYY-MM-DD&end=YYYY-MM-DD for custom date range."""
        conn = get_db()

        # Determine date range
        today = datetime.now().strftime('%Y-%m-%d')
        start_date = qs.get('start', [today])[0]
        end_date = qs.get('end', [today])[0]

        # Get all users
        users = conn.execute('SELECT id, username, display_name, role FROM users ORDER BY username').fetchall()

        results = []
        for u in users:
            uid = u['id']
            name = u['display_name'] or u['username']

            # Daily stats (today only, static)
            daily_changes = conn.execute(
                "SELECT COUNT(*) FROM change_log WHERE user_id=? AND date(changed_at)=date('now','localtime')",
                (uid,)).fetchone()[0]
            daily_supporters = conn.execute(
                "SELECT COUNT(*) FROM change_log WHERE user_id=? AND date(changed_at)=date('now','localtime') AND field_name='support_level' AND new_value='Supporter'",
                (uid,)).fetchone()[0]
            daily_signs = conn.execute(
                "SELECT COUNT(*) FROM change_log WHERE user_id=? AND date(changed_at)=date('now','localtime') AND field_name='sign_request' AND new_value='Requested'",
                (uid,)).fetchone()[0]
            daily_surveys = conn.execute(
                "SELECT COUNT(*) FROM change_log WHERE user_id=? AND date(changed_at)=date('now','localtime') AND field_name='notes' AND new_value LIKE '%Survey%'",
                (uid,)).fetchone()[0]

            # Total stats (all time, cumulative)
            total_changes = conn.execute(
                "SELECT COUNT(*) FROM change_log WHERE user_id=?", (uid,)).fetchone()[0]
            total_supporters = conn.execute(
                "SELECT COUNT(*) FROM change_log WHERE user_id=? AND field_name='support_level' AND new_value='Supporter'",
                (uid,)).fetchone()[0]
            total_signs = conn.execute(
                "SELECT COUNT(*) FROM change_log WHERE user_id=? AND field_name='sign_request' AND new_value='Requested'",
                (uid,)).fetchone()[0]
            total_surveys = conn.execute(
                "SELECT COUNT(*) FROM change_log WHERE user_id=? AND field_name='notes' AND new_value LIKE '%Survey%'",
                (uid,)).fetchone()[0]

            # Custom date range stats (if start != today or end != today)
            range_changes = 0
            range_supporters = 0
            range_signs = 0
            range_surveys = 0
            if start_date != today or end_date != today:
                range_changes = conn.execute(
                    "SELECT COUNT(*) FROM change_log WHERE user_id=? AND date(changed_at)>=? AND date(changed_at)<=?",
                    (uid, start_date, end_date)).fetchone()[0]
                range_supporters = conn.execute(
                    "SELECT COUNT(*) FROM change_log WHERE user_id=? AND date(changed_at)>=? AND date(changed_at)<=? AND field_name='support_level' AND new_value='Supporter'",
                    (uid, start_date, end_date)).fetchone()[0]
                range_signs = conn.execute(
                    "SELECT COUNT(*) FROM change_log WHERE user_id=? AND date(changed_at)>=? AND date(changed_at)<=? AND field_name='sign_request' AND new_value='Requested'",
                    (uid, start_date, end_date)).fetchone()[0]
                range_surveys = conn.execute(
                    "SELECT COUNT(*) FROM change_log WHERE user_id=? AND date(changed_at)>=? AND date(changed_at)<=? AND field_name='notes' AND new_value LIKE '%Survey%'",
                    (uid, start_date, end_date)).fetchone()[0]

            results.append({
                'user_id': uid,
                'username': u['username'],
                'display_name': name,
                'role': u['role'],
                'daily': {
                    'changes': daily_changes,
                    'supporters': daily_supporters,
                    'signs_requested': daily_signs,
                    'surveys': daily_surveys,
                },
                'total': {
                    'changes': total_changes,
                    'supporters': total_supporters,
                    'signs_requested': total_signs,
                    'surveys': total_surveys,
                },
                'range': {
                    'changes': range_changes,
                    'supporters': range_supporters,
                    'signs_requested': range_signs,
                    'surveys': range_surveys,
                }
            })

        conn.close()
        self._json({
            'users': results,
            'date_range': {'start': start_date, 'end': end_date},
            'today': today,
        })

    # ── Existing endpoints ───────────────────────────────────

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode('utf-8')
        ctype = self.headers.get('Content-Type', '')

        try:
            if 'application/json' in ctype:
                return json.loads(raw)
            elif 'application/x-www-form-urlencoded' in ctype:
                parsed = parse_qs(raw)
                return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
            else:
                return json.loads(raw)
        except (json.JSONDecodeError, Exception):
            return {}

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Quieter logs
        if '/api/' in str(args[0]):
            print(f'[{datetime.now().strftime("%H:%M:%S")}] {args[0]}')
        else:
            pass  # Suppress static file logs


    def handle_commit_to_vote(self, data):
        """Save commit-to-vote form submission (public endpoint)."""
        first    = str(data.get('first', '')).strip()
        last     = str(data.get('last', '')).strip()
        email    = str(data.get('email', '')).strip()
        phone    = str(data.get('phone', '')).strip()
        address  = str(data.get('address', '')).strip()
        postal   = str(data.get('postal', '')).strip()
        volunteer= bool(data.get('volunteer', False))
        sign     = bool(data.get('sign', False))
        top_issue = str(data.get('top_issue', '')).strip()
        registration_status = str(data.get('registration_status', '')).strip()
        email_consent = bool(data.get('email_consent', False))
        sms_consent = bool(data.get('sms_consent', False))
        pledge = bool(data.get('pledge', False))
        town_hall = bool(data.get('town_hall', False))
        source = str(data.get('source', 'electshawnallen')).strip()[:80]

        if not first or not last or not email:
            return self._json({'ok': False, 'error': 'First name, last name, and email are required.'}, 400)

        conn = get_db()
        conn.execute('''CREATE TABLE IF NOT EXISTS commit_to_vote (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT, last_name TEXT, email TEXT, phone TEXT,
            address TEXT, postal TEXT, volunteer INTEGER DEFAULT 0,
            lawn_sign INTEGER DEFAULT 0, top_issue TEXT,
            registration_status TEXT, email_consent INTEGER DEFAULT 0,
            sms_consent INTEGER DEFAULT 0, pledge INTEGER DEFAULT 0,
            town_hall INTEGER DEFAULT 0,
            source TEXT DEFAULT 'electshawnallen',
            submitted_at TEXT DEFAULT (datetime('now'))
        )''')
        for column, definition in (
            ('top_issue', 'TEXT'),
            ('registration_status', 'TEXT'),
            ('email_consent', 'INTEGER DEFAULT 0'),
            ('sms_consent', 'INTEGER DEFAULT 0'),
            ('pledge', 'INTEGER DEFAULT 0'),
            ('town_hall', 'INTEGER DEFAULT 0'),
            ('source', "TEXT DEFAULT 'electshawnallen'"),
        ):
            try:
                conn.execute(f'ALTER TABLE commit_to_vote ADD COLUMN {column} {definition}')
            except sqlite3.OperationalError:
                pass
        conn.execute('''INSERT INTO commit_to_vote
            (first_name, last_name, email, phone, address, postal, volunteer, lawn_sign,
             top_issue, registration_status, email_consent, sms_consent, pledge, town_hall, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (first, last, email, phone, address, postal, int(volunteer), int(sign),
             top_issue, registration_status, int(email_consent), int(sms_consent), int(pledge),
             int(town_hall), source))
        conn.commit()
        conn.close()

        # Send email notification
        self._send_commit_email(first, last, email, phone, address, postal, volunteer, sign,
                                top_issue, registration_status, email_consent, sms_consent,
                                pledge, town_hall, source)
        self._json({'ok': True, 'message': f'Thank you, {first}. Your commitment has been recorded.'})

    def handle_petition_count(self):
        """Return the public petition total: launch count plus verified web signatures."""
        launch_count = 9729
        goal = 20000
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS total FROM commit_to_vote WHERE source = ?",
                ('keeptaxesdown-petition',)
            ).fetchone()
            online_signatures = int(row['total'] if row else 0)
        except sqlite3.OperationalError:
            online_signatures = 0
        finally:
            conn.close()
        self._json({
            'ok': True,
            'count': launch_count + online_signatures,
            'goal': goal,
            'remaining': max(0, goal - launch_count - online_signatures)
        })

    def handle_sms_outbox(self, qs):
        """Return SMS outbox rows for the admin tab, joined with supporter name/address."""
        limit = min(int(qs.get('limit', [200])[0]), 1000)
        offset = int(qs.get('offset', [0])[0])
        conn = get_db()
        try:
            total = conn.execute("SELECT COUNT(*) FROM sms_outbox").fetchone()[0]
            rows = conn.execute(
                """SELECT o.*, s.full_name AS supporter_name,
                          COALESCE(s.street_number || ' ' || s.street, '') AS supporter_address,
                          s.poll
                   FROM sms_outbox o
                   LEFT JOIN supporters s ON o.supporter_id = s.id
                   ORDER BY o.sent_at DESC LIMIT ? OFFSET ?""",
                (limit, offset)
            ).fetchall()
            self._json({'ok': True, 'total': total, 'rows': [dict(r) for r in rows]})
        except sqlite3.OperationalError as e:
            self._json({'ok': False, 'error': str(e)}, 500)
        finally:
            conn.close()

    def handle_twilio_sms_status(self, body=None):
        """Receive Twilio SMS delivery status callbacks (POST with form-encoded fields).
        Updates sms_outbox status."""
        # body can be a dict (JSON-parsed by do_POST), a query-string dict from do_GET,
        # or a bytes/form string
        if isinstance(body, dict):
            # Could be from do_POST's _read_body (flat dict) or do_GET's parse_qs (list dict)
            sid = body.get('MessageSid', '')
            status = body.get('MessageStatus', '')
            error_code = body.get('ErrorCode', '')
            error_msg = body.get('ErrorMessage', '')
            # If values are lists (from parse_qs), take first element
            if isinstance(sid, list): sid = sid[0] if sid else ''
            if isinstance(status, list): status = status[0] if status else ''
            if isinstance(error_code, list): error_code = error_code[0] if error_code else ''
            if isinstance(error_msg, list): error_msg = error_msg[0] if error_msg else ''
            sid = sid.strip()
            status = status.strip()
            error_code = error_code.strip()
            error_msg = error_msg.strip()
        elif isinstance(body, bytes):
            params = parse_qs(body.decode('latin-1', errors='replace'))
            sid = (params.get('MessageSid', [''])[0] or '').strip()
            status = (params.get('MessageStatus', [''])[0] or '').strip()
            error_code = (params.get('ErrorCode', [''])[0] or '').strip()
            error_msg = (params.get('ErrorMessage', [''])[0] or '').strip()
        else:
            self._json({'ok': False, 'error': 'No body'}, 400)
            return

        if not sid or not status:
            self._json({'ok': False, 'error': 'Missing MessageSid or MessageStatus'}, 400)
            return

        conn = get_db()
        try:
            conn.execute(
                "UPDATE sms_outbox SET status=?, error_msg=CASE WHEN ? != '' THEN ? ELSE error_msg END "
                "WHERE twilio_sid=?",
                (status, error_code, error_code + ': ' + error_msg, sid)
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            pass
        finally:
            conn.close()

        self._json({'ok': True})

    def handle_volunteer_signup(self, data):
        """Save volunteer signup form submission (public endpoint)."""
        # Accept both the simple API shape ({name, roles: [], availability: "..."})
        # and the live electshawnallen.ca volunteer form shape
        # ({first, last, roles: {canvass: true, ...}, availability: {weekdayEve: true, ...}}).
        first = str(data.get('first', '')).strip()
        last = str(data.get('last', '')).strip()
        name = str(data.get('name', '')).strip() or f'{first} {last}'.strip()
        email = str(data.get('email', '')).strip()
        phone = str(data.get('phone', '')).strip()

        roles_raw = data.get('roles', [])
        if isinstance(roles_raw, dict):
            role_labels = {
                'canvass': 'Door-to-door canvassing',
                'phoneBank': 'Phone banking',
                'signs': 'Sign install / repair',
                'lit': 'Literature drops',
                'digital': 'Data / digital / social',
                'gotv': 'Election day (GOTV)',
                'events': 'Events & community presence',
                'driver': 'Drive voters / supplies',
            }
            roles = [role_labels.get(k, k) for k, v in roles_raw.items() if v]
        else:
            roles = roles_raw if isinstance(roles_raw, list) else [str(roles_raw)] if roles_raw else []

        avail_raw = data.get('availability', '')
        if isinstance(avail_raw, dict):
            avail_labels = {
                'weekdayEve': 'Weekday evenings',
                'weekendAm': 'Weekend mornings',
                'weekendPm': 'Weekend afternoons',
                'eDay': 'Election day only (Oct 26)',
            }
            avail = ', '.join(str(avail_labels.get(str(k), str(k))) for k, v in avail_raw.items() if v)
        else:
            avail = str(avail_raw).strip()

        notes_parts = []
        for label, key in (
            ('Address', 'address'),
            ('Neighbourhood', 'neighbourhood'),
            ('Postal', 'postal'),
            ('Languages', 'languages'),
        ):
            value = str(data.get(key, '')).strip()
            if value:
                notes_parts.append(f'{label}: {value}')
        user_notes = str(data.get('notes', '')).strip()
        if user_notes:
            notes_parts.append(f'Notes: {user_notes}')
        notes = ' | '.join(notes_parts)

        if not name or not email:
            return self._json({'ok': False, 'error': 'Name and email are required.'}, 400)

        conn = get_db()
        conn.execute('''CREATE TABLE IF NOT EXISTS volunteer_signups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, email TEXT, phone TEXT,
            roles TEXT, availability TEXT, notes TEXT,
            submitted_at TEXT DEFAULT (datetime('now'))
        )''')
        conn.execute('''INSERT INTO volunteer_signups (name, email, phone, roles, availability, notes)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (name, email, phone, json.dumps(roles) if isinstance(roles, list) else str(roles), avail, notes))
        conn.commit()
        conn.close()

        # Send email notification
        self._send_volunteer_email(name, email, phone, roles, avail, notes)

        greeting = name.split()[0] if name else 'friend'
        self._json({'ok': True, 'message': f'Thanks, {greeting}. A campaign organizer will follow up within 48 hours.'})

    def _send_commit_email(self, first, last, email, phone, address, postal, volunteer, sign,
                           top_issue='', registration_status='', email_consent=False,
                           sms_consent=False, pledge=False, town_hall=False,
                           source='electshawnallen'):
        """Email commit-to-vote form to info@electshawnallen.ca via AgentMail."""
        try:
            body = '📋 NEW COMMIT-TO-VOTE SUBMISSION\n\n'
            body += f'Name: {first} {last}\n'
            body += f'Email: {email}\n'
            body += f'Phone: {phone or "Not provided"}\n'
            body += f'Address: {address or "Not provided"}\n'
            body += f'Postal: {postal or "Not provided"}\n'
            body += f'Volunteer: {"Yes" if volunteer else "No"}\n'
            body += f'Lawn Sign: {"Yes" if sign else "No"}\n'
            body += f'Top Pocketbook Issue: {top_issue or "Not provided"}\n'
            body += f'Registration Status: {registration_status or "Not provided"}\n'
            body += f'Pledge to Vote: {"Yes" if pledge else "No"}\n'
            body += f'Pocketbook Town Hall: {"Registered" if town_hall else "No"}\n'
            body += f'Email Consent: {"Yes" if email_consent else "No"}\n'
            body += f'SMS Consent: {"Yes" if sms_consent else "No"}\n'
            body += f'Source: {source}\n'
            self._agentmail_send('info@electshawnallen.ca',
                f'🗳️ {first} {last} — Committed to Vote (Ward 25)', body)
            confirmation = (
                f'Hi {first},\n\n'
                'Thank you — your commitment to vote for Shawn Allen has been recorded.\n\n'
                'We will send voting location details, advance-poll dates, and reminders closer to election day.\n\n'
                '— Shawn Allen Campaign\n'
                'info@electshawnallen.ca\n'
                '647-999-8929'
            )
            self._agentmail_send(email,
                'Shawn Allen campaign — your commitment was recorded', confirmation)
        except Exception as e:
            print(f'[Commit Email] Failed: {e}')

    def _send_volunteer_email(self, name, email, phone, roles, avail, notes):
        """Email volunteer signup to info@electshawnallen.ca via AgentMail."""
        try:
            roles_str = ', '.join(roles) if isinstance(roles, list) else str(roles)
            body = '🙋 NEW VOLUNTEER SIGNUP\n\n'
            body += f'Name: {name}\n'
            body += f'Email: {email}\n'
            body += f'Phone: {phone or "Not provided"}\n'
            body += f'Roles: {roles_str}\n'
            body += f'Availability: {avail or "Not provided"}\n'
            body += f'Notes: {notes or "None"}\n'
            self._agentmail_send('info@electshawnallen.ca',
                f'🙋 {name} — Volunteer Signup (Ward 25)', body)

            first = name.split()[0] if name else 'there'
            confirmation = (
                f'Hi {first},\n\n'
                'Thank you for signing up to volunteer with Shawn Allen for City Councillor in Ward 25, Scarborough–Rouge Park.\n\n'
                'A campaign organizer will follow up within 48 hours to match you with the best role and schedule.\n\n'
                f'Roles selected: {roles_str or "Not specified"}\n'
                f'Availability: {avail or "Not provided"}\n\n'
                'If you need to update anything, just reply to this email or contact us at 647-999-8929.\n\n'
                'Thank you for joining the team.\n\n'
                'Shawn Allen Campaign\n'
                'info@electshawnallen.ca\n'
                'electshawnallen.ca'
            )
            self._agentmail_send(email,
                'Thank you for joining Team Shawn Allen', confirmation)
        except Exception as e:
            print(f'[Volunteer Email] Failed: {e}')

    def _agentmail_send(self, to, subject, text):
        """Send an email from info@electshawnallen.ca via Microsoft Graph."""
        script = '/root/.hermes/scripts/send-as-info.py'
        result = subprocess.run(
            ['python3', script, to, subject, text],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise Exception((result.stderr or result.stdout or 'Graph send failed').strip())

if __name__ == '__main__':
    import signal
    signal.signal(signal.SIGINT, lambda s, f: os._exit(0))

    # Kill any existing process on port
    os.system(f'fuser -k {PORT}/tcp 2>/dev/null; sleep 1')

    print(f'🚀 Supporter DB Server on http://localhost:{PORT}')
    print(f'   Database: {DB_PATH}')
    print(f'   Records: {sqlite3.connect(DB_PATH).execute("SELECT COUNT(*) FROM supporters").fetchone()[0]}')
    print(f'   Press Ctrl+C to stop')

    server = ThreadingHTTPServer(('', PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.server_close()
