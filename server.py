#!/usr/bin/env python3
"""Supporter Database Server — Ward 25 Campaign
Serves HTML frontend + REST API for supporter lookup, editing, and change tracking.
"""
import os, json, sqlite3, time, re, csv, hashlib, secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote_plus
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'supporters.db')
WWW_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = 8777

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=5000')
    return conn

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

        # API: Admin team dashboard
        if path == '/api/admin/team':
            self.handle_admin_team()
            return

        # API: Admin team dashboard export (CSV)
        if path == '/api/admin/team/export':
            self.handle_admin_team_export()
            return

        # Admin dashboard page
        if path == '/admin':
            self._serve_file('/admin.html')
            return

        # API: Search
        if path == '/api/search':
            self.handle_search(qs)
            return

        # API: Search export as CSV
        if path == '/api/search/export':
            self.handle_search_export(qs)
            return

        # API: Get single supporter
        if path.startswith('/api/supporter/'):
            try:
                sid = int(path.split('/')[-2] if path.endswith('/history') else path.split('/')[-1])
            except (ValueError, IndexError):
                self._json({'error': 'Invalid ID'}, 400)
                return

            if path.endswith('/history'):
                self.handle_history(sid)
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

        # Auth: Logout
        if path == '/api/auth/logout':
            self.handle_logout()
            return

        # Survey: Save response
        if path == '/api/survey':
            self.handle_survey_save(body)
            return

        # Admin: Create user (admin only)
        if path == '/api/admin/users':
            if require_admin(self):
                self.handle_admin_create_user(body)
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

        # If filters provided but no search query, allow listing by filter
        if not query or len(query) < 2:
            if not support_level and not sign_request:
                self._json({'results': [], 'total': 0, 'message': 'Enter 2+ characters to search'})
                return

        conn = get_db()
        # Base WHERE clauses
        where_parts = []
        params = []

        if query and len(query) >= 2:
            like = f'%{query}%'
            query_nospace = query.replace(' ', '')
            like_nospace = f'%{query_nospace}%'
            where_parts.append('''(
                REPLACE(street, ' ', '') LIKE ? OR full_name LIKE ? OR phone LIKE ?
                OR REPLACE(street_number || street, ' ', '') LIKE ?
                OR postal_code LIKE ?
                OR sign_request LIKE ?
                OR support_level LIKE ?
            )''')
            params.extend([like_nospace, like, like, like_nospace, like, like, like])
            order_params = [like_nospace, like, like]
        else:
            order_params = []

        if support_level:
            where_parts.append('support_level = ?')
            params.append(support_level)

        if sign_request:
            where_parts.append('sign_request = ?')
            params.append(sign_request)

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
                street, street_number'''
        else:
            order_clause = 'ORDER BY street, street_number'

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
            'sign_request': sign_request
        })

    def handle_search_export(self, qs):
        """Export current search results as CSV."""
        query = qs.get('q', [''])[0].strip()
        support_level = qs.get('support_level', [''])[0].strip()
        sign_request = qs.get('sign_request', [''])[0].strip()

        # Require at least a filter or search term
        if (not query or len(query) < 2) and not support_level and not sign_request:
            self._json({'error': 'Enter a search query or filter to export'}, 400)
            return

        conn = get_db()
        where_parts = []
        params = []

        if query and len(query) >= 2:
            like = f'%{query}%'
            query_nospace = query.replace(' ', '')
            like_nospace = f'%{query_nospace}%'
            where_parts.append('''(
                REPLACE(street, ' ', '') LIKE ? OR full_name LIKE ? OR phone LIKE ?
                OR REPLACE(street_number || street, ' ', '') LIKE ?
                OR postal_code LIKE ?
                OR sign_request LIKE ?
                OR support_level LIKE ?
            )''')
            params.extend([like_nospace, like, like, like_nospace, like, like, like])
            order_params = [like_nospace, like, like]
        else:
            order_params = []

        if support_level:
            where_parts.append('support_level = ?')
            params.append(support_level)

        if sign_request:
            where_parts.append('sign_request = ?')
            params.append(sign_request)

        where_clause = ' AND '.join(where_parts) if where_parts else '1=1'

        if order_params:
            order_clause = '''ORDER BY
                CASE
                    WHEN REPLACE(street_number || street, ' ', '') LIKE ? THEN 1
                    WHEN full_name LIKE ? THEN 2
                    WHEN phone LIKE ? THEN 3
                    ELSE 4
                END,
                street, street_number'''
        else:
            order_clause = 'ORDER BY street, street_number'

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

    def handle_update(self, sid, body):
        allowed_fields = {
            'full_name', 'first_name', 'last_name', 'phone', 'email',
            'street_number', 'street', 'apartment', 'city', 'postal_code',
            'support_level', 'notes', 'sign_request', 'candidate_conversation_request'
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

        for field, new_val in body.items():
            if field not in allowed_fields:
                continue
            old_val = str(old[field] or '')
            new_val_str = str(new_val or '')
            if old_val != new_val_str:
                updates[field] = new_val
                conn.execute(
                    'INSERT INTO change_log (supporter_id, field_name, old_value, new_value, user_id, changed_by) VALUES (?,?,?,?,?,?)',
                    (sid, field, old_val, new_val_str, user_id, username)
                )
                changes_logged.append({
                    'field': field,
                    'old': old_val,
                    'new': new_val_str,
                    'changed_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
                    'by': username
                })

        if updates:
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
                  'apartment', 'sign_request', 'candidate_conversation_request']
        values = {f: body.get(f, '') for f in fields}
        values['created_at'] = datetime.now().strftime('%Y-%m-%d %H:%M')

        cols = ', '.join(values.keys())
        placeholders = ', '.join('?' * len(values))
        conn.execute(f'INSERT INTO supporters ({cols}) VALUES ({placeholders})', list(values.values()))
        conn.commit()
        new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        row = conn.execute('SELECT * FROM supporters WHERE id = ?', (new_id,)).fetchone()
        conn.close()
        self._json({'success': True, 'supporter': dict_row(row)}, 201)

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

        # Signs marked (completed)
        signs_completed = conn.execute('''
            SELECT COUNT(*) FROM change_log
            WHERE user_id = ? AND field_name = 'sign_request' AND new_value = 'Completed'
        ''', (uid,)).fetchone()[0]

        conn.close()

        self._json({
            'today_changes': today_changes,
            'week_changes': week_changes,
            'touched_today': touched_today,
            'surveys_today': surveys_today,
            'total_surveys': total_surveys,
            'supporters_marked': supporters_marked,
            'signs_completed': signs_completed,
            'display_name': self.current_user.get('display_name', '')
        })

    def handle_recent_changes(self, qs):
        limit = min(int(qs.get('limit', [20])[0]), 100)
        conn = get_db()
        rows = conn.execute('''
            SELECT cl.*, s.full_name, s.street_number || ' ' || s.street as address
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
            ORDER BY cl.changed_at DESC
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
        self.send_header('Cache-Control', 'no-cache')
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

    def handle_login(self, body):
        username = body.get('username', '').strip().lower()
        password = body.get('password', '')
        if not username or not password:
            self._json({'error': 'Username and password required'}, 400)
            return
        conn = get_db()
        row = conn.execute('SELECT * FROM users WHERE LOWER(username) = ?', (username,)).fetchone()
        conn.close()
        if not row or not verify_password(password, row['password_hash']):
            self._json({'error': 'Invalid credentials'}, 401)
            return
        token = create_session(row['id'])
        self._json({
            'token': token,
            'user': {'id': row['id'], 'username': row['username'], 'role': row['role'], 'display_name': row['display_name']}
        })

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
        users = conn.execute('SELECT id, username, role, display_name, created_at FROM users ORDER BY id').fetchall()
        conn.close()
        self._json({'users': dict_rows(users)})

    def handle_admin_create_user(self, body):
        username = body.get('username', '').strip()
        password = body.get('password', '')
        role = body.get('role', 'canvasser')
        display_name = body.get('display_name', username)
        if not username or not password:
            self._json({'error': 'Username and password required'}, 400)
            return
        if role not in ('admin', 'canvasser'):
            self._json({'error': 'Invalid role'}, 400)
            return
        try:
            conn = get_db()
            conn.execute('INSERT INTO users (username, password_hash, role, display_name) VALUES (?,?,?,?)',
                        (username, hash_password(password), role, display_name))
            conn.commit()
            new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
            conn.close()
            self._json({'success': True, 'user': {'id': new_id, 'username': username, 'role': role, 'display_name': display_name}}, 201)
        except sqlite3.IntegrityError:
            self._json({'error': 'Username already exists'}, 409)

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
        # Recent changes (last 20)
        recent = conn.execute('''
            SELECT cl.*, s.full_name, s.street_number || ' ' || s.street as address
            FROM change_log cl
            JOIN supporters s ON cl.supporter_id = s.id
            ORDER BY cl.changed_at DESC LIMIT 20
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

    def handle_admin_team(self):
        """Team dashboard: breakdown by category."""
        conn = get_db()
        # Overall counts
        total = conn.execute('SELECT COUNT(*) FROM supporters').fetchone()[0]
        supporters = conn.execute("SELECT COUNT(*) FROM supporters WHERE support_level='Supporter'").fetchone()[0]
        refused = conn.execute("SELECT COUNT(*) FROM supporters WHERE support_level='Survey Refused'").fetchone()[0]
        signs_completed = conn.execute("SELECT COUNT(*) FROM supporters WHERE sign_request='Completed'").fetchone()[0]
        signs_pending = conn.execute("SELECT COUNT(*) FROM supporters WHERE sign_request='Pending'").fetchone()[0]
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
            'refused': refused,
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
        refused = conn.execute("SELECT COUNT(*) FROM supporters WHERE support_level='Survey Refused'").fetchone()[0]
        signs_completed = conn.execute("SELECT COUNT(*) FROM supporters WHERE sign_request='Completed'").fetchone()[0]
        signs_pending = conn.execute("SELECT COUNT(*) FROM supporters WHERE sign_request='Pending'").fetchone()[0]
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
        writer.writerow(['Survey Refused', refused])
        writer.writerow(['Signs Completed', signs_completed])
        writer.writerow(['Signs Pending', signs_pending])
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


if __name__ == '__main__':
    import signal
    signal.signal(signal.SIGINT, lambda s, f: os._exit(0))

    # Kill any existing process on port
    os.system(f'fuser -k {PORT}/tcp 2>/dev/null; sleep 1')

    print(f'🚀 Supporter DB Server on http://localhost:{PORT}')
    print(f'   Database: {DB_PATH}')
    print(f'   Records: {sqlite3.connect(DB_PATH).execute("SELECT COUNT(*) FROM supporters").fetchone()[0]}')
    print(f'   Press Ctrl+C to stop')

    server = HTTPServer(('0.0.0.0', PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.server_close()
