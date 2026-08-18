import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

import server


class PasswordResetTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        self.old_db_path = server.DB_PATH
        server.DB_PATH = self.db_path
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'canvasser',
                display_name TEXT,
                status TEXT DEFAULT 'active'
            );
            CREATE TABLE sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL
            );
        ''')
        conn.execute(
            'INSERT INTO users (id, username, password_hash, email, display_name) VALUES (1,?,?,?,?,?)'.replace('?,?,?,?,?', '?,?,?,?'),
            ('Canvasser', server.hash_password('old-password'), 'person@example.com', 'Person')
        )
        conn.execute('INSERT INTO sessions (token, user_id) VALUES (?,?)', ('active-session', 1))
        conn.commit()
        conn.close()

    def tearDown(self):
        server.DB_PATH = self.old_db_path
        try:
            os.unlink(self.db_path)
        except FileNotFoundError:
            pass

    def connect(self):
        conn = server.get_db()
        conn.row_factory = sqlite3.Row
        return conn

    def test_reset_token_is_stored_as_hash_not_plaintext(self):
        conn = self.connect()
        token = server.create_password_reset(conn, 1, now=1_000, ttl_seconds=3_600)
        row = conn.execute('SELECT token_hash, expires_at, used_at FROM password_reset_tokens').fetchone()
        conn.close()

        self.assertTrue(token)
        self.assertNotEqual(row['token_hash'], token)
        self.assertEqual(row['token_hash'], hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(row['expires_at'], 4_600)
        self.assertIsNone(row['used_at'])

    def test_valid_token_changes_password_revokes_sessions_and_is_one_time(self):
        conn = self.connect()
        token = server.create_password_reset(conn, 1, now=2_000)
        user_id = server.consume_password_reset(conn, token, 'new-secure-password', now=2_100)
        row = conn.execute('SELECT password_hash FROM users WHERE id=1').fetchone()
        sessions = conn.execute('SELECT COUNT(*) FROM sessions WHERE user_id=1').fetchone()[0]
        second_use = server.consume_password_reset(conn, token, 'another-password', now=2_200)
        conn.close()

        self.assertEqual(user_id, 1)
        self.assertTrue(server.verify_password('new-secure-password', row['password_hash']))
        self.assertEqual(sessions, 0)
        self.assertIsNone(second_use)

    def test_expired_token_is_rejected_without_changing_password(self):
        conn = self.connect()
        token = server.create_password_reset(conn, 1, now=3_000, ttl_seconds=60)
        result = server.consume_password_reset(conn, token, 'new-secure-password', now=3_061)
        row = conn.execute('SELECT password_hash FROM users WHERE id=1').fetchone()
        conn.close()

        self.assertIsNone(result)
        self.assertTrue(server.verify_password('old-password', row['password_hash']))

    def test_identifier_lookup_is_case_insensitive_for_username_or_email(self):
        conn = self.connect()
        by_username = server.find_password_reset_user(conn, 'CANVASSER')
        by_email = server.find_password_reset_user(conn, 'PERSON@EXAMPLE.COM')
        missing = server.find_password_reset_user(conn, 'missing@example.com')
        conn.close()

        self.assertEqual(by_username['id'], 1)
        self.assertEqual(by_email['id'], 1)
        self.assertIsNone(missing)

    def test_auth_schema_migration_persists_after_read_only_connection(self):
        conn = self.connect()
        conn.close()
        direct = sqlite3.connect(self.db_path)
        user_columns = {row[1] for row in direct.execute('PRAGMA table_info(users)')}
        tables = {row[0] for row in direct.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        direct.close()

        self.assertIn('email', user_columns)
        self.assertIn('password_reset_tokens', tables)

    def test_short_new_password_is_rejected(self):
        conn = self.connect()
        token = server.create_password_reset(conn, 1, now=4_000)
        with self.assertRaisesRegex(ValueError, 'at least 8'):
            server.consume_password_reset(conn, token, 'short', now=4_100)
        conn.close()

    def test_reset_emails_are_rate_limited_per_account(self):
        conn = self.connect()
        first = server.create_password_reset(conn, 1, now=5_000)
        throttled = server.create_password_reset(conn, 1, now=5_100)
        after_cooldown = server.create_password_reset(conn, 1, now=5_301)
        conn.close()

        self.assertTrue(first)
        self.assertIsNone(throttled)
        self.assertTrue(after_cooldown)

    def make_handler(self):
        handler = object.__new__(server.Handler)
        handler.responses = []
        handler.sent_emails = []
        handler._json = lambda payload, status=200: handler.responses.append((status, payload))
        handler._agentmail_send = lambda to, subject, text: handler.sent_emails.append((to, subject, text))
        return handler

    def test_reset_request_response_does_not_reveal_if_account_exists(self):
        existing = self.make_handler()
        existing.handle_password_reset_request({'identifier': 'person@example.com'})
        missing = self.make_handler()
        missing.handle_password_reset_request({'identifier': 'missing@example.com'})

        self.assertEqual(existing.responses, missing.responses)
        self.assertEqual(existing.responses[0][0], 200)
        self.assertEqual(len(existing.sent_emails), 1)
        self.assertEqual(existing.sent_emails[0][0], 'person@example.com')
        self.assertIn('reset_token=', existing.sent_emails[0][2])
        self.assertEqual(missing.sent_emails, [])

    def test_reset_confirmation_handler_rejects_invalid_token(self):
        handler = self.make_handler()
        handler.handle_password_reset_confirm({'token': 'invalid', 'password': 'new-secure-password'})

        self.assertEqual(handler.responses[0][0], 400)
        self.assertIn('invalid or expired', handler.responses[0][1]['error'].lower())

    def test_registration_requires_valid_email_for_future_resets(self):
        handler = self.make_handler()
        handler.handle_register({
            'username': 'NewUser',
            'display_name': 'New User',
            'password': 'secure-password'
        })

        self.assertEqual(handler.responses[0][0], 400)
        self.assertIn('email', handler.responses[0][1]['error'].lower())

    def test_registration_stores_reset_email(self):
        handler = self.make_handler()
        handler.handle_register({
            'username': 'EmailUser',
            'display_name': 'Email User',
            'email': 'email.user@example.com',
            'password': 'secure-password'
        })
        conn = self.connect()
        row = conn.execute("SELECT email FROM users WHERE username='EmailUser'").fetchone()
        conn.close()

        self.assertEqual(handler.responses[0][0], 201)
        self.assertEqual(row['email'], 'email.user@example.com')

    def test_admin_can_attach_a_reset_email_to_existing_user(self):
        handler = self.make_handler()
        handler.handle_admin_update_user_email(1, {'email': 'canvasser.new@example.com'})
        conn = self.connect()
        email = conn.execute('SELECT email FROM users WHERE id=1').fetchone()['email']
        conn.close()

        self.assertEqual(handler.responses[0][0], 200)
        self.assertEqual(email, 'canvasser.new@example.com')

    def test_pocketbook_commitment_fields_are_saved(self):
        handler = self.make_handler()
        sent = []
        handler._send_commit_email = lambda *args: sent.append(args)
        handler.handle_commit_to_vote({
            'first': 'Pocket',
            'last': 'Book',
            'email': 'pocket@example.com',
            'phone': '4165550100',
            'postal': 'M1C 2X1',
            'top_issue': 'Property taxes',
            'registration_status': 'Need to check',
            'email_consent': True,
            'sms_consent': False,
            'pledge': True,
            'town_hall': True,
            'source': 'keeptaxesdown-pocketbook'
        })
        conn = self.connect()
        row = conn.execute('SELECT * FROM commit_to_vote WHERE email=?', ('pocket@example.com',)).fetchone()
        conn.close()

        self.assertEqual(handler.responses[0][0], 200)
        self.assertEqual(row['top_issue'], 'Property taxes')
        self.assertEqual(row['registration_status'], 'Need to check')
        self.assertEqual(row['email_consent'], 1)
        self.assertEqual(row['pledge'], 1)
        self.assertEqual(row['town_hall'], 1)
        self.assertEqual(row['source'], 'keeptaxesdown-pocketbook')
        self.assertEqual(len(sent), 1)


class FrontendPasswordResetTests(unittest.TestCase):
    def test_login_page_contains_password_reset_forms_and_handlers(self):
        html = Path('index.html').read_text(encoding='utf-8')
        for marker in (
            'id="forgotForm"',
            'id="resetForm"',
            'showForgotPassword',
            'doPasswordResetRequest',
            'doPasswordResetConfirm',
            'reset_token'
        ):
            self.assertIn(marker, html)

    def test_registration_collects_email_for_future_resets(self):
        html = Path('index.html').read_text(encoding='utf-8')
        self.assertIn('id="regEmail"', html)
        self.assertIn('email:e', html)

    def test_admin_can_manage_password_recovery_emails(self):
        html = Path('admin.html').read_text(encoding='utf-8')
        self.assertIn('id="newUserEmail"', html)
        self.assertIn('saveUserEmail', html)


if __name__ == '__main__':
    unittest.main()
