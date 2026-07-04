#!/usr/bin/env python3
"""Daily survey report — finds all surveys completed today and generates a summary."""
import sqlite3, os, json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'supporters.db')

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    today = datetime.now().strftime('%Y-%m-%d')
    
    # Find supporters whose notes were updated today with "Survey completed"
    rows = conn.execute('''
        SELECT s.id, s.full_name, s.street_number || ' ' || s.street as address,
               s.phone, s.support_level, s.notes, s.updated_at
        FROM supporters s
        WHERE date(s.updated_at) = date('now','localtime')
          AND s.notes LIKE '%Survey completed%'
        ORDER BY s.updated_at DESC
    ''').fetchall()
    
    # Also find any records touched today where notes mention "Survey"
    # (catches the "Surveyed" variant too)
    extra = conn.execute('''
        SELECT s.id, s.full_name, s.street_number || ' ' || s.street as address,
               s.phone, s.support_level, s.notes, s.updated_at
        FROM supporters s
        WHERE date(s.updated_at) = date('now','localtime')
          AND s.notes LIKE '%Survey%'
          AND s.notes NOT LIKE '%Survey completed%'
        ORDER BY s.updated_at DESC
    ''').fetchall()
    
    conn.close()
    
    # Counts
    total_completed = len(rows)
    total_touched = len(extra)
    supporters_count = sum(1 for r in rows if r['support_level'] == 'Supporter')
    
    # Build report
    lines = []
    lines.append(f"📋 WARD 25 DAILY SURVEY REPORT — {today}")
    lines.append("=" * 50)
    lines.append(f"Surveys completed today: {total_completed}")
    lines.append(f"Supporters surveyed: {supporters_count}")
    lines.append(f"Other survey activity: {total_touched}")
    lines.append("")
    
    if rows:
        lines.append("── Completed Surveys ──")
        for i, r in enumerate(rows, 1):
            name = r['full_name'] or 'Unknown'
            addr = r['address'] or 'No address'
            phone = r['phone'] or '—'
            level = r['support_level'] or '—'
            lines.append(f"  {i}. {name} | {addr} | {phone} | {level}")
        lines.append("")
    
    if extra:
        lines.append("── Other Survey Activity ──")
        for i, r in enumerate(extra, 1):
            name = r['full_name'] or 'Unknown'
            lines.append(f"  {i}. {name} | {r['address']} | {r['support_level'] or '—'}")
    
    if not rows and not extra:
        lines.append("No survey activity recorded today.")
    
    lines.append("")
    lines.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    report = "\n".join(lines)
    print(report)

if __name__ == '__main__':
    main()
