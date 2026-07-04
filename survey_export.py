#!/usr/bin/env python3
"""
Daily Survey CSV Export — generates a comprehensive CSV of all completed surveys
with supporter info + survey responses, suitable for AI analysis and querying.
"""
import sqlite3, csv, io, os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'supporters.db')

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Get all survey responses joined with supporter data
    rows = conn.execute('''
        SELECT 
            sr.id as survey_id,
            sr.supporter_id,
            s.full_name,
            s.first_name,
            s.last_name,
            s.street_number || ' ' || s.street as address,
            s.apartment,
            s.city,
            s.postal_code,
            s.phone,
            s.email,
            s.support_level,
            s.sign_request,
            s.candidate_conversation_request,
            s.notes as supporter_notes,
            sr.voter_name,
            sr.phone as survey_phone,
            sr.email as survey_email,
            sr.address as survey_address,
            sr.years_in_ward,
            sr.top_issue,
            sr.top_issue_other,
            sr.downsize_home,
            sr.chow_rating,
            sr.fair_share,
            sr.lives_in_ward,
            sr.heard_of_shawn,
            sr.voting_plan,
            sr.decided_support,
            sr.involvement,
            sr.street_concern,
            sr.canvasser_notes,
            sr.eligible_voters,
            sr.created_at as survey_completed_at,
            s.updated_at,
            s.created_at
        FROM survey_responses sr
        LEFT JOIN supporters s ON sr.supporter_id = s.id
        ORDER BY sr.created_at DESC
    ''').fetchall()

    conn.close()

    if not rows:
        print("No survey responses yet.")
        # Still output empty CSV with headers
        headers = ['survey_id','supporter_id','full_name','first_name','last_name','address',
                   'apartment','city','postal_code','phone','email','support_level',
                   'sign_request','candidate_conversation_request','supporter_notes',
                   'voter_name','survey_phone','survey_email','survey_address',
                   'years_in_ward','top_issue','top_issue_other','downsize_home',
                   'chow_rating','fair_share','lives_in_ward','heard_of_shawn',
                   'voting_plan','decided_support','involvement','street_concern',
                   'canvasser_notes','eligible_voters','survey_completed_at',
                   'updated_at','created_at']
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        csv_path = os.path.join(os.path.dirname(DB_PATH), 'backups', 
                                f'surveys_{datetime.now().strftime("%Y-%m-%d")}.csv')
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        with open(csv_path, 'w', newline='') as f:
            f.write(output.getvalue())
        print(f"Empty CSV written to {csv_path}")
        print("SURVEY_COUNT:0")
        return

    # Build CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(rows[0].keys())

    # Data
    for row in rows:
        writer.writerow([str(v) if v is not None else '' for v in row])

    # Save to file
    today = datetime.now().strftime('%Y-%m-%d')
    csv_path = os.path.join(os.path.dirname(DB_PATH), 'backups', f'surveys_{today}.csv')
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, 'w', newline='') as f:
        f.write(output.getvalue())

    # Output summary for the agent to use in email
    count = len(rows)
    today_count = sum(1 for r in rows if str(r['survey_completed_at'] or '').startswith(today))

    print(f"SURVEY_COUNT:{count}")
    print(f"TODAY_COUNT:{today_count}")
    print(f"CSV_PATH:{csv_path}")
    print(f"FILE_SIZE:{os.path.getsize(csv_path)}")

    # Summary text
    supporters = sum(1 for r in rows if str(r['support_level'] or '').lower() == 'supporter')
    print(f"\n📋 WARD 25 SURVEY EXPORT — {today}")
    print(f"Total surveys: {count}")
    print(f"Completed today: {today_count}")
    print(f"Supporters surveyed: {supporters}")
    print(f"\nCSV saved to: {csv_path}")
    print(f"Columns: {', '.join(rows[0].keys())}")

    # Quick breakdown
    levels = {}
    for r in rows:
        lvl = r['support_level'] or 'Unknown'
        levels[lvl] = levels.get(lvl, 0) + 1
    print(f"\nBy support level:")
    for lvl, cnt in sorted(levels.items(), key=lambda x: -x[1]):
        print(f"  {lvl}: {cnt}")

if __name__ == '__main__':
    main()
