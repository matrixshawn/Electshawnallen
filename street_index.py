#!/usr/bin/env python3
"""Street Index Lookup — Maps street + number → sub-area (poll) for Ward 25."""
import re
import openpyxl
import os

STREET_INDEX_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  'street_index_W25.xlsx')

# In-memory cache: { 'STREET NAME': [ (odd_low, odd_high, sub), (even_low, even_high, sub), ... ] }
_index = None
_poll_order = []

def _normalize_street(name):
    """Normalize street name for matching: uppercase, strip, collapse spaces."""
    if not name:
        return ''
    return re.sub(r'\s+', ' ', str(name).upper().strip())

def _load_index():
    """Load the street index from the Excel file into memory."""
    global _index, _poll_order
    if _index is not None:
        return
    _index = {}
    _poll_order = []
    wb = openpyxl.load_workbook(STREET_INDEX_PATH, data_only=True)
    ws = wb['SI_W25']
    # Track poll order from file (first appearance)
    _poll_order = []
    seen_polls = set()
    # Skip header rows (row 1 = title, row 2 = headers)
    for row in ws.iter_rows(min_row=3, values_only=True):
        name, odd_low, odd_high, even_low, even_high, ward, sub = row
        if not name:
            continue
        key = _normalize_street(name)
        entry = {
            'odd_low': odd_low,
            'odd_high': odd_high,
            'even_low': even_low,
            'even_high': even_high,
            'sub': sub
        }
        if key not in _index:
            _index[key] = []
        _index[key].append(entry)
        if sub and sub not in seen_polls:
            seen_polls.add(sub)
            _poll_order.append(sub)
    wb.close()
    print(f"Street index loaded: {len(_index)} streets, {sum(len(v) for v in _index.values())} ranges")


def lookup_poll(street_name, street_number):
    """Return the sub-area (poll) number for a given street and number, or None.
    
    Args:
        street_name: The street name (e.g., "AKASHA CRT")
        street_number: The street number as string or int (e.g., "5")
    
    Returns:
        The sub-area number as integer, or None if not found.
    """
    global _index
    if _index is None:
        _load_index()
    
    if not street_name or not street_number or _index is None:
        return None
    
    # Parse numeric portion
    match = re.search(r'\d+', str(street_number))
    if not match:
        return None
    num = int(match.group())
    
    key = _normalize_street(street_name)
    
    # Try exact match first
    ranges = _index.get(key, [])
    if not ranges:
        # Try partial matches (e.g., "CRT" for "COURT", "RD" for "ROAD")
        for k, v in _index.items():
            # Check if one is a prefix/suffix variant of the other
            base = re.split(r'\s+(?:CRT|CT|RD|DR|ST|AVE|BLVD|LN|WAY|CIR|PL|TERR|GT)$', k)[0]
            base_key = re.split(r'\s+(?:CRT|CT|RD|DR|ST|AVE|BLVD|LN|WAY|CIR|PL|TERR|GT)$', key)[0]
            if base == base_key:
                ranges = v
                break
    
    if not ranges:
        return None
    
    is_even = (num % 2 == 0)
    
    for r in ranges:
        if is_even:
            low = r['even_low']
            high = r['even_high']
        else:
            low = r['odd_low']
            high = r['odd_high']
        
        try:
            low_i = int(low) if low is not None else None
            high_i = int(high) if high is not None else None
        except (ValueError, TypeError):
            low_i = high_i = None
        
        if low_i is not None and high_i is not None and low_i <= num <= high_i:
            return r['sub']
    
    return None


def get_poll_order():
    """Return the canonical poll order from the street index file (first appearance)."""
    global _index
    if _index is None:
        _load_index()
    return _poll_order


def backfill_polls(db_path=None):
    """Backfill poll data for all existing supporter records."""
    import sqlite3
    from datetime import datetime
    
    if db_path is None:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'supporters.db')
    
    _load_index()
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # Get all supporters
    rows = conn.execute('SELECT id, street_number, street, poll FROM supporters').fetchall()
    
    updated = 0
    skipped = 0
    
    for row in rows:
        # Skip if already has a valid poll
        if row['poll'] and str(row['poll']).strip() and str(row['poll']).strip() != 'None':
            skipped += 1
            continue
        
        sub = lookup_poll(row['street'], row['street_number'])
        if sub is not None:
            conn.execute(
                'UPDATE supporters SET poll = ?, updated_at = datetime("now","localtime") WHERE id = ?',
                (str(sub), row['id'])
            )
            updated += 1
    
    conn.commit()
    conn.close()
    
    print(f"Backfill complete: {updated} updated, {skipped} already had poll, {len(rows) - updated - skipped} unmatched")
    return updated, skipped, len(rows)


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--backfill':
        backfill_polls()
    elif len(sys.argv) > 1:
        sub = lookup_poll(sys.argv[1], sys.argv[2])
        print(f"Street: {sys.argv[1]}, Number: {sys.argv[2]} → Poll: {sub}")
    else:
        _load_index()
        print(f"Loaded {len(_index)} streets. Use --backfill to populate DB.")
