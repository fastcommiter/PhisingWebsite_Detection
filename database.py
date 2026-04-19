import sqlite3
from datetime import datetime

def get_db():
    conn = sqlite3.connect('phishdetector.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            is_safe INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(user_email, url, result, is_safe, risk_score):
    conn = get_db()
    conn.execute('''
        INSERT INTO scans (user_email, url, result, is_safe, risk_score, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_email, url, result, is_safe, risk_score, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_user_scans(user_email):
    conn = get_db()
    scans = conn.execute('''
        SELECT * FROM scans WHERE user_email = ? ORDER BY timestamp DESC
    ''', (user_email,)).fetchall()
    conn.close()
    return scans

def get_user_stats(user_email):
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM scans WHERE user_email = ?', (user_email,)).fetchone()[0]
    safe  = conn.execute('SELECT COUNT(*) FROM scans WHERE user_email = ? AND is_safe = 1', (user_email,)).fetchone()[0]
    unsafe = conn.execute('SELECT COUNT(*) FROM scans WHERE user_email = ? AND is_safe = 0', (user_email,)).fetchone()[0]
    recent = conn.execute('SELECT * FROM scans WHERE user_email = ? ORDER BY timestamp DESC LIMIT 5', (user_email,)).fetchall()
    conn.close()
    return { 'total': total, 'safe': safe, 'unsafe': unsafe, 'recent': recent }
def delete_scans(user_email, scan_ids):
    conn = get_db()
    placeholders = ','.join('?' * len(scan_ids))
    conn.execute(
        f'DELETE FROM scans WHERE user_email = ? AND id IN ({placeholders})',
        [user_email] + [int(i) for i in scan_ids]
    )
    conn.commit()
    conn.close()
