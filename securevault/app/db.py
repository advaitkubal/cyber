# SECURITY: SQL Injection Protection - All queries strictly use parameterized statements with ? placeholders.
# Never build SQL with f-strings, % formatting or string concatenation to prevent SQL injection vulnerabilities.

import sqlite3
from typing import Optional, Any
from flask import g, current_app

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    key_salt BLOB NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title_enc TEXT NOT NULL,
    body_enc TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    site_enc TEXT NOT NULL,
    username_enc TEXT NOT NULL,
    password_enc TEXT NOT NULL,
    url_enc TEXT,
    remarks_enc TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NULL,
    event TEXT NOT NULL,
    ip TEXT,
    created_at TEXT NOT NULL
);
"""

def get_db() -> sqlite3.Connection:
    """Returns a thread-local SQLite connection with foreign keys enabled."""
    if "db" not in g:
        db_path = current_app.config["DATABASE_PATH"]
        # SECURITY: Foreign Key Enforcement - Guarantees relational integrity and cascade deletes
        conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        g.db = conn
    return g.db

def close_db(e: Optional[BaseException] = None) -> None:
    """Closes the active database connection if open."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db(app=None) -> None:
    """Initializes the database schema if tables do not exist."""
    if app:
        with app.app_context():
            db = get_db()
            db.executescript(SCHEMA_SQL)
            db.commit()
    else:
        db = get_db()
        db.executescript(SCHEMA_SQL)
        db.commit()

# Parameterized Query Helper Functions
def query_db(query: str, args: tuple = (), one: bool = False) -> Any:
    """Executes a safe parameterized read query."""
    # SECURITY: Parameterized Queries - Avoids SQL injection via ? placeholders
    cur = get_db().execute(query, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows

def execute_db(query: str, args: tuple = ()) -> int:
    """Executes a safe parameterized write query and commits."""
    # SECURITY: Parameterized Queries - Avoids SQL injection via ? placeholders
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id
