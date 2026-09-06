"""
Round 1 - Cyber Puzzle: Mixed Fundamentals
Database layer (SQLite) and connection management.

Uses a dedicated SQLite database file (round1.db) for the Round 1
competition. Flake8/PEP8-friendly, thread-safe per-request connections.
"""
import os
import sqlite3
import time

# DB file lives inside the round1 package directory
DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DB_DIR, "round1.db")

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id TEXT UNIQUE NOT NULL,
    team_name TEXT NOT NULL,
    participant_names TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER,
    round1_access_id TEXT,
    round2_access_id TEXT,
    round1_enabled INTEGER NOT NULL DEFAULT 1,
    round2_enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS challenge_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_code TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    domain TEXT NOT NULL,
    description TEXT DEFAULT '',
    difficulty TEXT NOT NULL,
    points INTEGER NOT NULL DEFAULT 100,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS challenge_variants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge_category_id INTEGER NOT NULL,
    variant_code TEXT NOT NULL,
    title TEXT DEFAULT '',
    question TEXT DEFAULT '',
    task_description TEXT DEFAULT '',
    provided_data TEXT DEFAULT '',
    expected_answer TEXT NOT NULL,
    flag TEXT NOT NULL,
    difficulty TEXT NOT NULL,
    hint TEXT DEFAULT '',
    explanation TEXT DEFAULT '',
    estimated_solve_time TEXT DEFAULT '',
    -- Mini-CTF lab fields
    lab_type TEXT DEFAULT '',
    story TEXT DEFAULT '',
    objective TEXT DEFAULT '',
    lab_data TEXT DEFAULT '{}',
    hints TEXT DEFAULT '[]',
    mediabanner TEXT DEFAULT '',
    UNIQUE(challenge_category_id, variant_code),
    FOREIGN KEY (challenge_category_id) REFERENCES challenge_categories(id)
);

CREATE TABLE IF NOT EXISTS round_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    round_name TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    ends_at INTEGER NOT NULL,
    completed_at INTEGER,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    score INTEGER NOT NULL DEFAULT 0,
    challenges_solved INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (team_id) REFERENCES teams(id)
);

CREATE TABLE IF NOT EXISTS team_challenge_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    challenge_category_id INTEGER NOT NULL,
    variant_id INTEGER NOT NULL,
    display_order INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'IN_PROGRESS',
    started_at INTEGER,
    completed_at INTEGER,
    points_awarded INTEGER NOT NULL DEFAULT 0,
    -- Mini-CTF lab state
    lab_status TEXT NOT NULL DEFAULT 'NOT_STARTED',
    lab_started_at INTEGER,
    lab_completed_at INTEGER,
    flag_revealed INTEGER NOT NULL DEFAULT 0,
    -- Attempt / freeze state for the lab question (max 3 attempts)
    lab_attempts INTEGER NOT NULL DEFAULT 0,
    lab_submitted INTEGER NOT NULL DEFAULT 0,
    UNIQUE(session_id, challenge_category_id),
    FOREIGN KEY (session_id) REFERENCES round_sessions(id),
    FOREIGN KEY (challenge_category_id) REFERENCES challenge_categories(id),
    FOREIGN KEY (variant_id) REFERENCES challenge_variants(id)
);

CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    assignment_id INTEGER NOT NULL,
    submitted_answer TEXT NOT NULL,
    is_correct INTEGER NOT NULL DEFAULT 0,
    submitted_at INTEGER NOT NULL,
    attempt_number INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES round_sessions(id),
    FOREIGN KEY (assignment_id) REFERENCES team_challenge_assignments(id)
);

CREATE TABLE IF NOT EXISTS hint_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    used_at INTEGER NOT NULL,
    FOREIGN KEY (assignment_id) REFERENCES team_challenge_assignments(id)
);

CREATE TABLE IF NOT EXISTS lab_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT DEFAULT '',
    occurred_at INTEGER NOT NULL,
    FOREIGN KEY (assignment_id) REFERENCES team_challenge_assignments(id),
    FOREIGN KEY (session_id) REFERENCES round_sessions(id)
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- Admin-authorized team access-control / active participant login tracking.
-- A row exists for every team that is currently signed in with a valid
-- session token. The row is marked CLEARED when the participant logs out or
-- when an admin clears the login.
CREATE TABLE IF NOT EXISTS participant_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    team_id INTEGER NOT NULL,
    login_time INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    FOREIGN KEY (team_id) REFERENCES teams(id)
);

-- ---------------------------------------------------------------------------
-- Admin Control Center tables
-- ---------------------------------------------------------------------------

-- Per-round configuration (one row per round; used by the Admin control
-- center to enable/pause/complete a round and control its competition params).
CREATE TABLE IF NOT EXISTS round_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    round_name TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    description TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'DRAFT',
    start_time INTEGER,
    end_time INTEGER,
    timer_minutes INTEGER NOT NULL DEFAULT 60,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    scoring_mode TEXT NOT NULL DEFAULT 'AUTO',
    access_enabled INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER
);

-- Administrator audit trail (who did what, when, and the outcome).
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_user TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    result TEXT NOT NULL DEFAULT 'OK',
    created_at INTEGER NOT NULL
);

-- Round 2 content library: forensic cases.
CREATE TABLE IF NOT EXISTS r2_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_code TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    case_type TEXT DEFAULT 'SIMULATED CYBERCRIME',
    description TEXT DEFAULT '',
    objective TEXT DEFAULT '',
    case_brief TEXT DEFAULT '',
    company TEXT DEFAULT '',
    difficulty TEXT DEFAULT 'MEDIUM',
    time_limit INTEGER NOT NULL DEFAULT 60,
    points INTEGER NOT NULL DEFAULT 100,
    status TEXT NOT NULL DEFAULT 'DRAFT',
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER,
    updated_at INTEGER
);

-- Round 2 investigation tasks (a.k.a stations / vault levels). Each task owns
-- a single question, expected answer, points and validation settings.
CREATE TABLE IF NOT EXISTS r2_stations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    station_id TEXT NOT NULL,
    name TEXT NOT NULL,
    domain TEXT DEFAULT '',
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    question TEXT DEFAULT '',
    answer TEXT DEFAULT '',
    hint TEXT DEFAULT '',
    points INTEGER NOT NULL DEFAULT 100,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    validation_mode TEXT NOT NULL DEFAULT 'NORMALIZED',
    display_order INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'DRAFT',
    created_at INTEGER,
    updated_at INTEGER,
    UNIQUE(case_id, station_id),
    FOREIGN KEY (case_id) REFERENCES r2_cases(id)
);

-- Round 2 person-identification questions (final report section).
CREATE TABLE IF NOT EXISTS r2_persons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    person_key TEXT NOT NULL,
    answers TEXT NOT NULL DEFAULT '[]',
    clue TEXT DEFAULT '',
    display_order INTEGER NOT NULL DEFAULT 0,
    UNIQUE(case_id, person_key),
    FOREIGN KEY (case_id) REFERENCES r2_cases(id)
);

-- Round 2 evidence library items (uploaded artifacts + their hashes).
CREATE TABLE IF NOT EXISTS r2_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    evidence_code TEXT,
    name TEXT NOT NULL,
    evidence_type TEXT NOT NULL DEFAULT 'OTHER',
    description TEXT DEFAULT '',
    filename TEXT DEFAULT '',
    file_hash TEXT DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0,
    display_order INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'DRAFT',
    created_at INTEGER,
    updated_at INTEGER,
    FOREIGN KEY (case_id) REFERENCES r2_cases(id)
);

-- Round 2 persisted per-team progress (feed for the Round 2 leaderboard).
CREATE TABLE IF NOT EXISTS r2_progress (
    team_id INTEGER PRIMARY KEY,
    case_code TEXT DEFAULT '',
    station_points INTEGER NOT NULL DEFAULT 0,
    person_points INTEGER NOT NULL DEFAULT 0,
    report_points INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    verified_stations INTEGER NOT NULL DEFAULT 0,
    verified_persons INTEGER NOT NULL DEFAULT 0,
    report_done INTEGER NOT NULL DEFAULT 0,
    completed_at INTEGER,
    updated_at INTEGER,
    FOREIGN KEY (team_id) REFERENCES teams(id)
);

-- Indexes for performance & integrity
CREATE INDEX IF NOT EXISTS idx_sessions_team ON round_sessions(team_id);
CREATE INDEX IF NOT EXISTS idx_assignments_session ON team_challenge_assignments(session_id);
CREATE INDEX IF NOT EXISTS idx_submissions_session ON submissions(session_id);
CREATE INDEX IF NOT EXISTS idx_variants_cat ON challenge_variants(challenge_category_id);
CREATE INDEX IF NOT EXISTS idx_labevents_assignment ON lab_events(assignment_id);
CREATE INDEX IF NOT EXISTS idx_ps_team ON participant_sessions(team_id);
CREATE INDEX IF NOT EXISTS idx_ps_status ON participant_sessions(status);

-- Team IDs are treated as case-insensitive so CT2026-001 cannot be
-- duplicated as ct2026-001 or any other mixed-case variant.
CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_team_id_ci ON teams(team_id COLLATE NOCASE);
"""


def get_connection():
    """Return a new SQLite connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now_ms():
    """Current unix timestamp in milliseconds (server time)."""
    return int(time.time() * 1000)


def init_db():
    """Create tables if they do not exist."""
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def reset_db():
    """Drop all tables and re-initialize (useful for testing/clean start)."""
    conn = get_connection()
    try:
        conn.execute("PRAGMA foreign_keys = OFF")
        with conn:
            tables = [
                "teams", "challenge_categories", "challenge_variants",
                "round_sessions", "team_challenge_assignments",
                "submissions", "hint_usage", "lab_events", "admins",
            ]
            for t in tables:
                conn.execute(f"DROP TABLE IF EXISTS {t}")
        init_db()
    finally:
        conn.close()


def migrate():
    """Apply additive schema changes to an existing round1.db.

    Only adds the columns needed for the lab 3-attempt / freeze feature and
    the access-control tables so an existing database (already seeded with
    data) can be upgraded in place without losing any team progress.
    """
    conn = get_connection()
    try:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(team_challenge_assignments)")}
        if "lab_attempts" not in cols:
            conn.execute(
                "ALTER TABLE team_challenge_assignments "
                "ADD COLUMN lab_attempts INTEGER NOT NULL DEFAULT 0")
        if "lab_submitted" not in cols:
            conn.execute(
                "ALTER TABLE team_challenge_assignments "
                "ADD COLUMN lab_submitted INTEGER NOT NULL DEFAULT 0")

        # Access-control: teams enable/disable flag + update timestamp.
        team_cols = {r["name"] for r in conn.execute("PRAGMA table_info(teams)")}
        if "is_active" not in team_cols:
            conn.execute(
                "ALTER TABLE teams "
                "ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        if "updated_at" not in team_cols:
            conn.execute("ALTER TABLE teams ADD COLUMN updated_at INTEGER")
        # Separate credentials let the event team issue and rotate access for
        # each round independently. Existing teams retain their original ID
        # for both rounds, so upgrading never locks anybody out.
        if "round1_access_id" not in team_cols:
            conn.execute("ALTER TABLE teams ADD COLUMN round1_access_id TEXT")
        if "round2_access_id" not in team_cols:
            conn.execute("ALTER TABLE teams ADD COLUMN round2_access_id TEXT")
        if "round1_enabled" not in team_cols:
            conn.execute("ALTER TABLE teams ADD COLUMN round1_enabled INTEGER NOT NULL DEFAULT 1")
        if "round2_enabled" not in team_cols:
            conn.execute("ALTER TABLE teams ADD COLUMN round2_enabled INTEGER NOT NULL DEFAULT 1")
        conn.execute("UPDATE teams SET round1_access_id=team_id "
                     "WHERE round1_access_id IS NULL OR round1_access_id='' ")
        conn.execute("UPDATE teams SET round2_access_id=team_id "
                     "WHERE round2_access_id IS NULL OR round2_access_id='' ")

        # Active participant login tracking table (fresh installs get it from
        # SCHEMA; existing DBs get it here).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS participant_sessions ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " token TEXT UNIQUE NOT NULL,"
            " team_id INTEGER NOT NULL,"
            " login_time INTEGER NOT NULL,"
            " last_seen INTEGER NOT NULL,"
            " status TEXT NOT NULL DEFAULT 'ACTIVE',"
            " FOREIGN KEY (team_id) REFERENCES teams(id))")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ps_team ON participant_sessions(team_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ps_status ON participant_sessions(status)")
        ps_cols = {r["name"] for r in conn.execute("PRAGMA table_info(participant_sessions)")}
        if "round_name" not in ps_cols:
            conn.execute("ALTER TABLE participant_sessions ADD COLUMN round_name TEXT NOT NULL DEFAULT 'round1'")
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_teams_team_id_ci "
                "ON teams(team_id COLLATE NOCASE)")
        except sqlite3.OperationalError:
            # Pre-existing case-variant duplicates: keep default uniqueness and
            # rely on application-level case-insensitive checks instead.
            pass

        # Admin Control Center tables (additive; safe on existing DBs).
        conn.execute(
            "CREATE TABLE IF NOT EXISTS round_settings ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " round_name TEXT UNIQUE NOT NULL,"
            " display_name TEXT NOT NULL DEFAULT '',"
            " description TEXT DEFAULT '',"
            " status TEXT NOT NULL DEFAULT 'DRAFT',"
            " start_time INTEGER,"
            " end_time INTEGER,"
            " timer_minutes INTEGER NOT NULL DEFAULT 60,"
            " max_attempts INTEGER NOT NULL DEFAULT 3,"
            " scoring_mode TEXT NOT NULL DEFAULT 'AUTO',"
            " access_enabled INTEGER NOT NULL DEFAULT 1,"
            " updated_at INTEGER)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS admin_audit_log ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " admin_user TEXT NOT NULL,"
            " action TEXT NOT NULL,"
            " target TEXT DEFAULT '',"
            " detail TEXT DEFAULT '',"
            " result TEXT NOT NULL DEFAULT 'OK',"
            " created_at INTEGER NOT NULL)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS r2_cases ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " case_code TEXT UNIQUE NOT NULL,"
            " title TEXT NOT NULL,"
            " case_type TEXT DEFAULT 'SIMULATED CYBERCRIME',"
            " description TEXT DEFAULT '',"
            " objective TEXT DEFAULT '',"
            " case_brief TEXT DEFAULT '',"
            " company TEXT DEFAULT '',"
            " difficulty TEXT DEFAULT 'MEDIUM',"
            " time_limit INTEGER NOT NULL DEFAULT 60,"
            " points INTEGER NOT NULL DEFAULT 100,"
            " status TEXT NOT NULL DEFAULT 'DRAFT',"
            " display_order INTEGER NOT NULL DEFAULT 0,"
            " created_at INTEGER,"
            " updated_at INTEGER)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS r2_stations ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " case_id INTEGER NOT NULL,"
            " station_id TEXT NOT NULL,"
            " name TEXT NOT NULL,"
            " domain TEXT DEFAULT '',"
            " description TEXT DEFAULT '',"
            " evidence TEXT DEFAULT '',"
            " question TEXT DEFAULT '',"
            " answer TEXT DEFAULT '',"
            " hint TEXT DEFAULT '',"
            " points INTEGER NOT NULL DEFAULT 100,"
            " max_attempts INTEGER NOT NULL DEFAULT 5,"
            " validation_mode TEXT NOT NULL DEFAULT 'NORMALIZED',"
            " display_order INTEGER NOT NULL DEFAULT 0,"
            " status TEXT NOT NULL DEFAULT 'DRAFT',"
            " created_at INTEGER,"
            " updated_at INTEGER,"
            " UNIQUE(case_id, station_id),"
            " FOREIGN KEY (case_id) REFERENCES r2_cases(id))")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS r2_persons ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " case_id INTEGER NOT NULL,"
            " role TEXT NOT NULL,"
            " person_key TEXT NOT NULL,"
            " answers TEXT NOT NULL DEFAULT '[]',"
            " clue TEXT DEFAULT '',"
            " display_order INTEGER NOT NULL DEFAULT 0,"
            " UNIQUE(case_id, person_key),"
            " FOREIGN KEY (case_id) REFERENCES r2_cases(id))")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS r2_evidence ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " case_id INTEGER NOT NULL,"
            " evidence_code TEXT,"
            " name TEXT NOT NULL,"
            " evidence_type TEXT NOT NULL DEFAULT 'OTHER',"
            " description TEXT DEFAULT '',"
            " filename TEXT DEFAULT '',"
            " file_hash TEXT DEFAULT '',"
            " file_size INTEGER NOT NULL DEFAULT 0,"
            " display_order INTEGER NOT NULL DEFAULT 0,"
            " status TEXT NOT NULL DEFAULT 'DRAFT',"
            " created_at INTEGER,"
            " updated_at INTEGER,"
            " FOREIGN KEY (case_id) REFERENCES r2_cases(id))")

        # Round 1 content: publish/unpublish switch + display ordering for
        # challenge categories and their variants (question bank).
        cat_cols = {r["name"] for r in conn.execute("PRAGMA table_info(challenge_categories)")}
        if "display_order" not in cat_cols:
            conn.execute("ALTER TABLE challenge_categories ADD COLUMN display_order INTEGER NOT NULL DEFAULT 0")
        var_cols = {r["name"] for r in conn.execute("PRAGMA table_info(challenge_variants)")}
        if "status" not in var_cols:
            conn.execute("ALTER TABLE challenge_variants ADD COLUMN status TEXT NOT NULL DEFAULT 'PUBLISHED'")
        if "validation_mode" not in var_cols:
            conn.execute("ALTER TABLE challenge_variants ADD COLUMN validation_mode TEXT NOT NULL DEFAULT 'NORMALIZED'")
        if "display_order" not in var_cols:
            conn.execute("ALTER TABLE challenge_variants ADD COLUMN display_order INTEGER NOT NULL DEFAULT 0")

        # Per-round access on participant_sessions so Round 1 / Round 2 login
        # tracking is fully independent (already added on fresh DBs).
        ps_cols = {r["name"] for r in conn.execute("PRAGMA table_info(participant_sessions)")}
        if "round_name" not in ps_cols:
            conn.execute("ALTER TABLE participant_sessions ADD COLUMN round_name TEXT NOT NULL DEFAULT 'round1'")
        if "case_code" not in ps_cols:
            conn.execute("ALTER TABLE participant_sessions ADD COLUMN case_code TEXT")

        # Seed per-round defaults (idempotent; only when rows are missing).
        conn.execute(
            "INSERT OR IGNORE INTO round_settings "
            "(round_name, display_name, description, status, timer_minutes, "
            " max_attempts, scoring_mode, access_enabled, updated_at) "
            "VALUES ('round1', 'MIXED FUNDAMENTALS', 'Cyber Puzzle technical challenges.', "
            "'ACTIVE', 30, 3, 'AUTO', 1, ?)",
            (now_ms(),))
        conn.execute(
            "INSERT OR IGNORE INTO round_settings "
            "(round_name, display_name, description, status, timer_minutes, "
            " max_attempts, scoring_mode, access_enabled, updated_at) "
            "VALUES ('round2', 'DIGITAL FORENSICS', 'Cyber Detective investigation cases.', "
            "'ACTIVE', 45, 5, 'AUTO', 1, ?)",
            (now_ms(),))
        # Fix: Round 2 timer is 45 minutes. Migrate legacy 90-min rows.
        conn.execute(
            "UPDATE round_settings SET timer_minutes=45, updated_at=? "
            "WHERE round_name='round2' AND timer_minutes != 45",
            (now_ms(),))
        conn.commit()
    finally:
        conn.close()
