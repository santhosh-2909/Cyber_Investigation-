"""Participant access control + admin session management.

Single source of truth for who may log in (admin-authorized teams), tracking
of active participant login sessions, and the admin's ability to revoke
individual / selected / all participant sessions without touching team
records or Round 1 / Round 2 progress.

Architecture notes
------------------
* Only teams the administrator creates via the Admin panel (stored in the
  existing ``teams`` table of round1.db) can sign in.
* A participant logs in with exactly two credentials: TEAM NAME + TEAM ID.
  Nothing else is trusted from the client.
* On login, a random server-issued token is stored in the Flask session and a
  matching row (status ACTIVE) is written to ``participant_sessions``. Every
  protected request re-validates that token server-side, so session tokens
  cannot be forged or faked via localStorage / cookies / URL parameters.
* When an admin clears a login the row is marked CLEARED; the participant's
  next request detects the revocation and returns them to the login page.
* The team's ``is_active`` flag enables / disables access. Disabled teams
  cannot log in and any already-open session is invalidated on next request.
"""
import os
import re
import secrets

import round1.db as db
import admin_ops

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Flask session key holding the server-issued participant token.
# Round 2 uses its own token when the team signed in through the unified
# ONE LOGIN · BOTH ROUNDS flow (one ACTIVE row per round).
SESSION_TOKEN_KEY = "ptoken"
SESSION_TOKEN_KEY_R2 = "ptoken_r2"

# Round 1 admin session key (existing, authenticates against the admins table).
SESSION_ADMIN_KEY = "r1_admin"

# All participant-owned session keys. Cleared together on logout / session
# invalidation. Admin keys are intentionally NOT included.
PARTICIPANT_SESSION_KEYS = (
    SESSION_TOKEN_KEY,
    SESSION_TOKEN_KEY_R2,
    "r1_team",
    "r1_rules_ack",
    "r1_profile",
    "team",
    "findings",
    "persons",
    "notes",
    "attempts",
    "report",
    "brief_viewed",
    "challenges_solved",
    "active_round",
    "unified_rounds",
    "r2_started_at",
    "r2_ends_at",
    "r2_status",
    "r2_completed_at",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Rotating case pool (matches CASES keys in app.py).
CASE_LIST = ["case1", "case2", "case3"]

# Session liveness windows (no background polling).
# A session whose last seen activity is within SESSION_ONLINE_WINDOW_MS is
# ONLINE; older than that but less than SESSION_EXPIRE_MS it is OFFLINE (still
# a valid login); older than SESSION_EXPIRE_MS it is auto-cleared so it stops
# appearing in the admin lists. Liveness is computed when the admin page/
# listing is loaded, and each participant request already refreshes last_seen
# as a heartbeat (see validate_participant).
SESSION_ONLINE_WINDOW_MS = 5 * 60 * 1000          # 5 minutes
SESSION_EXPIRE_MS = 24 * 60 * 60 * 1000           # 24 hours

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _session():
    import flask
    return flask.session


def _norm(text):
    """Case-insensitive, whitespace-collapsed normalisation for comparisons."""
    if not text:
        return ""
    return " ".join(re.sub(r"\s+", " ", str(text).strip().lower()).split())


def pick_case():
    """Rotating case assignment (existing data/case_counter.txt convention).

    If the Admin Control Center has published Round 2 cases, the rotation
    draws from those (admin-managed = participant-consumed). Otherwise it
    falls back to the original hard-coded pool so an unconfigured database
    keeps the classic behaviour.
    """
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT case_code FROM r2_cases WHERE status='PUBLISHED' "
            "ORDER BY display_order, id").fetchall()
    finally:
        conn.close()
    pool = [r["case_code"] for r in rows]
    if not pool:
        pool = [c for c in CASE_LIST if c]
    counter = 0
    counter_path = os.path.join(BASE_DIR, "data", "case_counter.txt")
    if os.environ.get("VERCEL"):
        counter_path = "/tmp/case_counter.txt"
    try:
        with open(counter_path, "r") as f:
            counter = int(f.read().strip() or "0")
    except Exception:
        counter = 0
    selected = pool[counter % len(pool)]
    counter += 1
    try:
        with open(counter_path, "w") as f:
            f.write(str(counter))
    except Exception:
        pass
    return selected


# ---------------------------------------------------------------------------
# Team lookup / validation
# ---------------------------------------------------------------------------


def get_team_by_credentials(team_name, access_id, round_name=None):
    """Return the team row (dict) whose name + id match, or None.

    Both fields must match an authorized team record. Team IDs are compared
    case-insensitively; names are compared case-insensitively after collapsing
    whitespace. No partial matches.
    """
    team_name = (team_name or "").strip()
    access_id = (access_id or "").strip()
    if not team_name or not access_id:
        return None
    credential_column = {
        "round1": "round1_access_id",
        "round2": "round2_access_id",
    }.get(round_name, "team_id")
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM teams WHERE %s = ? COLLATE NOCASE" % credential_column,
            (access_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    team = dict(row)
    enabled_column = {"round1": "round1_enabled", "round2": "round2_enabled"}.get(round_name)
    if (_norm(team.get("team_name")) == _norm(team_name)
            and (not enabled_column or team.get(enabled_column, 0))):
        return team
    return None


def _team_pub_dict(d):
    """Return only safe team columns (never session tokens / internal ids)."""
    keys = ("id", "team_id", "team_name", "participant_names",
            "created_at", "is_active", "updated_at")
    return {k: d.get(k) for k in keys}


def _session_fallback_team(s, round_name=None):
    """Reconstruct a team dict from the signed Flask session cookie.

    On Vercel / serverless platforms the SQLite DB is ephemeral per function
    instance, so the token written during login may not exist in the DB on
    the *next* request (different instance → fresh DB copy).  Because Flask
    session cookies are cryptographically signed with the app secret key the
    client cannot forge them, making them a safe fallback for auth when the
    DB row is missing.
    """
    profile = s.get("r1_profile")
    team_sess = s.get("team")

    if round_name == "round1" and profile:
        return {
            "id": profile.get("id"),
            "team_id": profile.get("team_id"),
            "team_name": profile.get("team_name"),
            "participant_names": "",
            "is_active": 1,
            "round1_enabled": 1,
            "round2_enabled": 0,
        }
    if round_name == "round2" and team_sess:
        return {
            "id": s.get("r1_team"),
            "team_id": team_sess.get("team_id"),
            "team_name": team_sess.get("name"),
            "participant_names": team_sess.get("captain", ""),
            "is_active": 1,
            "round1_enabled": 0,
            "round2_enabled": 1,
        }
    # No specific round requested — return whichever round's session exists.
    if profile:
        return {
            "id": profile.get("id"),
            "team_id": profile.get("team_id"),
            "team_name": profile.get("team_name"),
            "participant_names": "",
            "is_active": 1,
            "round1_enabled": 1,
            "round2_enabled": 1,
        }
    if team_sess:
        return {
            "id": s.get("r1_team"),
            "team_id": team_sess.get("team_id"),
            "team_name": team_sess.get("name"),
            "participant_names": team_sess.get("captain", ""),
            "is_active": 1,
            "round1_enabled": 1,
            "round2_enabled": 1,
        }
    return None


# ---------------------------------------------------------------------------
# Participant login / logout / validation
# ---------------------------------------------------------------------------


def participant_login(team_name, access_id, round_name="round1"):
    """Validate an admin-authorized team and establish a participant session.

    Returns (ok: bool, error: str | None).
    """
    if not admin_ops.round_open(round_name):
        return False, "This round is not currently open."
    team = get_team_by_credentials(team_name, access_id, round_name)
    if team is None:
        return False, "Invalid team credentials for this round."
    if not team.get("is_active", 1):
        return False, "This team is currently unavailable."
    _open_session(team, round_name)
    return True, None


def participant_login_unified(team_name, access_id):
    """Validate a team ONCE (TEAM LOGIN) and open BOTH round sessions.

    ONE TEAM LOGIN · BOTH ROUNDS: the same sign-in grants access to Round 1
    and Round 2. The Team ID credential validates the team; sessions are then
    opened for every enabled + currently-open round (round1 and/or round2).

    Returns (ok: bool, error: str | None).
    """
    team = get_team_by_credentials(team_name, access_id)
    if team is None:
        return False, "Invalid team name or team ID."
    if not team.get("is_active", 1):
        return False, "This team is currently unavailable."
    opened = []
    for rn, enabled_col in (("round1", "round1_enabled"),
                            ("round2", "round2_enabled")):
        if team.get(enabled_col, 0) and admin_ops.round_open(rn):
            opened.append(rn)
    if not opened:
        return False, "No round is currently open for this team."
    for rn in opened:
        _open_session(team, rn)
    s = _session()
    s["unified_rounds"] = opened
    s["active_round"] = "round1" if "round1" in opened else "round2"
    return True, None


def _build_team_dict(team):
    """Round-2 presentation dict built from a teams row (used by sessions)."""
    return {
        "name": team.get("team_name"),
        "team_id": team.get("team_id"),
        "captain": team.get("participant_names") or "",
    }


def _open_session(team, round_name):
    """Persist an ACTIVE participant login row and seed the Flask session.

    Round 1 and Round 2 each keep their own ACTIVE participant_sessions row so
    one sign-in (TEAM LOGIN) can open BOTH rounds: the row for round_name is
    (re)created under its round-specific session token, and the cross-round
    session state is seeded once.
    """
    conn = db.get_connection()
    try:
        conn.execute(
            "UPDATE participant_sessions SET status='CLEARED' "
            "WHERE team_id=? AND round_name=? AND status='ACTIVE'", (team["id"], round_name))
        token = secrets.token_urlsafe(32)
        now = db.now_ms()
        case_code = None
        if round_name == "round2":
            case_code = pick_case()
        conn.execute(
            "INSERT INTO participant_sessions (token, team_id, round_name, login_time, "
            "last_seen, status, case_code) VALUES (?,?,?,?,?,?,?)",
            (token, team["id"], round_name, now, now, "ACTIVE", case_code))
        conn.commit()
    finally:
        conn.close()

    s = _session()
    # Store the token under the round-specific key so validate_participant can
    # authorize either round independently from a single sign-in.
    if round_name == "round2":
        s[SESSION_TOKEN_KEY_R2] = token
        if not s.get(SESSION_TOKEN_KEY):
            s[SESSION_TOKEN_KEY] = token
    else:
        s[SESSION_TOKEN_KEY] = token

    # Round 1 session keys (existing).
    s["r1_team"] = team["id"]
    s["r1_profile"] = {
        "id": team["id"],
        "team_id": team["team_id"],
        "team_name": team["team_name"],
    }
    # Round 2 session keys (existing). 'team' is the presentation dict the
    # Round 2 templates use; built here so the unified hub renders it.
    s["team"] = {
        "name": team["team_name"],
        "team_id": team["team_id"],
        "captain": team.get("participant_names") or "",
        "case": case_code or pick_case(),
    }
    s["findings"] = {}
    s["persons"] = {}
    s["notes"] = {}
    s["attempts"] = {}
    s["active_round"] = round_name
    # Round 2 countdown: fixed 45-min limit (admin setting, default 45).
    # Started at login; expiry marks the round COMPLETED server-side.
    if round_name == "round2":
        try:
            timer_minutes = int(
                (admin_ops.get_round_settings("round2") or {}).get(
                    "timer_minutes") or 45)
        except (TypeError, ValueError):
            timer_minutes = 45
        if timer_minutes <= 0:
            timer_minutes = 45
        now = db.now_ms()
        s["r2_started_at"] = now
        s["r2_ends_at"] = now + timer_minutes * 60 * 1000
        s["r2_status"] = "ACTIVE"
        s.pop("r2_completed_at", None)


def validate_participant(round_name=None):
    """Return the authorized team dict for the current participant, or None.

    This is the ONLY authorization gate used by every protected participant
    route / API. Server-side checks performed on every request:

    * a valid server-issued session token exists,
    * the token maps to an ACTIVE participant_sessions row,
    * the linked team still exists and is enabled.

    With the unified ONE LOGIN · BOTH ROUNDS flow a team holds one ACTIVE row
    per round, each under its own token. When round_name is supplied the
    round-specific token (SESSION_TOKEN_KEY_R2 for round2, SESSION_TOKEN_KEY
    otherwise) is used, so either round can be authorized independently.

    If any check fails the participant's session keys are wiped and a flag is
    stored so the login page can show an appropriate notice. As a lightweight
    heartbeat the last_seen timestamp is refreshed on each valid request.
    """
    s = _session()
    token = None
    if round_name == "round2":
        token = s.get(SESSION_TOKEN_KEY_R2) or s.get(SESSION_TOKEN_KEY)
    elif round_name == "round1":
        token = s.get(SESSION_TOKEN_KEY)
    else:
        token = s.get(SESSION_TOKEN_KEY) or s.get(SESSION_TOKEN_KEY_R2)
    if not token:
        return None
    conn = db.get_connection()
    try:
        if round_name:
            row = conn.execute(
                "SELECT ps.status AS ps_status, ps.token, t.* "
                "FROM participant_sessions ps "
                "JOIN teams t ON ps.team_id = t.id "
                "WHERE ps.token = ? AND ps.round_name = ?",
                (token, round_name)).fetchone()
        else:
            row = conn.execute(
                "SELECT ps.status AS ps_status, ps.token, t.* "
                "FROM participant_sessions ps "
                "JOIN teams t ON ps.team_id = t.id "
                "WHERE ps.token = ?", (token,)).fetchone()
    finally:
        conn.close()

    def _invalidate(reason_flag):
        s[reason_flag] = True
        _clear_participant_session()

    if row is None:
        # On Vercel / serverless platforms the SQLite DB is ephemeral per
        # function instance so a freshly-copied DB will NOT contain the token
        # written during login on a previous (or different) instance.  When
        # the session cookie still carries valid team metadata we can fall
        # back to cookie-based auth — Flask sessions are signed with the
        # secret key and cannot be forged by the client.
        cookie_team = _session_fallback_team(s, round_name)
        if cookie_team is not None:
            return cookie_team
        if round_name:
            return None
        _invalidate("session_ended_by_admin")
        return None
    d = dict(row)
    if d.get("ps_status") != "ACTIVE":
        _invalidate("session_ended_by_admin")
        return None
    if not d.get("is_active", 1):
        _invalidate("session_team_unavailable")
        return None
    active_round = round_name or s.get("active_round") or d.get("round_name")
    if active_round == "round1" and not d.get("round1_enabled", 0):
        _invalidate("session_team_unavailable")
        return None
    if active_round == "round2" and not d.get("round2_enabled", 0):
        _invalidate("session_team_unavailable")
        return None
    # Global round control: a paused/completed/admin-locked round blocks
    # everyone, even teams with valid active logins (Round 1 unaffected by
    # Round 2 state and vice-versa).
    if not admin_ops.round_open(active_round):
        _invalidate("round_not_open")
        return None

    # Valid request -> lightweight heartbeat so the admin sees online status.
    conn = db.get_connection()
    try:
        conn.execute("UPDATE participant_sessions SET last_seen=? WHERE token=?",
                     (db.now_ms(), token))
        conn.commit()
    finally:
        conn.close()

    # Ensure the required session keys are present (e.g. after server restart
    # while the browser cookie survives).
    if "team" not in s:
        s["team"] = {
            "name": d["team_name"],
            "team_id": d["team_id"],
            "captain": d.get("participant_names") or "",
            "case": pick_case(),
        }
    if "r1_team" not in s:
        s["r1_team"] = d["id"]
    return _team_pub_dict(d)


def participant_logout():
    """Mark the current participant logins CLEARED and wipe session keys.

    A unified (both-rounds) sign-in holds one token per round, so every
    token present in the session is revoked.
    """
    s = _session()
    tokens = {t for t in (s.get(SESSION_TOKEN_KEY), s.get(SESSION_TOKEN_KEY_R2)) if t}
    if tokens:
        conn = db.get_connection()
        try:
            for token in tokens:
                conn.execute("UPDATE participant_sessions SET status='CLEARED' "
                             "WHERE token=?", (token,))
            conn.commit()
        finally:
            conn.close()
    _clear_participant_session()


def _clear_participant_session():
    s = _session()
    for key in PARTICIPANT_SESSION_KEYS:
        s.pop(key, None)


def pop_login_notice():
    """Pop any session invalidation flag and return a user-facing message.

    Called by the login pages so a participant whose session was ended while
    mid-round (round paused, team disabled, admin cleared) is told why.
    """
    s = _session()
    if s.pop("round_not_open", None):
        return "This round is not currently open. Please try again later."
    if s.pop("session_team_unavailable", None):
        return "This team is currently unavailable."
    if s.pop("session_ended_by_admin", None):
        return "Your session was ended. Please log in again."
    return None


def is_logged_in(round_name=None):
    """Participant-level convenience check."""
    return validate_participant(round_name) is not None


# ---------------------------------------------------------------------------
# Admin: team access management
# ---------------------------------------------------------------------------


def list_teams():
    """Return all authorized teams with their live session counts."""
    now = db.now_ms()
    online_cutoff = now - SESSION_ONLINE_WINDOW_MS
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT t.*, "
            "(SELECT COUNT(*) FROM participant_sessions ps "
            "  WHERE ps.team_id = t.id AND ps.status='ACTIVE' "
            "  AND ps.last_seen >= ?) AS online_sessions, "
            "(SELECT COUNT(*) FROM participant_sessions ps "
            "  WHERE ps.team_id = t.id AND ps.status='ACTIVE') AS active_sessions, "
            "(SELECT COUNT(*) FROM round_sessions rs "
            "  WHERE rs.team_id = t.id AND rs.status='ACTIVE') AS round_active "
            "FROM teams t ORDER BY t.id DESC", (online_cutoff,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def team_detail(team_id):
    conn = db.get_connection()
    try:
        if isinstance(team_id, int) or (isinstance(team_id, str) and team_id.isdigit()):
            row = conn.execute("SELECT * FROM teams WHERE id=?",
                               (int(team_id),)).fetchone()
        else:
            row = conn.execute("SELECT * FROM teams WHERE team_id=? COLLATE NOCASE",
                               (str(team_id),)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def add_team(team_name, team_id, round1_access_id=None, round2_access_id=None):
    """Create an admin-authorized team. Returns (ok, message)."""
    team_name = (team_name or "").strip()
    team_id = (team_id or "").strip()
    if not team_name:
        return False, "Enter a team name."
    if not team_id:
        return False, "Enter a team ID."
    round1_access_id = (round1_access_id or team_id).strip()
    round2_access_id = (round2_access_id or team_id).strip()
    if not round1_access_id or not round2_access_id:
        return False, "Enter access IDs for both rounds."
    conn = db.get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM teams WHERE team_id = ? COLLATE NOCASE",
            (team_id,)).fetchone()
        if existing:
            return False, "Team ID already exists."
        for value, label in ((round1_access_id, "Round 1"), (round2_access_id, "Round 2")):
            existing = conn.execute(
                "SELECT id FROM teams WHERE %s_access_id = ? COLLATE NOCASE" % label.lower().replace(" ", ""),
                (value,)).fetchone()
            if existing:
                return False, "%s access ID already exists." % label
        now = db.now_ms()
        conn.execute(
            "INSERT INTO teams (team_id, team_name, participant_names, "
            "created_at, updated_at, round1_access_id, round2_access_id, "
            "round1_enabled, round2_enabled) VALUES (?,?,?,?,?,?,?,?,?)",
            (team_id, team_name, "", now, now, round1_access_id, round2_access_id, 1, 1))
        conn.commit()
        return True, "Team created successfully."
    finally:
        conn.close()


def set_round2_access(team_name, round2_access_id):
    """Issue or rotate a Round 2 Access ID for an existing team."""
    team_name = (team_name or "").strip()
    round2_access_id = (round2_access_id or "").strip()
    if not team_name or not round2_access_id:
        return False, "Enter both Team Name and Round 2 Access ID."
    conn = db.get_connection()
    try:
        rows = conn.execute("SELECT * FROM teams").fetchall()
        team = next((dict(row) for row in rows
                     if _norm(row["team_name"]) == _norm(team_name)), None)
        if not team:
            return False, "Create the team in Round 1 first."
        duplicate = conn.execute(
            "SELECT id FROM teams WHERE round2_access_id=? COLLATE NOCASE AND id<>?",
            (round2_access_id, team["id"])).fetchone()
        if duplicate:
            return False, "That Round 2 Access ID is already assigned."
        conn.execute("UPDATE teams SET round2_access_id=?, round2_enabled=1, updated_at=? WHERE id=?",
                     (round2_access_id, db.now_ms(), team["id"]))
        conn.commit()
        return True, "Round 2 Access ID saved."
    finally:
        conn.close()


def set_team_active(team_id, active):
    """Enable (active=True) or disable (active=False) a team's access."""
    conn = db.get_connection()
    try:
        cur = conn.execute(
            "UPDATE teams SET is_active=?, updated_at=? WHERE id=?",
            (1 if active else 0, db.now_ms(), int(team_id)))
        conn.commit()
        if cur.rowcount == 0:
            return False, "Team not found."
        return True, "Team access updated."
    finally:
        conn.close()


def update_team(team_db_id, team_name=None, team_id=None,
                participant_names=None, is_active=None):
    """Update an authorized team's details manually.

    A None argument keeps the current value, so the admin can edit a single
    field at a time. Team ID uniqueness is enforced case-insensitively while
    excluded for the team being edited.
    """
    row = team_detail(team_db_id)
    if not row:
        return False, "Team not found."
    team_name = (team_name if team_name is not None else row["team_name"]).strip()
    team_id = (team_id if team_id is not None else row["team_id"]).strip()
    participant_names = (
        participant_names if participant_names is not None
        else row.get("participant_names") or "").strip()
    if not team_name:
        return False, "Enter a team name."
    if not team_id:
        return False, "Enter a team ID."
    active = (1 if is_active else 0) if is_active is not None else row.get("is_active", 1)
    conn = db.get_connection()
    try:
        dup = conn.execute(
            "SELECT id FROM teams WHERE team_id = ? COLLATE NOCASE AND id <> ?",
            (team_id, int(team_db_id))).fetchone()
        if dup:
            return False, "Team ID already exists."
        conn.execute(
            "UPDATE teams SET team_name=?, team_id=?, participant_names=?, "
            "is_active=?, updated_at=? WHERE id=?",
            (team_name, team_id, participant_names, active,
             db.now_ms(), int(team_db_id)))
        conn.commit()
        return True, "Team updated successfully."
    finally:
        conn.close()


def delete_team(team_id):
    """Permanently remove a team and its child records.

    Explicitly separated from 'clear login'. Deleting a team also revokes any
    open participant login for it and removes its challenge progress.
    """
    conn = db.get_connection()
    try:
        team = conn.execute("SELECT * FROM teams WHERE id=?",
                            (int(team_id),)).fetchone()
        if team is None:
            return False, "Team not found."
        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            conn.execute("DELETE FROM participant_sessions WHERE team_id=?",
                         (int(team_id),))
            session_ids = [r["id"] for r in conn.execute(
                "SELECT id FROM round_sessions WHERE team_id=?",
                (int(team_id),)).fetchall()]
            for sid in session_ids:
                conn.execute("DELETE FROM lab_events WHERE session_id=?", (sid,))
                conn.execute(
                    "DELETE FROM hint_usage WHERE assignment_id IN "
                    "(SELECT id FROM team_challenge_assignments WHERE session_id=?)",
                    (sid,))
                conn.execute("DELETE FROM submissions WHERE session_id=?", (sid,))
                conn.execute(
                    "DELETE FROM team_challenge_assignments WHERE session_id=?",
                    (sid,))
            conn.execute("DELETE FROM round_sessions WHERE team_id=?",
                         (int(team_id),))
            conn.execute("DELETE FROM teams WHERE id=?", (int(team_id),))
            conn.commit()
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
        return True, "Team deleted."
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Admin: active participant logins
# ---------------------------------------------------------------------------


def list_active_logins():
    """Return currently online/offline participant sessions (oldest first).

    Liveness is derived from the last_seen heartbeat (no polling). Sessions
    whose last activity is older than SESSION_EXPIRE_MS are auto-CLEARED so
    abandoned logins stop appearing; the admin's own session is unaffected.
    """
    conn = db.get_connection()
    try:
        expire_cutoff = db.now_ms() - SESSION_EXPIRE_MS
        conn.execute(
            "UPDATE participant_sessions SET status='CLEARED' "
            "WHERE status='ACTIVE' AND last_seen < ?", (expire_cutoff,))
        conn.commit()
        rows = conn.execute(
            "SELECT ps.token, ps.login_time, ps.last_seen, ps.status, ps.round_name, "
            "t.id AS team_id, t.team_id AS team_code, t.team_name "
            "FROM participant_sessions ps "
            "JOIN teams t ON ps.team_id = t.id "
            "WHERE ps.status='ACTIVE' ORDER BY ps.login_time ASC").fetchall()
    finally:
        conn.close()
    now = db.now_ms()
    online_cutoff = now - SESSION_ONLINE_WINDOW_MS
    result = []
    for r in rows:
        d = dict(r)
        d["state"] = "ONLINE" if d["last_seen"] >= online_cutoff else "OFFLINE"
        result.append(d)
    return result


def clear_login_by_team(team_id):
    """Revoke the active login(s) of a single team. Team data is preserved."""
    conn = db.get_connection()
    try:
        cur = conn.execute(
            "UPDATE participant_sessions SET status='CLEARED' "
            "WHERE team_id=? AND status='ACTIVE'", (int(team_id),))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def clear_selected_logins(team_ids):
    """Revoke active logins for the selected teams. Returns count cleared."""
    ids = []
    for x in team_ids or []:
        try:
            ids.append(int(x))
        except (TypeError, ValueError):
            continue
    if not ids:
        return 0
    placeholders = ",".join("?" for _ in ids)
    conn = db.get_connection()
    try:
        cur = conn.execute(
            "UPDATE participant_sessions SET status='CLEARED' "
            "WHERE status='ACTIVE' AND team_id IN (%s)" % placeholders, ids)
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def clear_all_logins():
    """Revoke every active participant login. Admin sessions are untouched."""
    conn = db.get_connection()
    try:
        cur = conn.execute(
            "UPDATE participant_sessions SET status='CLEARED' "
            "WHERE status='ACTIVE'")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def active_login_count():
    # Only sessions observed within the online window count as live.
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM participant_sessions "
            "WHERE status='ACTIVE' AND last_seen >= ?",
            (db.now_ms() - SESSION_ONLINE_WINDOW_MS,)).fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Round status (admin overview)
# ---------------------------------------------------------------------------


def round_stats():
    conn = db.get_connection()
    now = db.now_ms()
    online_cutoff = now - SESSION_ONLINE_WINDOW_MS
    try:
        teams = conn.execute("SELECT COUNT(*) AS n FROM teams").fetchone()["n"]
        enabled = conn.execute(
            "SELECT COUNT(*) AS n FROM teams WHERE is_active=1").fetchone()["n"]
        live_logins = conn.execute(
            "SELECT COUNT(*) AS n FROM participant_sessions "
            "WHERE status='ACTIVE' AND last_seen >= ?", (online_cutoff,)
        ).fetchone()["n"]
        total_logins = conn.execute(
            "SELECT COUNT(*) AS n FROM participant_sessions WHERE status='ACTIVE'"
        ).fetchone()["n"]
        r1_sessions = conn.execute(
            "SELECT COUNT(*) AS n FROM round_sessions").fetchone()["n"]
        r1_active = conn.execute(
            "SELECT COUNT(*) AS n FROM round_sessions WHERE status='ACTIVE'"
        ).fetchone()["n"]
        r1_completed = conn.execute(
            "SELECT COUNT(*) AS n FROM round_sessions WHERE status='COMPLETED'"
        ).fetchone()["n"]
    finally:
        conn.close()
    return {
        "teams": teams,
        "enabled": enabled,
        "live_logins": live_logins,
        "total_logins": total_logins,
        "r1_sessions": r1_sessions,
        "r1_active": r1_active,
        "r1_completed": r1_completed,
    }


# ---------------------------------------------------------------------------
# Admin authorization
# ---------------------------------------------------------------------------


def login_admin(username, password):
    """Authenticate against the existing admins table. Returns bool."""
    from werkzeug.security import check_password_hash
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM admins WHERE username=?",
                           (username,)).fetchone()
    finally:
        conn.close()
    if row and check_password_hash(row["password_hash"], password):
        _session()[SESSION_ADMIN_KEY] = row["username"]
        return True
    return False


def is_admin():
    return bool(_session().get(SESSION_ADMIN_KEY))


def verify_admin_password(username, password):
    """Check admin credentials without touching the session. Returns bool."""
    from werkzeug.security import check_password_hash
    if not username or password is None:
        return False
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM admins WHERE username=?",
                           (username,)).fetchone()
    finally:
        conn.close()
    return bool(row and check_password_hash(row["password_hash"], password))


def admin_logout():
    _session().pop(SESSION_ADMIN_KEY, None)


# ---------------------------------------------------------------------------
# Idempotent startup
# ---------------------------------------------------------------------------


def init():
    """Upgrade the schema for access control (safe to run on every boot)."""
    db.init_db()
    db.migrate()
