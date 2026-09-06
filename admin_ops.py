"""Admin Control Center domain operations.

Single module used by the Admin routes in app.py. Everything an administrator
can do from the control center is implemented here against the existing
SQLite database so the participant application consumes the exact same data
the admin manages.

No participant-facing code imports this module; these operations are
administrator-only and every route is gated server-side by access.is_admin().
"""
import csv
import io
import json
import os
import sqlite3
import time

import round1.db as db

# ---------------------------------------------------------------------------
# Round settings
# ---------------------------------------------------------------------------

DEFAULT_ROUND_SETTINGS = {
    "round1": {
        "round_name": "round1",
        "display_name": "MIXED FUNDAMENTALS",
        "description": "Cyber Puzzle technical challenges.",
        "status": "ACTIVE",
        "timer_minutes": 30,
        "max_attempts": 3,
        "scoring_mode": "AUTO",
        "access_enabled": 1,
    },
    "round2": {
        "round_name": "round2",
        "display_name": "DIGITAL FORENSICS",
        "description": "Cyber Detective investigation cases.",
        "status": "ACTIVE",
        "timer_minutes": 45,
        "max_attempts": 5,
        "scoring_mode": "AUTO",
        "access_enabled": 1,
    },
}

ROUND_STATUSES = ("DRAFT", "SCHEDULED", "ACTIVE", "PAUSED", "COMPLETED")


def get_round_settings(round_name):
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM round_settings WHERE round_name=?",
                           (round_name,)).fetchone()
    finally:
        conn.close()
    if row:
        return dict(row)
    defaults = dict(DEFAULT_ROUND_SETTINGS.get(round_name, {}))
    defaults["start_time"] = None
    defaults["end_time"] = None
    update_round_settings(round_name, defaults)
    return defaults


def update_round_settings(round_name, fields):
    """Persist editable round settings. Returns (ok, message)."""
    allowed = {
        "display_name", "description", "status", "start_time", "end_time",
        "timer_minutes", "max_attempts", "scoring_mode", "access_enabled",
    }
    current = get_round_settings(round_name)
    updates = {k: v for k, v in (fields or {}).items() if k in allowed}
    if "status" in updates and updates["status"] not in ROUND_STATUSES:
        return False, "Invalid round status."
    if "scoring_mode" in updates and updates["scoring_mode"] not in ("AUTO", "MANUAL"):
        return False, "Invalid scoring mode."
    for key, val in updates.items():
        current[key] = val
    try:
        conn = db.get_connection()
        cur = conn.execute(
            "UPDATE round_settings SET display_name=?, description=?, status=?, "
            "start_time=?, end_time=?, timer_minutes=?, max_attempts=?, "
            "scoring_mode=?, access_enabled=?, updated_at=? WHERE round_name=?",
            (current["display_name"], current["description"], current["status"],
             current.get("start_time"), current.get("end_time"),
             int(current.get("timer_minutes") or 0),
             int(current.get("max_attempts") or 0),
             current["scoring_mode"],
             1 if current.get("access_enabled", 1) else 0,
             db.now_ms(), round_name))
        if cur.rowcount == 0:
            conn.execute(
                "INSERT OR REPLACE INTO round_settings "
                "(round_name, display_name, description, status, start_time, end_time, "
                "timer_minutes, max_attempts, scoring_mode, access_enabled, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (round_name, current["display_name"], current["description"],
                 current["status"], current.get("start_time"), current.get("end_time"),
                 int(current.get("timer_minutes") or 0),
                 int(current.get("max_attempts") or 0),
                 current["scoring_mode"],
                 1 if current.get("access_enabled", 1) else 0, db.now_ms()))
        conn.commit()
    finally:
        conn.close()
    return True, "Round settings saved."


def round_open(round_name):
    """True when the round is ACTIVE (or SCHEDULED) and access is enabled."""
    s = get_round_settings(round_name)
    return bool(s.get("access_enabled", 1)) and s.get("status") in ("ACTIVE", "SCHEDULED")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def audit(admin_user, action, target="", detail="", result="OK"):
    conn = db.get_connection()
    try:
        conn.execute(
            "INSERT INTO admin_audit_log (admin_user, action, target, detail, result, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (admin_user, action, target or "", detail or "", result, db.now_ms()))
        conn.commit()
    finally:
        conn.close()


def list_audit(limit=200):
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM admin_audit_log ORDER BY id DESC LIMIT ?",
            (int(limit),)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Team access helpers
# ---------------------------------------------------------------------------

def list_teams_for_round(round_name):
    """All teams with round-scoped access fields + live session state.

    round_name is 'round1' or 'round2'. Completely separate views for each
    round (Round 1 access never affects Round 2 and vice-versa).
    """
    now = db.now_ms()
    online_cutoff = now - access_window_ms()
    round_label = "Round 1" if round_name == "round1" else "Round 2"
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT t.id, t.team_id, t.team_name, t.participant_names, t.is_active, "
            "t.round1_access_id, t.round2_access_id, "
            "t.round1_enabled, t.round2_enabled, t.created_at, t.updated_at, "
            "(SELECT COUNT(*) FROM participant_sessions ps "
            "  WHERE ps.team_id=t.id AND ps.round_name=? AND ps.status='ACTIVE' "
            "  AND ps.last_seen >= ?) AS online_sessions, "
            "(SELECT COUNT(*) FROM participant_sessions ps "
            "  WHERE ps.team_id=t.id AND ps.round_name=? AND ps.status='ACTIVE') "
            "AS active_sessions, "
            "(SELECT ps.login_time FROM participant_sessions ps "
            "  WHERE ps.team_id=t.id AND ps.round_name=? AND ps.status='ACTIVE' "
            "  ORDER BY ps.login_time DESC LIMIT 1) AS last_login "
            "FROM teams t ORDER BY t.team_name COLLATE NOCASE",
            (round_name, online_cutoff, round_name, round_name)).fetchall()
    finally:
        conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["login_enabled"] = bool(d.get(round_name + "_enabled", 0) and d.get("is_active", 0))
        d["access_id"] = d.get(round_name + "_access_id", "")
        d["credential_id"] = d.get(round_name + "_access_id", "")
        d["round_label"] = round_label
        result.append(d)
    return result


def access_window_ms():
    import access
    return access.SESSION_ONLINE_WINDOW_MS


def set_round_access(team_id, round_name, enabled):
    """Enable/disable a team's login for a single round."""
    col = round_name + "_enabled"
    conn = db.get_connection()
    try:
        cur = conn.execute(
            "UPDATE teams SET %s=?, updated_at=? WHERE id=?" % col,
            (1 if enabled else 0, db.now_ms(), int(team_id)))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def set_round_access_id(team_id, round_name, access_id):
    """Set/rotate the dedicated access ID for one round (unique check)."""
    col = round_name + "_access_id"
    access_id = (access_id or "").strip()
    if not access_id:
        return False, "Access ID is required."
    if round_name == "round1" and col == "round1_access_id":
        # Round 1 keeps team_id as its identity; also keep in sync.
        pass
    conn = db.get_connection()
    try:
        dup = conn.execute(
            "SELECT id FROM teams WHERE %s=? COLLATE NOCASE AND id<>?" % col,
            (access_id, int(team_id))).fetchone()
        if dup:
            return False, "That ID is already assigned to another team."
        conn.execute(
            "UPDATE teams SET %s=?, updated_at=? WHERE id=?" % col,
            (access_id, db.now_ms(), int(team_id)))
        conn.commit()
        return True, "Access ID updated."
    finally:
        conn.close()


def create_round2_team(team_name, access_id):
    """Enroll a team in Round 2, creating a Round 2-only team if needed.

    Existing teams are looked up by normalized name. A brand-new team is
    created with Round 1 intentionally disabled (their Round 2 ID must not
    unlock Round 1). Round 2 Access IDs are unique.
    """
    team_name = (team_name or "").strip()
    access_id = (access_id or "").strip()
    if not team_name or not access_id:
        return False, "Team name and Round 2 ID are required."
    target = " ".join(team_name.split()).lower()
    conn = db.get_connection()
    try:
        rows = conn.execute("SELECT * FROM teams").fetchall()
        team = next((dict(r) for r in rows
                     if " ".join((r["team_name"] or "").split()).lower() == target),
                    None)
        if team:
            if team.get("round2_enabled"):
                return False, "'%s' is already enrolled in Round 2." % team_name
            dup = conn.execute(
                "SELECT id FROM teams WHERE round2_access_id=? COLLATE NOCASE AND id<>?",
                (access_id, team["id"])).fetchone()
            if dup:
                return False, "That Round 2 ID is already assigned to another team."
            conn.execute(
                "UPDATE teams SET round2_access_id=?, round2_enabled=1, updated_at=? WHERE id=?",
                (access_id, db.now_ms(), team["id"]))
            conn.commit()
            return True, ""
        dup = conn.execute(
            "SELECT id FROM teams WHERE team_id=? COLLATE NOCASE OR "
            "round2_access_id=? COLLATE NOCASE", (access_id, access_id)).fetchone()
        if dup:
            return False, "That Round 2 ID already exists."
        now = db.now_ms()
        conn.execute(
            "INSERT INTO teams (team_id, team_name, participant_names, created_at, updated_at, "
            "round1_access_id, round2_access_id, round1_enabled, round2_enabled) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (access_id, team_name, "", now, now, access_id, access_id, 0, 1))
        conn.commit()
        return True, ""
    finally:
        conn.close()


def clear_round_logins(team_id, round_name=None):
    """Revoke active participant logins for a team (optionally per round)."""
    conn = db.get_connection()
    try:
        if round_name:
            cur = conn.execute(
                "UPDATE participant_sessions SET status='CLEARED' "
                "WHERE team_id=? AND round_name=? AND status='ACTIVE'",
                (int(team_id), round_name))
        else:
            cur = conn.execute(
                "UPDATE participant_sessions SET status='CLEARED' "
                "WHERE team_id=? AND status='ACTIVE'", (int(team_id),))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def clear_selected_round_logins(team_ids, round_name=None):
    ids = [int(x) for x in (team_ids or []) if str(x).isdigit()]
    if not ids:
        return 0
    placeholders = ",".join("?" for _ in ids)
    conn = db.get_connection()
    try:
        sql = "UPDATE participant_sessions SET status='CLEARED' WHERE status='ACTIVE' AND team_id IN (%s)" % placeholders
        if round_name:
            sql += " AND round_name=?"
            cur = conn.execute(sql, ids + [round_name])
        else:
            cur = conn.execute(sql, ids)
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def clear_all_round_logins(round_name=None):
    conn = db.get_connection()
    try:
        if round_name:
            cur = conn.execute(
                "UPDATE participant_sessions SET status='CLEARED' "
                "WHERE status='ACTIVE' AND round_name=?", (round_name,))
        else:
            cur = conn.execute(
                "UPDATE participant_sessions SET status='CLEARED' WHERE status='ACTIVE'")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def reset_team_round_progress(team_id, round_name):
    """Reset a single team's competition progress for one round ONLY.

    Round 1: deletes/archives that team's Round 1 sessions, assignments,
    submissions, hints and lab events. Round 2 progress currently lives in
    the participant's in-memory session, which is cleared on next login, so
    we only clear the login tracking row and return.

    Never touches team access, content, or the other round's data.
    """
    conn = db.get_connection()
    try:
        if round_name == "round1":
            session_ids = [r["id"] for r in conn.execute(
                "SELECT id FROM round_sessions WHERE team_id=?", (int(team_id),)).fetchall()]
            for sid in session_ids:
                conn.execute("DELETE FROM lab_events WHERE session_id=?", (sid,))
                conn.execute(
                    "DELETE FROM hint_usage WHERE assignment_id IN "
                    "(SELECT id FROM team_challenge_assignments WHERE session_id=?)",
                    (sid,))
                conn.execute("DELETE FROM submissions WHERE session_id=?", (sid,))
                conn.execute(
                    "DELETE FROM team_challenge_assignments WHERE session_id=?", (sid,))
            conn.execute("DELETE FROM round_sessions WHERE team_id=?", (int(team_id),))
        # Clear any active login row for the round so the participant must
        # re-authenticate, and in-memory Round 2 state starts fresh.
        conn.execute(
            "UPDATE participant_sessions SET status='CLEARED' "
            "WHERE team_id=? AND round_name=? AND status='ACTIVE'",
            (int(team_id), round_name))
        conn.commit()
        return True
    finally:
        conn.close()


def team_profile(team_id):
    """Everything an admin needs on the team profile page."""
    conn = db.get_connection()
    try:
        team_row = conn.execute("SELECT * FROM teams WHERE id=?", (int(team_id),)).fetchone()
        if team_row is None:
            return None
        team = dict(team_row)
        login_history = [dict(r) for r in conn.execute(
            "SELECT ps.login_time, ps.last_seen, ps.status, ps.round_name, ps.case_code "
            "FROM participant_sessions ps WHERE ps.team_id=? "
            "ORDER BY ps.login_time DESC LIMIT 30", (int(team_id),)).fetchall()]
        r1_sessions = [dict(r) for r in conn.execute(
            "SELECT id, started_at, ends_at, completed_at, status, score, challenges_solved "
            "FROM round_sessions WHERE team_id=? ORDER BY id DESC LIMIT 20",
            (int(team_id),)).fetchall()]
        r1_assignments = [dict(r) for r in conn.execute(
            "SELECT a.id, a.session_id, a.display_order, a.status, a.points_awarded, "
            "a.lab_status, a.lab_attempts, a.flag_revealed, c.challenge_code, c.title, "
            "v.variant_code, "
            "(SELECT COUNT(*) FROM submissions s WHERE s.assignment_id=a.id AND s.is_correct=1) AS solves, "
            "(SELECT COUNT(*) FROM submissions s WHERE s.assignment_id=a.id) AS attempts "
            "FROM team_challenge_assignments a "
            "JOIN challenge_categories c ON a.challenge_category_id=c.id "
            "JOIN challenge_variants v ON a.variant_id=v.id "
            "WHERE a.session_id IN (SELECT id FROM round_sessions WHERE team_id=?) "
            "ORDER BY a.display_order DESC LIMIT 60", (int(team_id),)).fetchall()]
    finally:
        conn.close()
    return {
        "team": team,
        "login_history": login_history,
        "r1_sessions": r1_sessions,
        "r1_assignments": r1_assignments,
    }


# ---------------------------------------------------------------------------
# Round 1 content (challenge categories + question bank variants)
# ---------------------------------------------------------------------------

def list_r1_challenges():
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT c.*, "
            "(SELECT COUNT(*) FROM challenge_variants v WHERE v.challenge_category_id=c.id) AS variants, "
            "(SELECT COUNT(*) FROM team_challenge_assignments a "
            "  JOIN challenge_variants v ON a.variant_id=v.id WHERE v.challenge_category_id=c.id) AS assigned "
            "FROM challenge_categories c ORDER BY c.display_order, c.id").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def get_r1_challenge(cat_id):
    """Single challenge with variant + assignment counts (for edit prefill)."""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT c.*, "
            "(SELECT COUNT(*) FROM challenge_variants v WHERE v.challenge_category_id=c.id) AS variants, "
            "(SELECT COUNT(*) FROM team_challenge_assignments a "
            "  JOIN challenge_variants v ON a.variant_id=v.id WHERE v.challenge_category_id=c.id) AS assigned "
            "FROM challenge_categories c WHERE c.id=?", (int(cat_id),)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def create_r1_challenge(fields):
    title = (fields.get("title") or "").strip()
    domain = (fields.get("domain") or "WEB").strip()
    difficulty = (fields.get("difficulty") or "MEDIUM").strip()
    if not title:
        return False, "Title is required."
    code = (fields.get("challenge_code") or title).upper().strip()
    code = re_nonword(code)
    conn = db.get_connection()
    try:
        existing = conn.execute(
            "SELECT id FROM challenge_categories WHERE challenge_code=? COLLATE NOCASE",
            (code,)).fetchone()
        if existing:
            return False, "Challenge code already exists."
        order = int(fields.get("display_order") or _next_order(conn, "challenge_categories") or 0)
        now = db.now_ms()
        conn.execute(
            "INSERT INTO challenge_categories (challenge_code, title, domain, description, "
            "difficulty, points, active, display_order) VALUES (?,?,?,?,?,?,?,?)",
            (code, title, domain, (fields.get("description") or "").strip(),
             difficulty, int(fields.get("points") or 100),
             1 if _settings_bool(fields.get("active"), default=True) else 0, order))
        conn.commit()
        cat_id = conn.execute("SELECT id FROM challenge_categories WHERE challenge_code=?",
                              (code,)).fetchone()["id"]
    finally:
        conn.close()
    create_r1_variant(cat_id, {
        "question": fields.get("question") or "",
        "task_description": fields.get("task_description") or "",
        "provided_data": fields.get("provided_data") or "",
        "expected_answer": fields.get("expected_answer") or "",
        "flag": fields.get("flag") or "",
        "hint": fields.get("hint") or "",
        "difficulty": difficulty,
        "title": title,
    })
    return True, "Challenge created."


def re_nonword(code):
    import re
    code = re.sub(r"[^a-zA-Z0-9_-]+", "_", code)
    return code or "CHALLENGE"


def _settings_bool(value, default=None):
    """Interpret an admin-panel boolean value; returns default when absent."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _next_order(conn, table):
    row = conn.execute("SELECT COALESCE(MAX(display_order), 0) + 1 AS n FROM %s" % table).fetchone()
    return row["n"]


def update_r1_challenge(cat_id, fields):
    allowed = ("challenge_code", "title", "domain", "description", "difficulty",
               "points", "active", "display_order", "status")
    conn = db.get_connection()
    try:
        existing = conn.execute("SELECT * FROM challenge_categories WHERE id=?",
                                (int(cat_id),)).fetchone()
        if existing is None:
            return False, "Challenge not found."
        current = dict(existing)
        for k in allowed:
            if k in fields and fields[k] is not None:
                current[k] = fields[k]
        code = re_nonword(str(current.get("challenge_code") or current.get("title") or "CH"))
        dup = conn.execute(
            "SELECT id FROM challenge_categories WHERE challenge_code=? COLLATE NOCASE AND id<>?",
            (code, int(cat_id))).fetchone()
        if dup:
            return False, "Challenge code already exists."
        conn.execute(
            "UPDATE challenge_categories SET challenge_code=?, title=?, domain=?, description=?, "
            "difficulty=?, points=?, active=?, display_order=? WHERE id=?",
            (code, current["title"], current["domain"], current["description"],
             current["difficulty"], int(current["points"] or 0),
             1 if current.get("active", 1) else 0,
             int(current.get("display_order") or 0), int(cat_id)))
        conn.commit()
        return True, "Challenge updated."
    finally:
        conn.close()


def set_r1_challenge_status(cat_id, active):
    conn = db.get_connection()
    try:
        conn.execute("UPDATE challenge_categories SET active=? WHERE id=?",
                     (1 if active else 0, int(cat_id)))
        conn.commit()
        return True
    finally:
        conn.close()


def delete_or_archive_r1_challenge(cat_id):
    """Archive before hard-delete if the challenge has any participant activity."""
    conn = db.get_connection()
    try:
        used = conn.execute(
            "SELECT COUNT(*) AS n FROM team_challenge_assignments a "
            "JOIN challenge_variants v ON a.variant_id=v.id "
            "WHERE v.challenge_category_id=?", (int(cat_id),)).fetchone()["n"]
        if used:
            conn.execute("UPDATE challenge_categories SET active=0 WHERE id=?",
                         (int(cat_id),))
            conn.commit()
            return "archived"
        conn.execute("DELETE FROM challenge_variants WHERE challenge_category_id=?", (int(cat_id),))
        conn.execute("DELETE FROM challenge_categories WHERE id=?", (int(cat_id),))
        conn.commit()
        return "deleted"
    finally:
        conn.close()


def reorder_r1_challenge(cat_id, direction):
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM challenge_categories WHERE id=?", (int(cat_id),)).fetchone()
        if row is None:
            return False
        cur_order = row["display_order"]
        _swap_order(conn, "challenge_categories", int(cat_id), cur_order, direction)
        return True
    finally:
        conn.close()


def list_r1_variants(filter_cat=None):
    conn = db.get_connection()
    try:
        sql = ("SELECT v.*, c.challenge_code, c.title AS category_title, c.points AS category_points "
               "FROM challenge_variants v "
               "JOIN challenge_categories c ON v.challenge_category_id=c.id")
        args = []
        if filter_cat:
            sql += " WHERE v.challenge_category_id=?"
            args = [int(filter_cat)]
        sql += " ORDER BY c.display_order, v.display_order, v.id"
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def create_r1_variant(cat_id, fields):
    question = (fields.get("question") or "").strip()
    if not question:
        return False, "Question is required."
    conn = db.get_connection()
    try:
        cat = conn.execute("SELECT * FROM challenge_categories WHERE id=?",
                           (int(cat_id),)).fetchone()
        if cat is None:
            return False, "Challenge not found."
        order = _next_order(conn, "challenge_variants")
        code = "V%d" % order
        now = db.now_ms()
        conn.execute(
            "INSERT INTO challenge_variants (challenge_category_id, variant_code, title, question, "
            "task_description, provided_data, expected_answer, flag, difficulty, hint, "
            "explanation, estimated_solve_time, lab_type, story, objective, lab_data, hints, "
            "mediabanner, status, validation_mode, display_order) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (int(cat_id), code, (fields.get("title") or cat["title"]), question,
             (fields.get("task_description") or "").strip(),
             (fields.get("provided_data") or "").strip(),
             (fields.get("expected_answer") or "").strip(),
             (fields.get("flag") or (fields.get("expected_answer") or "")).strip(),
             fields.get("difficulty") or cat["difficulty"],
             (fields.get("hint") or "").strip(), "", "",
             fields.get("lab_type") or "brief", "", "", "{}", "[]", "",
             "PUBLISHED", fields.get("validation_mode") or "NORMALIZED", order))
        conn.commit()
        return True, "Question created."
    except sqlite3.IntegrityError as e:
        conn.close()
        return False, "Duplicate variant code: %s" % e
    finally:
        conn.close()


def update_r1_variant(variant_id, fields):
    allowed = ("title", "question", "task_description", "provided_data",
               "expected_answer", "flag", "hint", "explanation", "difficulty",
               "points", "status", "validation_mode", "display_order")
    conn = db.get_connection()
    try:
        current_row = conn.execute("SELECT * FROM challenge_variants WHERE id=?",
                                   (int(variant_id),)).fetchone()
        if current_row is None:
            return False, "Question not found."
        current = dict(current_row)
        for k in allowed:
            if k in fields and fields[k] is not None:
                current[k] = fields[k]
        conn.execute(
            "UPDATE challenge_variants SET title=?, question=?, task_description=?, "
            "provided_data=?, expected_answer=?, flag=?, hint=?, explanation=?, "
            "difficulty=?, status=?, validation_mode=?, display_order=? WHERE id=?",
            (current.get("title") or "", current.get("question") or "",
             current.get("task_description") or "", current.get("provided_data") or "",
             current.get("expected_answer") or "", current.get("flag") or "",
             current.get("hint") or "", current.get("explanation") or "",
             current.get("difficulty") or "MEDIUM",
             current.get("status") or "PUBLISHED",
             current.get("validation_mode") or "NORMALIZED",
             int(current.get("display_order") or 0), int(variant_id)))
        conn.commit()
        return True, "Question updated."
    finally:
        conn.close()


def delete_r1_variant(variant_id):
    conn = db.get_connection()
    try:
        used = conn.execute(
            "SELECT COUNT(*) AS n FROM team_challenge_assignments WHERE variant_id=?",
            (int(variant_id),)).fetchone()["n"]
        if used:
            conn.execute("UPDATE challenge_variants SET status='ARCHIVED' WHERE id=?",
                         (int(variant_id),))
            conn.commit()
            return "archived"
        conn.execute("DELETE FROM challenge_variants WHERE id=?", (int(variant_id),))
        conn.commit()
        return "deleted"
    finally:
        conn.close()


def set_r1_variant_status(variant_id, status):
    conn = db.get_connection()
    try:
        conn.execute("UPDATE challenge_variants SET status=? WHERE id=?",
                     (status, int(variant_id)))
        conn.commit()
        return True
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Round 2 content
# ---------------------------------------------------------------------------

EVIDENCE_TYPES = (
    "DISK IMAGE", "SYSTEM LOG", "NETWORK LOG", "PCAP", "MEMORY IMAGE", "EMAIL",
    "BROWSER ARTIFACT", "FILE", "METADATA", "TIMELINE", "REGISTRY",
    "PROCESS DATA", "OTHER",
)

STATION_STATUSES = ("DRAFT", "PUBLISHED", "ARCHIVED")
CASE_STATUSES = ("DRAFT", "PUBLISHED", "ARCHIVED")


def _infer_evidence_type(filename):
    ext = (filename or "").rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    mapping = {
        "eml": "EMAIL", "msg": "EMAIL", "pcap": "PCAP", "pcapng": "PCAP",
        "zip": "FILE", "docx": "METADATA", "txt": "FILE", "log": "SYSTEM LOG",
        "dmp": "MEMORY IMAGE", "raw": "DISK IMAGE", "csv": "SYSTEM LOG",
    }
    return mapping.get(ext, "OTHER")


def seed_r2_cases(cases_dict):
    """Idempotently import the legacy in-memory Round 2 cases into the DB.

    Only seeds when a case (or its stations/persons/evidence) is still empty,
    so administrator edits are never clobbered on a later restart.
    """
    conn = db.get_connection()
    try:
        for code, case in cases_dict.items():
            row = conn.execute("SELECT id FROM r2_cases WHERE case_code=?",
                               (code,)).fetchone()
            now = db.now_ms()
            if row is None:
                cur = conn.execute(
                    "INSERT INTO r2_cases (case_code, title, case_type, description, "
                    "objective, case_brief, company, difficulty, time_limit, points, "
                    "status, display_order, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (code, case.get("code", code.upper()), case.get("title", code),
                     "SIMULATED CYBERCRIME", case.get("objective", ""),
                     case.get("incident", ""), case.get("company", ""), "MEDIUM",
                     60, 100, "PUBLISHED", int(code.replace("case", "")), now, now))
                case_id = cur.lastrowid
            else:
                case_id = row["id"]
            if conn.execute("SELECT COUNT(*) AS n FROM r2_stations WHERE case_id=?",
                            (case_id,)).fetchone()["n"] == 0:
                for i, st in enumerate(case.get("stations", []), start=1):
                    conn.execute(
                        "INSERT INTO r2_stations (case_id, station_id, name, domain, "
                        "description, evidence, question, answer, hint, points, "
                        "max_attempts, validation_mode, display_order, status, "
                        "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (case_id, st.get("id", "S%d" % i), st.get("name", ""),
                         st.get("domain", ""), st.get("desc", ""), st.get("evidence", ""),
                         st.get("question", ""), st.get("flag", ""), st.get("hint", ""),
                         100, 5, "NORMALIZED", i, "PUBLISHED", now, now))
            if conn.execute("SELECT COUNT(*) AS n FROM r2_persons WHERE case_id=?",
                            (case_id,)).fetchone()["n"] == 0:
                for i, p in enumerate(case.get("persons", []), start=1):
                    conn.execute(
                        "INSERT INTO r2_persons (case_id, role, person_key, answers, "
                        "clue, display_order) VALUES (?,?,?,?,?,?)",
                        (case_id, p.get("role", ""), p.get("key", "person%d" % i),
                         json.dumps([str(a) for a in (p.get("answer") or [])]),
                         p.get("clue", ""), i))
            if conn.execute("SELECT COUNT(*) AS n FROM r2_evidence WHERE case_id=?",
                            (case_id,)).fetchone()["n"] == 0:
                seen = set()
                for i, st in enumerate(case.get("stations", []), start=1):
                    fname = st.get("evidence", "")
                    if not fname or fname in seen:
                        continue
                    seen.add(fname)
                    conn.execute(
                        "INSERT INTO r2_evidence (case_id, evidence_code, name, "
                        "evidence_type, description, filename, file_hash, file_size, "
                        "display_order, status, created_at, updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (case_id, "EDG-%03d" % i, fname, _infer_evidence_type(fname),
                         st.get("desc", ""), fname, "", 0, i, "PUBLISHED", now, now))
        conn.commit()
    finally:
        conn.close()

def list_r2_cases(include_archived=True):
    conn = db.get_connection()
    try:
        sql = ("SELECT c.*, "
               "(SELECT COUNT(*) FROM r2_stations s WHERE s.case_id=c.id) AS station_count, "
               "(SELECT COUNT(*) FROM r2_evidence e WHERE e.case_id=c.id) AS evidence_count, "
               "(SELECT COUNT(*) FROM r2_persons p WHERE p.case_id=c.id) AS person_count "
               "FROM r2_cases c")
        if not include_archived:
            sql += " WHERE c.status != 'ARCHIVED'"
        sql += " ORDER BY c.display_order, c.id"
        rows = conn.execute(sql).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def create_round2_case(fields):
    title = (fields.get("title") or "").strip()
    if not title:
        return False, "Case title is required."
    code = (fields.get("case_code") or "CASE-" + str(int(time.time()) % 1000000)).strip()
    conn = db.get_connection()
    try:
        dup = conn.execute("SELECT id FROM r2_cases WHERE case_code=? COLLATE NOCASE",
                           (code,)).fetchone()
        if dup:
            return False, "Case code already exists."
        order = _next_order(conn, "r2_cases")
        now = db.now_ms()
        conn.execute(
            "INSERT INTO r2_cases (case_code, title, case_type, description, objective, "
            "case_brief, company, difficulty, time_limit, points, status, display_order, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (code, title, fields.get("case_type") or "SIMULATED CYBERCRIME",
             (fields.get("description") or "").strip(),
             (fields.get("objective") or "").strip(),
             (fields.get("case_brief") or "").strip(),
             (fields.get("company") or "").strip(),
             fields.get("difficulty") or "MEDIUM",
             int(fields.get("time_limit") or 60),
             int(fields.get("points") or 100),
             fields.get("status") or "DRAFT", order, now, now))
        conn.commit()
        return True, "Case created."
    finally:
        conn.close()


def update_round2_case(case_id, fields):
    allowed = ("case_code", "title", "case_type", "description", "objective",
               "case_brief", "company", "difficulty", "time_limit", "points",
               "status", "display_order")
    conn = db.get_connection()
    try:
        cur_row = conn.execute("SELECT * FROM r2_cases WHERE id=?", (int(case_id),)).fetchone()
        if cur_row is None:
            return False, "Case not found."
        current = dict(cur_row)
        for k in allowed:
            if k in fields and fields[k] is not None:
                current[k] = fields[k]
        dup = conn.execute(
            "SELECT id FROM r2_cases WHERE case_code=? COLLATE NOCASE AND id<>?",
            (str(current["case_code"]).strip(), int(case_id))).fetchone()
        if dup:
            return False, "Case code already exists."
        conn.execute(
            "UPDATE r2_cases SET case_code=?, title=?, case_type=?, description=?, "
            "objective=?, case_brief=?, company=?, difficulty=?, time_limit=?, "
            "points=?, status=?, display_order=?, updated_at=? WHERE id=?",
            (str(current["case_code"]).strip(), current["title"], current["case_type"],
             current["description"], current["objective"], current["case_brief"],
             current["company"], current["difficulty"], int(current["time_limit"] or 0),
             int(current["points"] or 0), current["status"],
             int(current.get("display_order") or 0), db.now_ms(), int(case_id)))
        conn.commit()
        return True, "Case updated."
    finally:
        conn.close()


def delete_round2_case(case_id):
    conn = db.get_connection()
    try:
        used = conn.execute(
            "SELECT COUNT(*) AS n FROM participant_sessions WHERE case_code IN "
            "(SELECT case_code FROM r2_cases WHERE id=?)",
            (int(case_id),)).fetchone()["n"]
        if used:
            conn.execute("UPDATE r2_cases SET status='ARCHIVED' WHERE id=?",
                         (int(case_id),))
            conn.commit()
            return "archived"
        conn.execute("DELETE FROM r2_persons WHERE case_id=?", (int(case_id),))
        conn.execute("DELETE FROM r2_stations WHERE case_id=?", (int(case_id),))
        conn.execute("DELETE FROM r2_evidence WHERE case_id=?", (int(case_id),))
        conn.execute("DELETE FROM r2_cases WHERE id=?", (int(case_id),))
        conn.commit()
        return "deleted"
    finally:
        conn.close()


def get_round2_case(case_id):
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM r2_cases WHERE id=?", (int(case_id),)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_round2_case_by_code(case_code):
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM r2_cases WHERE case_code=? COLLATE NOCASE",
                           (case_code,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def r2_person_count(case_id):
    return stat_count("SELECT COUNT(*) AS n FROM r2_persons WHERE case_id=?",
                      (int(case_id),))


def list_r2_stations(case_id):
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM r2_stations WHERE case_id=? ORDER BY display_order, id",
            (int(case_id),)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def list_r2_persons(case_id):
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM r2_persons WHERE case_id=? ORDER BY display_order, id",
            (int(case_id),)).fetchall()
    finally:
        conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["answers"] = _parse_json_list(d.get("answers"))
        result.append(d)
    return result


def create_r2_station(case_id, fields):
    name = (fields.get("name") or "").strip()
    if not name:
        return False, "Task name is required."
    conn = db.get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) AS n FROM r2_stations WHERE case_id=?",
                             (int(case_id),)).fetchone()["n"]
        station_id = fields.get("station_id") or ("S%d" % (count + 1))
        dup = conn.execute(
            "SELECT id FROM r2_stations WHERE case_id=? AND station_id=? COLLATE NOCASE",
            (int(case_id), str(station_id))).fetchone()
        if dup:
            return False, "Station id already exists for this case."
        order = int(fields.get("display_order") or (count + 1))
        now = db.now_ms()
        conn.execute(
            "INSERT INTO r2_stations (case_id, station_id, name, domain, description, "
            "evidence, question, answer, hint, points, max_attempts, validation_mode, "
            "display_order, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (int(case_id), str(station_id), name, (fields.get("domain") or "").strip(),
             (fields.get("description") or "").strip(),
             (fields.get("evidence") or "").strip(),
             (fields.get("question") or "").strip(),
             (fields.get("answer") or "").strip(),
             (fields.get("hint") or "").strip(),
             int(fields.get("points") or 100),
             int(fields.get("max_attempts") or 5),
             fields.get("validation_mode") or "NORMALIZED",
             order, fields.get("status") or "DRAFT", now, now))
        conn.commit()
        return True, "Task created."
    finally:
        conn.close()


def update_r2_station(station_id, fields):
    allowed = ("station_id", "name", "domain", "description", "evidence", "question",
               "answer", "hint", "points", "max_attempts", "validation_mode",
               "display_order", "status")
    conn = db.get_connection()
    try:
        cur_row = conn.execute("SELECT * FROM r2_stations WHERE id=?",
                               (int(station_id),)).fetchone()
        if cur_row is None:
            return False, "Task not found."
        current = dict(cur_row)
        for k in allowed:
            if k in fields and fields[k] is not None:
                current[k] = fields[k]
        conn.execute(
            "UPDATE r2_stations SET station_id=?, name=?, domain=?, description=?, "
            "evidence=?, question=?, answer=?, hint=?, points=?, max_attempts=?, "
            "validation_mode=?, display_order=?, status=?, updated_at=? WHERE id=?",
            (str(current["station_id"]), current["name"], current["domain"],
             current["description"], current["evidence"], current["question"],
             current["answer"], current["hint"], int(current["points"] or 0),
             int(current["max_attempts"] or 5), current["validation_mode"],
             int(current.get("display_order") or 0), current["status"],
             db.now_ms(), int(station_id)))
        conn.commit()
        return True, "Task updated."
    finally:
        conn.close()


def delete_r2_station(station_id):
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM r2_stations WHERE id=?", (int(station_id),))
        conn.commit()
        return True
    finally:
        conn.close()


def set_r2_station_status(station_id, status):
    conn = db.get_connection()
    try:
        conn.execute("UPDATE r2_stations SET status=? WHERE id=?", (status, int(station_id)))
        conn.commit()
        return True
    finally:
        conn.close()


def create_r2_person(case_id, fields):
    role = (fields.get("role") or "").strip()
    person_key = (fields.get("person_key") or re_nonword(role or "person")).strip()
    if not role:
        return False, "Role is required."
    conn = db.get_connection()
    try:
        dup = conn.execute(
            "SELECT id FROM r2_persons WHERE case_id=? AND person_key=? COLLATE NOCASE",
            (int(case_id), person_key)).fetchone()
        if dup:
            return False, "Person key already exists."
        order = _next_order(conn, "r2_persons")
        now = db.now_ms()
        conn.execute(
            "INSERT INTO r2_persons (case_id, role, person_key, answers, clue, display_order) "
            "VALUES (?,?,?,?,?,?)",
            (int(case_id), role, person_key,
             json.dumps(fields.get("answers") or []),
             (fields.get("clue") or "").strip(), order))
        conn.commit()
        return True, "Person added."
    finally:
        conn.close()


def update_r2_person(person_id, fields):
    conn = db.get_connection()
    try:
        cur_row = conn.execute("SELECT * FROM r2_persons WHERE id=?", (int(person_id),)).fetchone()
        if cur_row is None:
            return False, "Person not found."
        current = dict(cur_row)
        for k in ("role", "person_key", "clue", "display_order"):
            if k in fields and fields[k] is not None:
                current[k] = fields[k]
        if "answers" in fields and fields["answers"] is not None:
            current["answers"] = json.dumps(fields["answers"])
        conn.execute(
            "UPDATE r2_persons SET role=?, person_key=?, answers=?, clue=?, display_order=? "
            "WHERE id=?",
            (current["role"], current["person_key"], current["answers"],
             current["clue"], int(current.get("display_order") or 0), int(person_id)))
        conn.commit()
        return True, "Person updated."
    finally:
        conn.close()


def delete_r2_person(person_id):
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM r2_persons WHERE id=?", (int(person_id),))
        conn.commit()
        return True
    finally:
        conn.close()


def list_r2_evidence(case_id=None):
    conn = db.get_connection()
    try:
        sql = ("SELECT e.*, c.case_code, c.title AS case_title "
               "FROM r2_evidence e JOIN r2_cases c ON e.case_id=c.id")
        args = []
        if case_id:
            sql += " WHERE e.case_id=?"
            args = [int(case_id)]
        sql += " ORDER BY e.display_order, e.id"
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def create_r2_evidence(case_id, fields):
    name = (fields.get("name") or "").strip()
    if not name:
        return False, "Evidence name is required."
    conn = db.get_connection()
    try:
        order = _next_order(conn, "r2_evidence")
        code = fields.get("evidence_code") or ("EDG-%03d" % order)
        now = db.now_ms()
        conn.execute(
            "INSERT INTO r2_evidence (case_id, evidence_code, name, evidence_type, "
            "description, filename, file_hash, file_size, display_order, status, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (int(case_id), code, name,
             fields.get("evidence_type") or "OTHER",
             (fields.get("description") or "").strip(),
             (fields.get("filename") or "").strip(),
             (fields.get("file_hash") or "").strip(),
             int(fields.get("file_size") or 0),
             order, fields.get("status") or "DRAFT", now, now))
        conn.commit()
        return True, "Evidence added."
    finally:
        conn.close()


def update_r2_evidence(evidence_id, fields):
    allowed = ("evidence_code", "name", "evidence_type", "description", "filename",
               "file_hash", "file_size", "display_order", "status")
    conn = db.get_connection()
    try:
        cur_row = conn.execute("SELECT * FROM r2_evidence WHERE id=?",
                               (int(evidence_id),)).fetchone()
        if cur_row is None:
            return False, "Evidence not found."
        current = dict(cur_row)
        for k in allowed:
            if k in fields and fields[k] is not None:
                current[k] = fields[k]
        conn.execute(
            "UPDATE r2_evidence SET evidence_code=?, name=?, evidence_type=?, description=?, "
            "filename=?, file_hash=?, file_size=?, display_order=?, status=?, updated_at=? "
            "WHERE id=?",
            (str(current["evidence_code"] or ""), current["name"], current["evidence_type"],
             current["description"], current["filename"], current["file_hash"] or "",
             int(current["file_size"] or 0), int(current.get("display_order") or 0),
             current["status"], db.now_ms(), int(evidence_id)))
        conn.commit()
        return True, "Evidence updated."
    finally:
        conn.close()


def delete_r2_evidence(evidence_id):
    conn = db.get_connection()
    try:
        conn.execute("DELETE FROM r2_evidence WHERE id=?", (int(evidence_id),))
        conn.commit()
        return True
    finally:
        conn.close()


def get_round2_stats():
    conn = db.get_connection()
    try:
        cases = conn.execute("SELECT COUNT(*) AS n FROM r2_cases").fetchone()["n"]
        published_cases = conn.execute(
            "SELECT COUNT(*) AS n FROM r2_cases WHERE status='PUBLISHED'").fetchone()["n"]
        evidence = conn.execute("SELECT COUNT(*) AS n FROM r2_evidence").fetchone()["n"]
        stations = conn.execute("SELECT COUNT(*) AS n FROM r2_stations").fetchone()["n"]
        persons = conn.execute("SELECT COUNT(*) AS n FROM r2_persons").fetchone()["n"]
    finally:
        conn.close()
    return {
        "cases": cases,
        "published_cases": published_cases,
        "evidence": evidence,
        "stations": stations,
        "persons": persons,
    }


# ---------------------------------------------------------------------------
# Live monitoring / dashboard
# ---------------------------------------------------------------------------

def list_submissions(limit=200):
    """Recent Round 1 answer submissions joined with team + challenge labels."""
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT s.id, s.submitted_answer, s.is_correct, s.submitted_at, "
            "s.attempt_number, t.team_name, c.id AS category_id, "
            "c.title AS item, v.variant_code, c.challenge_code "
            "FROM submissions s "
            "JOIN round_sessions rs ON s.session_id=rs.id "
            "JOIN teams t ON rs.team_id=t.id "
            "JOIN team_challenge_assignments a ON s.assignment_id=a.id "
            "JOIN challenge_categories c ON a.challenge_category_id=c.id "
            "JOIN challenge_variants v ON a.variant_id=v.id "
            "ORDER BY s.id DESC LIMIT ?", (int(limit),)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def leaderboard(limit=50):
    """Best Round 1 score per team. Round 2 scoring lives in participant
    sessions, so its column is intentionally blank until persisted."""
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT t.id AS team_id, t.team_name, "
            "MAX(rs.score) AS r1_score, MAX(rs.challenges_solved) AS r1_solved, "
            "MAX(rs.completed_at) AS r1_done, "
            "(SELECT COUNT(*) FROM participant_sessions ps "
            "  WHERE ps.team_id=t.id AND ps.round_name='round2' AND ps.status='ACTIVE') "
            "AS r2_sessions "
            "FROM round_sessions rs JOIN teams t ON rs.team_id=t.id "
            "GROUP BY t.id "
            "ORDER BY r1_score DESC, r1_solved DESC LIMIT ?", (int(limit),)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def save_r2_progress(team_db_id, case_code, data):
    """Upsert a team's Round 2 score card (written from the participant /score)."""
    conn = db.get_connection()
    try:
        conn.execute(
            "INSERT INTO r2_progress (team_id, case_code, station_points, person_points, "
            "report_points, total, verified_stations, verified_persons, report_done, "
            "completed_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(team_id) DO UPDATE SET case_code=excluded.case_code, "
            "station_points=excluded.station_points, person_points=excluded.person_points, "
            "report_points=excluded.report_points, total=excluded.total, "
            "verified_stations=excluded.verified_stations, "
            "verified_persons=excluded.verified_persons, report_done=excluded.report_done, "
            "completed_at=excluded.completed_at, updated_at=excluded.updated_at",
            (int(team_db_id), case_code or "", int(data.get("station_points") or 0),
             int(data.get("person_points") or 0), int(data.get("report_points") or 0),
             int(data.get("total") or 0), int(data.get("verified_stations") or 0),
             int(data.get("verified_persons") or 0), 1 if data.get("report_done") else 0,
             data.get("completed_at"), db.now_ms()))
        conn.commit()
    finally:
        conn.close()


def r2_leaderboard(limit=50):
    """Round 2 rankings from persisted r2_progress score cards."""
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT t.id AS team_id, t.team_name, "
            "COALESCE(p.case_code, '') AS case_code, "
            "COALESCE(c.title, '') AS case_title, "
            "COALESCE(p.total, 0) AS total, "
            "COALESCE(p.station_points, 0) AS station_points, "
            "COALESCE(p.person_points, 0) AS person_points, "
            "COALESCE(p.report_points, 0) AS report_points, "
            "COALESCE(p.verified_stations, 0) AS verified_stations, "
            "COALESCE(p.verified_persons, 0) AS verified_persons, "
            "COALESCE(p.report_done, 0) AS report_done, "
            "COALESCE(p.completed_at, 0) AS completed_at "
            "FROM r2_progress p JOIN teams t ON p.team_id=t.id "
            "LEFT JOIN r2_cases c ON c.case_code=p.case_code "
            "ORDER BY p.total DESC, p.updated_at ASC LIMIT ?", (int(limit),)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def list_r2_reviews():
    """Teams currently on a Round 2 case, ready for report review."""
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT t.id AS team_id, t.team_name, ps.case_code, "
            "COALESCE(c.title, '') AS case_title, COALESCE(c.status, '') AS case_status "
            "FROM teams t "
            "JOIN participant_sessions ps ON ps.team_id=t.id "
            "  AND ps.round_name='round2' AND ps.status='ACTIVE' "
            "LEFT JOIN r2_cases c ON c.case_code=ps.case_code "
            "ORDER BY ps.last_seen DESC").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def live_monitoring():
    """Active participant sessions enriched with Round 1 progress details."""
    import access
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT ps.token, ps.round_name, ps.login_time, ps.last_seen, ps.case_code, "
        "t.id AS team_id, t.team_id AS team_code, t.team_name "
        "FROM participant_sessions ps JOIN teams t ON ps.team_id=t.id "
        "WHERE ps.status='ACTIVE' ORDER BY ps.last_seen DESC").fetchall()
    result = []
    online_cutoff = db.now_ms() - access.SESSION_ONLINE_WINDOW_MS
    for r in rows:
        d = dict(r)
        d["state"] = "ONLINE" if d["last_seen"] >= online_cutoff else "OFFLINE"
        if d["round_name"] == "round1":
            sess = conn.execute(
                "SELECT score, challenges_solved, status FROM round_sessions "
                "WHERE team_id=? ORDER BY id DESC LIMIT 1",
                (d["team_id"],)).fetchone()
            d["score"] = sess["score"] if sess else None
            d["progress"] = "%d / 6" % (sess["challenges_solved"] if sess else 0)
            d["session_status"] = sess["status"] if sess else "NO_SESSION"
            d["current"] = ""
            if sess and sess["status"] == "ACTIVE":
                cur = conn.execute(
                    "SELECT c.title, a.display_order FROM team_challenge_assignments a "
                    "JOIN challenge_categories c ON a.challenge_category_id=c.id "
                    "WHERE a.session_id=(SELECT id FROM round_sessions WHERE team_id=? "
                    "ORDER BY id DESC LIMIT 1) AND a.status='IN_PROGRESS' "
                    "ORDER BY a.display_order LIMIT 1",
                    (d["team_id"],)).fetchone()
                d["current"] = cur["title"] if cur else ""
            d["case"] = "—"
        else:
            d["score"] = None
            d["progress"] = "—"
            d["session_status"] = "ACTIVE"
            d["current"] = ""
            d["case"] = d.get("case_code") or "—"
        result.append(d)
    conn.close()
    return result


def dashboard_stats():
    """High-level statistics for the Admin overview page (no hardcoding)."""
    import access
    now = db.now_ms()
    online_cutoff = now - access.SESSION_ONLINE_WINDOW_MS
    stats = dict(access.round_stats())
    stats["r1_teams"] = stat_count("SELECT COUNT(*) AS n FROM teams WHERE round1_enabled=1")
    stats["r2_teams"] = stat_count("SELECT COUNT(*) AS n FROM teams WHERE round2_enabled=1")
    stats["active_participants"] = stat_count(
        "SELECT COUNT(*) AS n FROM participant_sessions WHERE status='ACTIVE' AND last_seen>=?",
        (online_cutoff,))
    stats["round2_logins"] = stat_count(
        "SELECT COUNT(*) AS n FROM participant_sessions WHERE round_name='round2' AND status='ACTIVE'")
    stats["round2_settings"] = get_round_settings("round2")
    stats["round1_settings"] = get_round_settings("round1")
    stats["submissions"] = stat_count("SELECT COUNT(*) AS n FROM submissions")
    stats["correct_submissions"] = stat_count(
        "SELECT COUNT(*) AS n FROM submissions WHERE is_correct=1")
    stats["round2"] = get_round2_stats()
    return stats


def stat_count(sql, args=()):
    conn = db.get_connection()
    try:
        row = conn.execute(sql, args).fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


def recent_activity(limit=8):
    """Mix of admin audit events + participant lab events for the dashboard."""
    conn = db.get_connection()
    try:
        audit_rows = conn.execute(
            "SELECT admin_user, action, target, detail, created_at FROM admin_audit_log "
            "ORDER BY id DESC LIMIT %d" % limit).fetchall()
        lab_rows = conn.execute(
            "SELECT e.kind, e.detail, e.occurred_at, t.team_name FROM lab_events e "
            "JOIN round_sessions s ON e.session_id=s.id "
            "JOIN teams t ON s.team_id=t.id "
            "ORDER BY e.id DESC LIMIT %d" % limit).fetchall()
        login_rows = conn.execute(
            "SELECT ps.login_time, t.team_name, ps.round_name, ps.case_code "
            "FROM participant_sessions ps JOIN teams t ON ps.team_id=t.id "
            "ORDER BY ps.login_time DESC LIMIT %d" % limit).fetchall()
    finally:
        conn.close()
    items = []
    for r in audit_rows:
        items.append({"text": "ADMIN • %s %s %s" % (r["admin_user"], r["action"], r["target"] or ""),
                      "time": r["created_at"]})
    for r in lab_rows:
        items.append({"text": "%s %s" % (r["team_name"], _describe_lab_event(r["kind"], r["detail"])),
                      "time": r["occurred_at"]})
    for r in login_rows:
        items.append({"text": "%s logged into %s%s" % (
            r["team_name"], "Round 1" if r["round_name"] == "round1" else "Round 2",
            " (" + (r["case_code"] or "") + ")" if r["case_code"] else ""),
            "time": r["login_time"]})
    items.sort(key=lambda x: x["time"], reverse=True)
    return items[:limit]


def _describe_lab_event(kind, detail):
    mapping = {
        "lab_opened": "opened a lab",
        "lab_attempt": "submitted a lab answer (incorrect)" if detail else "submitted a lab answer",
        "lab_completed": "completed a lab",
        "flag_revealed": "revealed a flag",
        "flag_submitted": "submitted a flag (%s)" % ("correct" if detail == "correct" else ""),
    }
    return mapping.get(kind, kind)


# ---------------------------------------------------------------------------
# Import / export teams (CSV)
# ---------------------------------------------------------------------------

def import_teams(csv_text, round_name):
    """Import admin-authorized teams from CSV.

    Expected columns (header row optional): team_name, access_id.
    Every row is validated; duplicate / invalid rows are reported instead of
    corrupting the database.
    """
    csv_text = (csv_text or "").strip()
    if not csv_text:
        return {"imported": 0, "failed": 0, "duplicate": 0, "invalid": 0, "errors": []}
    reader = csv.reader(io.StringIO(csv_text))
    imported = failed = duplicate = invalid = 0
    errors = []
    seen = set()
    for lineno, row in enumerate(reader, start=1):
        if not row or not any(cell.strip() for cell in row):
            continue
        cells = [c.strip() for c in row]
        if lineno == 1 and cells[0].lower() in ("team name", "team_name", "team") and \
                len(cells) > 1 and cells[1].lower() in ("team id", "team_id", "access id", "access_id", "id"):
            continue
        team_name = cells[0] if cells else ""
        access_id = cells[1] if len(cells) > 1 else ""
        if not team_name or not access_id:
            invalid += 1
            errors.append("Row %d: missing team name or access ID" % lineno)
            continue
        key = (team_name.lower(), access_id.lower())
        if key in seen:
            duplicate += 1
            errors.append("Row %d: duplicate row (%s)" % (lineno, team_name))
            continue
        seen.add(key)
        ok, msg = _import_one_team(team_name, access_id, round_name)
        if ok:
            imported += 1
        elif "already exists" in msg.lower():
            duplicate += 1
            errors.append("Row %d: %s" % (lineno, msg))
        else:
            failed += 1
            errors.append("Row %d: %s" % (lineno, msg))
    return {"imported": imported, "failed": failed, "duplicate": duplicate,
            "invalid": invalid, "errors": errors}


def _import_one_team(team_name, access_id, round_name):
    conn = db.get_connection()
    try:
        if round_name == "round1":
            dup = conn.execute(
                "SELECT id FROM teams WHERE team_id=? COLLATE NOCASE OR "
                "round1_access_id=? COLLATE NOCASE", (access_id, access_id)).fetchone()
            if dup:
                return False, "Team ID already exists."
            now = db.now_ms()
            conn.execute(
                "INSERT INTO teams (team_id, team_name, participant_names, created_at, "
                "updated_at, round1_access_id, round2_access_id, round1_enabled, round2_enabled) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (access_id, team_name, "", now, now, access_id, access_id, 1, 0))
            conn.commit()
            return True, "ok"
        dup = conn.execute(
            "SELECT id FROM teams WHERE round2_access_id=? COLLATE NOCASE",
            (access_id,)).fetchone()
        if dup:
            return False, "Round 2 access ID already exists."
        rows = conn.execute("SELECT * FROM teams").fetchall()
        team = next((dict(r) for r in rows if " ".join((r["team_name"] or "").split()).lower()
                     == " ".join(team_name.split()).lower()), None)
        if team is None:
            # Auto-create the team with both credential slots to keep the
            # two-round model consistent (Round 1 disabled by default).
            now = db.now_ms()
            conn.execute(
                "INSERT INTO teams (team_id, team_name, participant_names, created_at, "
                "updated_at, round1_access_id, round2_access_id, round1_enabled, round2_enabled) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (access_id, team_name, "", now, now, access_id, access_id, 0, 1))
            conn.commit()
            return True, "ok"
        dup2 = conn.execute(
            "SELECT id FROM teams WHERE round2_access_id=? COLLATE NOCASE AND id<>?",
            (access_id, team["id"])).fetchone()
        if dup2:
            return False, "Round 2 access ID already exists."
        conn.execute(
            "UPDATE teams SET round2_access_id=?, round2_enabled=1, updated_at=? WHERE id=?",
            (access_id, db.now_ms(), team["id"]))
        conn.commit()
        return True, "ok"
    finally:
        conn.close()


def export_teams(round_name):
    """CSV rows for a round's authorized teams."""
    conn = db.get_connection()
    try:
        rows = conn.execute("SELECT * FROM teams ORDER BY team_name COLLATE NOCASE").fetchall()
    finally:
        conn.close()
    columns = ["team_name", "access_id", "login_enabled", "is_active"]
    lines = [",".join(columns)]
    for r in rows:
        d = dict(r)
        if round_name == "round1":
            access_id = d.get("round1_access_id") or d.get("team_id") or ""
            enabled = d.get("round1_enabled", 0)
        else:
            access_id = d.get("round2_access_id") or d.get("team_id") or ""
            enabled = d.get("round2_enabled", 0)
        lines.append(",".join(_csv_escape(x) for x in [
            d.get("team_name", ""), access_id, "ENABLED" if enabled else "DISABLED",
            "ENABLED" if d.get("is_active", 1) else "DISABLED"]))
    return "\n".join(lines) + "\n"


def _csv_escape(v):
    v = "" if v is None else str(v)
    if any(ch in v for ch in ',"\n\r'):
        return '"' + v.replace('"', '""') + '"'
    return v


# ---------------------------------------------------------------------------
# Reordering helpers
# ---------------------------------------------------------------------------

def reorder_item(table, item_id, direction):
    """Swap display_order with the previous/next row in a given table."""
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM %s WHERE id=?" % table, (int(item_id),)).fetchone()
        if row is None:
            return False
        cur = row["display_order"]
        return _swap_order(conn, table, int(item_id), cur, direction)
    finally:
        conn.close()


def _swap_order(conn, table, item_id, cur_order, direction):
    if direction == "up":
        other = conn.execute(
            "SELECT id, display_order FROM %s WHERE display_order < ? "
            "ORDER BY display_order DESC LIMIT 1" % table, (cur_order,)).fetchone()
    else:
        other = conn.execute(
            "SELECT id, display_order FROM %s WHERE display_order > ? "
            "ORDER BY display_order ASC LIMIT 1" % table, (cur_order,)).fetchone()
    if other is None:
        conn.commit()
        return True
    conn.execute("UPDATE %s SET display_order=? WHERE id=?" % table,
                 (other["display_order"], item_id))
    conn.execute("UPDATE %s SET display_order=? WHERE id=?" % table,
                 (cur_order, other["id"]))
    conn.commit()
    return True


def _parse_json_list(value):
    if isinstance(value, list):
        return value
    try:
        return json.loads(value or "[]")
    except Exception:
        return []


# ---------------------------------------------------------------------------
# System settings (currently exposed: stats only; import/export handled above)
# ---------------------------------------------------------------------------

def system_stats():
    stat = {}
    stat["total_teams"] = stat_count("SELECT COUNT(*) AS n FROM teams")
    stat["total_sessions"] = stat_count("SELECT COUNT(*) AS n FROM round_sessions")
    stat["total_submissions"] = stat_count("SELECT COUNT(*) AS n FROM submissions")
    stat["audit_entries"] = stat_count("SELECT COUNT(*) AS n FROM admin_audit_log")
    stat["round1_categories"] = stat_count("SELECT COUNT(*) AS n FROM challenge_categories")
    stat["round1_variants"] = stat_count("SELECT COUNT(*) AS n FROM challenge_variants")
    stat["round2_cases"] = stat_count("SELECT COUNT(*) AS n FROM r2_cases")
    stat["date"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return stat