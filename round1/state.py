"""Round 1 - serverless-friendly progress persistence layer.

Vercel serverless function instances do NOT share filesystem state.  Each
request may land on a different (cold) instance which gets a fresh copy of the
packaged SQLite DB, so anything a team writes (round session, challenge
assignment rows, submissions, lab events) is lost on the very next request.

To make every Round 1 button work on serverless deploys, the team's dynamic
progress is mirrored into the signed Flask session cookie (which the browser
always sends back).  The static challenge catalog (categories + variants) is
part of the packaged DB so it is always available.

All functions here go DB-first (so localhost/admin/leaderboard still see real
rows) and fall back to the cookie mirror when the DB row is missing.
"""
import json

import round1.db as db
import round1.lab as lab
from flask import session as flask_session

# Session-cookie key holding the compact R1 progress mirror.
STATE_KEY = "r1_state"


# ---------------------------------------------------------------------------
# Cookie mirror
# ---------------------------------------------------------------------------


def _load():
    return dict(flask_session.get(STATE_KEY) or {})


def _save(state):
    flask_session[STATE_KEY] = state


def _clear():
    flask_session.pop(STATE_KEY, None)


def _compact_session(row):
    row = dict(row)
    keep = ("id", "team_id", "round_name", "started_at", "ends_at",
            "completed_at", "status", "score", "challenges_solved")
    return {k: row.get(k) for k in keep}


def _compact_assignment(row):
    row = dict(row)
    keep = ("id", "session_id", "challenge_category_id", "variant_id",
            "display_order", "status", "started_at", "completed_at",
            "points_awarded", "lab_status", "lab_started_at",
            "lab_completed_at", "flag_revealed", "lab_attempts",
            "lab_submitted", "flag_attempts")
    compact = {k: row.get(k) for k in keep}
    # Row keys may be a.*-style (challenge_category_id / id) or library-style
    # (category_id / assignment_id). Normalise so the cookie always holds the
    # assignment id and the category id.
    compact["challenge_category_id"] = (
        row.get("challenge_category_id") or row.get("category_id"))
    compact["id"] = row.get("id") or row.get("assignment_id")
    return compact


# ---------------------------------------------------------------------------
# Reading state (DB first, cookie fallback)
# ---------------------------------------------------------------------------


def get_session(team_id):
    """Return the current active round_sessions row or None."""
    sess = _db_session(team_id)
    if sess is not None:
        return sess
    state = _load()
    sess = state.get("session")
    return dict(sess) if sess else None


def _db_session(team_id):
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM round_sessions WHERE team_id=? "
            "AND status NOT IN ('COMPLETED','EXPIRED') ORDER BY id DESC LIMIT 1",
            (team_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def mirror_session(session_row):
    """Persist the current active session row to the cookie mirror."""
    if session_row is None:
        return
    state = _load()
    state["session"] = _compact_session(session_row)
    _save(state)


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------


def _db_assignments(session_id, order_by_display=True):
    conn = db.get_connection()
    try:
        order = "ORDER BY a.display_order" if order_by_display else ""
        rows = conn.execute(
            "SELECT a.id AS assignment_id, a.display_order, a.status, "
            "a.started_at, a.completed_at, a.points_awarded, "
            "a.lab_status, a.lab_started_at, a.lab_completed_at, "
            "a.flag_revealed, a.lab_attempts, a.lab_submitted, "
            "c.id AS category_id, c.challenge_code, c.title, c.domain, "
            "c.description, c.points, "
            "v.id AS variant_id, v.variant_code, v.question, "
            "v.task_description, v.provided_data, v.difficulty, v.hint, "
            "v.lab_type, v.story, v.objective, v.lab_data, "
            "v.estimated_solve_time AS eta, v.explanation, v.hints "
            "FROM team_challenge_assignments a "
            "JOIN challenge_categories c ON a.challenge_category_id = c.id "
            "JOIN challenge_variants v ON a.variant_id = v.id "
            "WHERE a.session_id=? " + order,
            (session_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["lab_meta"] = lab.LAB_META.get(d.get("lab_type") or "", {})
            d["lab_payload"] = lab.sanitize_lab_data(
                lab.parse_lab_data(d.get("lab_data")))
            try:
                d["hints"] = json.loads(d["hints"]) if d.get("hints") else []
            except Exception:
                d["hints"] = []
            out.append(d)
        return out
    finally:
        conn.close()


def _build_assignment_from_cookie(compact, db_data):
    """Merge a compact cookie assignment with static DB challenge data."""
    if db_data is None:
        return None
    merged = dict(db_data)
    merged.update(compact)
    merged["lab_meta"] = lab.LAB_META.get(merged.get("lab_type") or "", {})
    merged["lab_payload"] = lab.sanitize_lab_data(
        lab.parse_lab_data(merged.get("lab_data")))
    try:
        merged["hints"] = json.loads(merged["hints"]) if merged.get("hints") else []
    except Exception:
        merged["hints"] = []
    if compact.get("id"):
        merged["id"] = compact["id"]
        merged.setdefault("assignment_id", compact["id"])
    if compact.get("challenge_category_id"):
        merged.setdefault("category_id", compact["challenge_category_id"])
    return merged


def _static_assignment(category_id, variant_id):
    """Fetch the static category+variant row for a compact cookie assignment."""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT c.id AS category_id, c.challenge_code, c.title, c.domain, "
            "c.description, c.points, "
            "v.id AS variant_id, v.variant_code, v.question, "
            "v.task_description, v.provided_data, v.difficulty, v.hint, "
            "v.lab_type, v.story, v.objective, v.lab_data, "
            "v.estimated_solve_time AS eta, v.explanation, v.hints, "
            "v.flag, v.expected_answer "
            "FROM challenge_categories c "
            "JOIN challenge_variants v ON v.id = ? "
            "WHERE c.id = ?",
            (variant_id, category_id)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_assignments(session_id):
    """Return all assignments for a session (DB first, cookie fallback)."""
    db_rows = _db_assignments(session_id)
    if db_rows:
        return db_rows
    state = _load()
    if state.get("session", {}).get("id") != session_id:
        return []
    out = []
    for compact in state.get("assignments", []):
        static = _static_assignment(compact.get("challenge_category_id"),
                                    compact.get("variant_id"))
        if static is None:
            continue
        merged = _build_assignment_from_cookie(compact, static)
        # Cookie compact uses "id" for the assignment id already.
        merged.setdefault("assignment_id", compact.get("id"))
        out.append(merged)
    return sorted(out, key=lambda a: a.get("display_order", 0))


def get_assignment(session_id, assignment_id, team_id):
    """Return a single assignment belonging to the team (or None)."""
    try:
        session_row = get_session(team_id)
    except Exception:
        session_row = None
    db_row = _db_assignment(session_id, assignment_id, team_id)
    if db_row is not None:
        return db_row
    # Cookie fallback.
    state = _load()
    if state.get("session", {}).get("id") != session_id:
        return None
    for compact in state.get("assignments", []):
        if compact.get("id") == assignment_id:
            static = _static_assignment(compact.get("challenge_category_id"),
                                        compact.get("variant_id"))
            return _build_assignment_from_cookie(compact, static)
    return None


def _db_assignment(session_id, assignment_id, team_id):
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT a.id AS assignment_id, a.display_order, a.status, "
            "a.started_at, a.completed_at, a.points_awarded, "
            "a.lab_status, a.lab_started_at, a.lab_completed_at, "
            "a.flag_revealed, a.lab_attempts, a.lab_submitted, "
            "c.id AS category_id, c.challenge_code, c.title, c.domain, "
            "c.description, c.points, "
            "v.id AS variant_id, v.variant_code, v.question, "
            "v.task_description, v.provided_data, v.difficulty, v.hint, "
            "v.lab_type, v.story, v.objective, v.lab_data, "
            "v.estimated_solve_time AS eta, v.explanation, v.hints "
            "FROM team_challenge_assignments a "
            "JOIN challenge_categories c ON a.challenge_category_id = c.id "
            "JOIN challenge_variants v ON a.variant_id = v.id "
            "WHERE a.id=? AND a.session_id=? AND a.session_id IN "
            "(SELECT id FROM round_sessions WHERE id=? AND team_id=?)",
            (assignment_id, session_id, session_id, team_id)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["lab_meta"] = lab.LAB_META.get(d.get("lab_type") or "", {})
        d["lab_payload"] = lab.sanitize_lab_data(lab.parse_lab_data(d["lab_data"]))
        try:
            d["hints"] = json.loads(d["hints"]) if d.get("hints") else []
        except Exception:
            d["hints"] = []
        return d
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Progress helpers (cookie-aware)
# ---------------------------------------------------------------------------


def get_completed_count(session_id):
    rows = get_assignments(session_id)
    return sum(1 for a in rows if a.get("status") == "COMPLETED")


def get_current_unlocked_id(session_id):
    """Lowest display_order assignment not completed and not attempt-locked."""
    max_attempts = 3
    try:
        import admin_ops
        max_attempts = int(admin_ops.get_round_settings("round1").get(
            "max_attempts") or 3)
    except Exception:
        max_attempts = 3
    for a in get_assignments(session_id):
        if a.get("status") == "COMPLETED":
            continue
        if int(a.get("lab_attempts") or 0) >= max_attempts:
            continue
        return a.get("id") or a.get("assignment_id")
    return None


def get_unlocked(session_id):
    """Return the currently unlocked assignment (rich view) or None."""
    unlocked_id = get_current_unlocked_id(session_id)
    if unlocked_id is None:
        return None
    for a in get_assignments(session_id):
        if (a.get("id") or a.get("assignment_id")) == unlocked_id:
            return a
    return None


def get_flag(assignment_id):
    """Return the variant flag for an assignment.

    Works even when the ephemeral team_challenge_assignments row is missing
    (serverless fallback) by resolving the variant from the cookie mirror.
    """
    variant_id = _variant_id_for(assignment_id)
    if variant_id is None:
        return ""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT flag FROM challenge_variants WHERE id=?", (variant_id,)
        ).fetchone()
        return row["flag"] if row else ""
    finally:
        conn.close()


def get_lab_answer(assignment_id):
    """Return the expected lab answer for an assignment (server-side only).

    Falls back to the cookie mirror when the assignment row is ephemeral.
    """
    variant_id = _variant_id_for(assignment_id)
    if variant_id is None:
        return ""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT expected_answer FROM challenge_variants WHERE id=?",
            (variant_id,)).fetchone()
        return row["expected_answer"] if row else ""
    finally:
        conn.close()


def _variant_id_for(assignment_id):
    """Resolve a variant_id from DB first, then the cookie mirror."""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT variant_id FROM team_challenge_assignments WHERE id=?",
            (assignment_id,)).fetchone()
        if row:
            return row["variant_id"]
    finally:
        conn.close()
    for a in (dict(flask_session.get(STATE_KEY) or {}).get("assignments") or []):
        if a.get("id") == assignment_id:
            return a.get("variant_id")
    return None


def get_submission_count(assignment_id):
    """Return the number of flag submissions for an assignment.

    DB-first, then cookie mirror (flag_attempts overrides / sums).
    """
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM submissions WHERE assignment_id=?",
            (assignment_id,)).fetchone()
        if row and row["n"]:
            return row["n"]
    finally:
        conn.close()
    for a in (dict(flask_session.get(STATE_KEY) or {}).get("assignments") or []):
        if a.get("id") == assignment_id:
            return int(a.get("flag_attempts") or 0)
    return 0


# ---------------------------------------------------------------------------
# Writes (DB + cookie mirror)
# ---------------------------------------------------------------------------


def remember_assignments(session_row, assignment_rows):
    """Store session + assignment rows into the cookie mirror."""
    state = _load()
    state["session"] = _compact_session(session_row)
    state["assignments"] = [_compact_assignment(a) for a in assignment_rows]
    _save(state)


def update_session_status(session_id, status, completed_at=None):
    """Update a round session's status in the DB (best effort) and cookie."""
    try:
        conn = db.get_connection()
        try:
            conn.execute(
                "UPDATE round_sessions SET status=?, completed_at=COALESCE(?, "
                "completed_at) WHERE id=?", (status, completed_at, session_id))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
    state = _load()
    if state.get("session", {}).get("id") == session_id:
        state["session"]["status"] = status
        if completed_at:
            state["session"]["completed_at"] = completed_at
        _save(state)


def update_assignment(assignment_id, **fields):
    """Update an assignment in the DB (if present) and cookie mirror."""
    allowed = ("status", "completed_at", "points_awarded", "lab_status",
               "lab_started_at", "lab_completed_at", "flag_revealed",
               "lab_attempts", "lab_submitted", "flag_attempts")
    updates = {k: v for k, v in fields.items() if k in allowed}
    # DB write (best effort).
    try:
        conn = db.get_connection()
        try:
            if updates:
                sets = ", ".join("%s=?" % k for k in updates)
                conn.execute(
                    "UPDATE team_challenge_assignments SET %s WHERE id=?" % sets,
                    list(updates.values()) + [assignment_id])
                conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
    # Cookie mirror.
    state = _load()
    assignments = state.get("assignments") or []
    for a in assignments:
        if a.get("id") == assignment_id:
            a.update(updates)
            break
    _save(state)


def clear():
    """Remove the cookie mirror (e.g. on logout / reset)."""
    _clear()