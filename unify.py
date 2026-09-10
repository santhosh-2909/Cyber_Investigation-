"""Unified single-link project helpers.

Bridges Round 1 (Cyber Puzzle, backed by round1.db) and Round 2
(Cyber Detective, in-memory session) so a team signs in ONCE from a single
landing page and moves through Round 1 -> Round 2 sequentially.

Authorization for the unified participant session is enforced by
`access.validate_participant()` (server-side token against the
participant_sessions table). These helpers only read presentation state.

Session keys:
    'team'     -> Round 2 team dict (existing)
    'r1_team'  -> Round 1 team row id (existing)
    'r1_profile'-> cached Round 1 team_name/team_id for the hub header
"""
import access
import round1.db as db
import round1.assign as assign
from flask import session


def get_round1_profile():
    """Return a small dict describing the Round 1 team (or None)."""
    if not access.is_logged_in():
        return None
    team_id = session.get("r1_team")
    if not team_id:
        return None
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT * FROM teams WHERE id=?", (int(team_id),)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {"id": row["id"], "team_id": row["team_id"], "team_name": row["team_name"]}


def get_round1_session():
    """Return the team's active round1 session dict (resumed), or None."""
    profile = get_round1_profile()
    if profile is None:
        return None
    sess = assign.get_session_by_team(profile["id"])
    if sess is None:
        return None
    # Re-evaluate expiry
    if sess["status"] == "ACTIVE" and sess["ends_at"] <= db.now_ms():
        conn = db.get_connection()
        try:
            conn.execute("UPDATE round_sessions SET status='EXPIRED' WHERE id=?", (sess["id"],))
            conn.commit()
        finally:
            conn.close()
        sess["status"] = "EXPIRED"
    return sess


def round1_stage():
    """Return the team's Round 1 stage: 'not_started'|'in_progress'|'complete'."""
    profile = get_round1_profile()
    if profile is None:
        return "not_started"
    sess = get_round1_session()
    if sess is None:
        # maybe they finished/expired previously
        conn = db.get_connection()
        try:
            done = conn.execute(
                "SELECT status FROM round_sessions WHERE team_id=? "
                "ORDER BY id DESC LIMIT 1", (profile["id"],)).fetchone()
        finally:
            conn.close()
        if done and done["status"] in ("COMPLETED", "EXPIRED"):
            return "complete"
        return "not_started"
    if sess["status"] == "ACTIVE":
        return "in_progress"
    if sess["status"] in ("COMPLETED", "EXPIRED"):
        return "complete"
    return "not_started"


def round2_ready():
    """Round 2 is always open — no longer gated behind Round 1 completion."""
    return True


def is_round2_logged_in():
    return access.is_logged_in()


def is_logged_in():
    return access.is_logged_in()