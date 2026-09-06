"""Round 1 - Cyber Puzzle: Mixed Fundamentals - web routes.

Blueprints mounted under the /r1 URL prefix. All timers, scoring, validation,
and randomization are enforced server-side. Flags and expected answers are
never exposed to client templates.
"""
from functools import wraps

from flask import (Blueprint, abort, jsonify, redirect, render_template,
                   request, session, url_for, Response)
from werkzeug.security import check_password_hash

import access
import admin_ops
import round1.db as db
import round1.assign as assign
import round1.lab as lab

# A distinct session key for the Round 1 team so it never collides with
# Round 2's session keys.
SESSION_TEAM_KEY = "r1_team"
SESSION_ADMIN_KEY = "r1_admin"
# Distinct session flag tracking whether the participant acknowledged the
# Round 1 Rules & Regulations popup on the registration page.
RULES_ACK_KEY = "r1_rules_ack"

# Rate-limit for submissions: N attempts per window
SUBMIT_LIMIT = 15
SUBMIT_WINDOW_MS = 60 * 1000

r1 = Blueprint("r1", __name__, template_folder="templates",
               url_prefix="")


# ---------------------------------------------------------------------------
# Helpers / decorators
# ---------------------------------------------------------------------------

def get_current_team():
    """Return the current authorized Round 1 team dict or None.

    Authorization is delegated to access.validate_participant() so an admin-
    revoked or disabled team cannot access the round even with a stale cookie.
    """
    return access.validate_participant("round1")


def max_attempts():
    """Round 1 max lab/challenge attempts from admin round settings."""
    settings = admin_ops.get_round_settings("round1")
    return int(settings.get("max_attempts") or assign.MAX_LAB_ATTEMPTS)


def login_required_team(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        team = get_current_team()
        if team is None:
            return redirect(url_for("r1.r1_landing"))
        kwargs["team"] = team
        return view(*args, **kwargs)
    return wrapped


def login_required_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get(SESSION_ADMIN_KEY):
            return redirect(url_for("r1.r1_admin_login"))
        return view(*args, **kwargs)
    return wrapped


def _rate_limit_exceeded(team_id):
    """Return True if the team exceeded the submission rate limit."""
    conn = db.get_connection()
    try:
        window_start = db.now_ms() - SUBMIT_WINDOW_MS
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM submissions sub "
            "JOIN round_sessions s ON sub.session_id = s.id "
            "WHERE s.team_id=? AND sub.submitted_at >= ?",
            (team_id, window_start),
        ).fetchone()
        return (row["n"] if row else 0) >= SUBMIT_LIMIT
    finally:
        conn.close()


def _mark_expired(session_row):
    """If the session has passed its deadline, flip it to COMPLETED."""
    if session_row["status"] == "ACTIVE" and session_row["ends_at"] <= db.now_ms():
        conn = db.get_connection()
        try:
            conn.execute("UPDATE round_sessions SET status='COMPLETED', completed_at=? WHERE id=?",
                         (db.now_ms(), session_row["id"]))
            conn.commit()
            session_row["status"] = "COMPLETED"
            session_row["completed_at"] = db.now_ms()
        finally:
            conn.close()
    return session_row


def _get_session_row(session_id, team_id):
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM round_sessions WHERE id=? AND team_id=?",
            (session_id, team_id),
        ).fetchone()
        conn.execute("SELECT 1")  # keep connection fresh
        return row
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------

@r1.route("/r1")
def r1_landing():
    """Legacy URL only: avoid a duplicate Round 1 entry page.

    `/r1` previously showed the separate "Mixed Fundamentals" landing. The
    public home now owns round selection, so this URL goes directly to the
    correct next action instead of rendering a second landing screen.
    """
    if get_current_team() is not None:
        return redirect(url_for("r1.r1_dashboard"))
    return redirect(url_for("r1.r1_login"))


@r1.route("/r1/rules")
def r1_rules():
    return render_template("r1_rules.html", team=get_current_team())


@r1.route("/r1/register", methods=["GET", "POST"])
def r1_register():
    # Registration is administratively controlled: teams are provisioned by
    # the event admin, so this route no longer creates accounts. GET sends the
    # participant to the unified team login; POST validates the credentials.
    if request.method == "POST":
        team_name = request.form.get("team_name", "").strip()
        team_id_input = request.form.get("team_id", "").strip()
        ok, error = access.participant_login(team_name, team_id_input, "round1")
        if not ok:
            return render_template(
                "r1_register.html",
                error=error,
                team=None,
                rules_ack=session.get(RULES_ACK_KEY, False))
        session[RULES_ACK_KEY] = True
        return redirect(url_for("r1.r1_dashboard"))
    return redirect(url_for("start"))


@r1.route("/r1/register/rules-ack", methods=["POST"])
def r1_register_rules_ack():
    """Record that the participant acknowledged the Round 1 Rules popup.

    Uses the existing Flask session (no page reload / form reset). After the
    team acknowledges, the popup will not reappear on subsequent visits.
    """
    session[RULES_ACK_KEY] = True
    return jsonify({"ok": True})


@r1.route("/r1/login", methods=["GET", "POST"])
def r1_login():
    if request.method == "POST":
        team_name = request.form.get("team_name", "").strip()
        team_id_input = request.form.get("team_id", "").strip()
        # Login is only permitted for admin-authorized teams.
        ok, error = access.participant_login(team_name, team_id_input, "round1")
        if not ok:
            return render_template("r1_login.html", error=error, team=None)
        return redirect(url_for("r1.r1_dashboard"))
    return render_template("r1_login.html", error=access.pop_login_notice(),
                           team=None)


@r1.route("/r1/logout")
def r1_logout():
    access.participant_logout()
    return redirect(url_for("landing"))


# ---------------------------------------------------------------------------
# Dashboard / start / challenges
# ---------------------------------------------------------------------------

@r1.route("/r1/start", methods=["POST"])
@login_required_team
def r1_start(team):
    conn = db.get_connection()
    try:
        # existing active session?
        existing = assign.get_session_by_team(team["id"])
        if existing and existing["status"] == "ACTIVE":
            return redirect(url_for("r1.r1_dashboard"))
        # finished previously?
        finished = conn.execute(
            "SELECT * FROM round_sessions WHERE team_id=? AND status IN "
            "('COMPLETED','EXPIRED') ORDER BY id DESC LIMIT 1",
            (team["id"],)).fetchone()
        if finished:
            finished = _mark_expired(finished)
            if finished["status"] in ("COMPLETED", "EXPIRED"):
                return redirect(url_for("r1.r1_complete",
                                        session_id=finished["id"]))
        # create fresh assignment
        sess = assign.create_assignment(team["id"])
        return redirect(url_for("r1.r1_dashboard"))
    finally:
        conn.close()


@r1.route("/r1/dashboard")
@login_required_team
def r1_dashboard(team):
    session_row = _get_session_row_from_team(team)
    if session_row is None:
        # No active session: if the team already finished (COMPLETED/EXPIRED),
        # take them to the completion state rather than a fresh start screen.
        finished = _get_finished_session(team["id"])
        if finished:
            return redirect(url_for("r1.r1_complete", session_id=finished["id"]))
        return render_template("r1_dashboard.html", team=team, session_row=None,
                               unlocked=None)
    if session_row["status"] in ("COMPLETED", "EXPIRED"):
        return redirect(url_for("r1.r1_complete", session_id=session_row["id"]))
    session_row["remaining_ms"] = session_row["ends_at"] - db.now_ms()
    unlocked = assign.get_unlocked_assignment(session_row["id"])
    completed = assign.get_completed_count(session_row["id"])
    # Real mission-log events for the participant HUD (visual only; nothing
    # answer-revealing or future-challenge-revealing is exposed).
    connm = db.get_connection()
    try:
        events = connm.execute(
            "SELECT kind, detail, occurred_at, assignment_id FROM lab_events "
            "WHERE session_id=? ORDER BY occurred_at DESC LIMIT 12",
            (session_row["id"],)).fetchall()
    finally:
        connm.close()
    if unlocked is None:
        # All 6 solved but session not yet marked COMPLETED -> close it out.
        conn = db.get_connection()
        try:
            conn.execute(
                "UPDATE round_sessions SET status='COMPLETED', completed_at=? "
                "WHERE id=? AND status='ACTIVE'",
                (db.now_ms(), session_row["id"]))
            conn.commit()
        finally:
            conn.close()
        session_row["status"] = "COMPLETED"
        return redirect(url_for("r1.r1_complete", session_id=session_row["id"]))
    return render_template("r1_dashboard.html", team=team,
                           session_row=session_row, unlocked=unlocked,
                           completed=completed, events=[dict(r) for r in events])


def _get_session_row_from_team(team):
    sess = assign.get_session_by_team(team["id"])
    if sess is None:
        return None
    sess = _mark_expired(sess)
    return sess


def _get_finished_session(team_id):
    """Return the team's most recent COMPLETED/EXPIRED session, if any.

    Falls back so a finished round routes to the completion page instead of a
    fresh-start screen after all challenges are solved.
    """
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM round_sessions WHERE team_id=? "
            "AND status IN ('COMPLETED','EXPIRED') ORDER BY id DESC LIMIT 1",
            (team_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _get_assignment(session_id, assignment_id, team_id):
    """Return the assignment owned by a session (IDOR-safe)."""
    return assign.get_assignment_detail(session_id, assignment_id, team_id)


def _enforce_unlocked(session_id, assignment_id):
    """Return a redirect for GET flows accessing a non-unlocked challenge.

    Enforces strict sequential unlocking. If the requested assignment is not the
    currently unlocked challenge (future or already-completed), the participant
    is redirected to the currently unlocked challenge. Returns None when the
    assignment IS the currently unlocked challenge.
    """
    unlocked_id = assign.get_current_unlocked_id(session_id)
    if unlocked_id is None:
        # All challenges complete -> send to the completion state.
        return redirect(url_for("r1.r1_complete", session_id=session_id))
    if unlocked_id != assignment_id:
        return redirect(url_for("r1.r1_challenge", assignment_id=unlocked_id))
    return None


def _confirm_unlocked(session_id, assignment_id):
    """Return True only if the assignment is the currently unlocked challenge.

    Used by POST endpoints to reject attempts against future or completed
    challenges (prevents skipping / direct access to locked challenges).
    """
    unlocked_id = assign.get_current_unlocked_id(session_id)
    return unlocked_id is not None and unlocked_id == assignment_id


@r1.route("/r1/challenge/<int:assignment_id>")
@login_required_team
def r1_challenge(team, assignment_id):
    session_row = _get_session_row_from_team(team)
    if session_row is None:
        return redirect(url_for("r1.r1_dashboard"))
    if session_row["status"] in ("COMPLETED", "EXPIRED"):
        return redirect(url_for("r1.r1_complete", session_id=session_row["id"]))
    a = _get_assignment(session_row["id"], assignment_id, team["id"])
    if a is None:
        abort(404)
    locked_redirect = _enforce_unlocked(session_row["id"], assignment_id)
    if locked_redirect is not None:
        return locked_redirect
    conn = db.get_connection()
    try:
        attempts = conn.execute(
            "SELECT COUNT(*) AS n FROM submissions WHERE assignment_id=?",
            (assignment_id,)).fetchone()["n"]
        already_solved = conn.execute(
            "SELECT id FROM submissions WHERE assignment_id=? AND is_correct=1 "
            "LIMIT 1", (assignment_id,)).fetchone() is not None
    finally:
        conn.close()
    lab_locked = (a.get("lab_status", "") != "LAB_COMPLETED"
                  and int(a.get("lab_attempts") or 0) >= max_attempts())
    return render_template(
        "r1_challenge.html", team=team, assignment=a, session_row=session_row,
        attempts=attempts, already_solved=already_solved,
        flag_revealed=a.get("flag_revealed", 0),
        lab_completed=(a.get("lab_status", "") == "LAB_COMPLETED"),
        lab_locked=lab_locked,
        lab_attempts=int(a.get("lab_attempts") or 0),
        remaining_ms=session_row["ends_at"] - db.now_ms())


@r1.route("/r1/challenge/<int:assignment_id>/submit", methods=["POST"])
@login_required_team
def r1_submit(team, assignment_id):
    session_row = _get_session_row_from_team(team)
    if session_row is None or session_row["status"] in ("COMPLETED", "EXPIRED"):
        return jsonify({"ok": False, "error": "Session not active"}), 400
    a = _get_assignment(session_row["id"], assignment_id, team["id"])
    if a is None:
        return jsonify({"ok": False, "error": "Not found"}), 404
    if not _confirm_unlocked(session_row["id"], assignment_id):
        return jsonify({"ok": False, "error": "Challenge locked."}), 403

    # --- Flag submission rules ---------------------------------------------
    if a.get("lab_status") != "LAB_COMPLETED":
        return jsonify({"ok": False,
                        "error": "Complete the lab first to unlock the flag."}), 403

    # rate limit
    if _rate_limit_exceeded(team["id"]):
        return jsonify({"ok": False,
                        "error": "Too many submissions. Please wait a moment."}), 429

    flag = request.form.get("flag", "").strip()
    if not flag:
        return jsonify({"ok": False, "error": "Empty flag."}), 400

    conn = db.get_connection()
    try:
        # already solved -> no double points
        correct_already = conn.execute(
            "SELECT id FROM submissions WHERE assignment_id=? AND is_correct=1 "
            "LIMIT 1", (assignment_id,)).fetchone()
        if correct_already:
            return jsonify({"ok": True, "correct": True, "already": True})

        attempt_number = conn.execute(
            "SELECT COUNT(*) AS n FROM submissions WHERE assignment_id=?",
            (assignment_id,)).fetchone()["n"] + 1

        real_flag = conn.execute(
            "SELECT v.flag FROM team_challenge_assignments a "
            "JOIN challenge_variants v ON a.variant_id = v.id WHERE a.id=?",
            (assignment_id,)).fetchone()["flag"]
        is_correct = (flag.strip() == (real_flag or "").strip())

        conn.execute(
            "INSERT INTO submissions (session_id, assignment_id, submitted_answer, "
            "is_correct, submitted_at, attempt_number) VALUES (?,?,?,?,?,?)",
            (session_row["id"], assignment_id, flag, 1 if is_correct else 0,
             db.now_ms(), attempt_number))

        if is_correct:
            conn.execute(
                "UPDATE team_challenge_assignments SET status='COMPLETED', "
                "completed_at=?, points_awarded=? WHERE id=?",
                (db.now_ms(), a["points"], assignment_id))
            conn.execute(
                "INSERT INTO lab_events (assignment_id, session_id, kind, detail, "
                "occurred_at) VALUES (?,?,?,?,?)",
                (assignment_id, session_row["id"], "flag_submitted", "correct",
                 db.now_ms()))
            update_session_score(conn, session_row["id"])
            conn.commit()
            return jsonify({"ok": True, "correct": True, "attempt": attempt_number,
                            "points": a["points"]})

        conn.commit()
        return jsonify({"ok": True, "correct": False, "attempt": attempt_number})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Interactive Mini-Lab
# ---------------------------------------------------------------------------

def _log_lab_event(conn, session_id, assignment_id, kind, detail=""):
    conn.execute(
        "INSERT INTO lab_events (assignment_id, session_id, kind, detail, "
        "occurred_at) VALUES (?,?,?,?,?)",
        (assignment_id, session_id, kind, detail, db.now_ms()))


@r1.route("/r1/lab/<int:assignment_id>")
@login_required_team
def r1_lab(team, assignment_id):
    session_row = _get_session_row_from_team(team)
    if session_row is None:
        return redirect(url_for("r1.r1_dashboard"))
    if session_row["status"] in ("COMPLETED", "EXPIRED"):
        return redirect(url_for("r1.r1_complete", session_id=session_row["id"]))
    a = _get_assignment(session_row["id"], assignment_id, team["id"])
    if a is None:
        abort(404)
    locked_redirect = _enforce_unlocked(session_row["id"], assignment_id)
    if locked_redirect is not None:
        return locked_redirect

    conn = db.get_connection()
    try:
        if a.get("lab_status") == "NOT_STARTED":
            conn.execute(
                "UPDATE team_challenge_assignments SET lab_status='IN_PROGRESS', "
                "lab_started_at=? WHERE id=?",
                (db.now_ms(), assignment_id))
            _log_lab_event(conn, session_row["id"], assignment_id, "lab_opened")
            conn.commit()
            a["lab_status"] = "IN_PROGRESS"
            a["lab_started_at"] = a["lab_started_at"] or db.now_ms()
        already_solved = conn.execute(
            "SELECT id FROM submissions WHERE assignment_id=? AND is_correct=1 "
            "LIMIT 1", (assignment_id,)).fetchone() is not None
        revealed_flag = None
        if a.get("flag_revealed") and a.get("lab_status") == "LAB_COMPLETED":
            row = conn.execute(
                "SELECT v.flag FROM team_challenge_assignments x "
                "JOIN challenge_variants v ON x.variant_id = v.id WHERE x.id=?",
                (assignment_id,)).fetchone()
            revealed_flag = row["flag"] if row else None
    finally:
        conn.close()
    lab_attempts = int(a.get("lab_attempts") or 0)
    lab_submitted = int(a.get("lab_submitted") or 0)
    locked = (not a.get("lab_status") == "LAB_COMPLETED"
              and lab_attempts >= max_attempts())
    return render_template(
        "r1_lab.html", team=team, assignment=a, session_row=session_row,
        lab_completed=(a.get("lab_status") == "LAB_COMPLETED"),
        lab_attempts=lab_attempts,
        lab_submitted=lab_submitted,
        locked=locked,
        already_solved=already_solved, flag_revealed=a.get("flag_revealed", 0),
        revealed_flag=revealed_flag,
        remaining_ms=session_row["ends_at"] - db.now_ms())


@r1.route("/r1/lab/<int:assignment_id>/action", methods=["POST"])
@login_required_team
def r1_lab_action(team, assignment_id):
    session_row = _get_session_row_from_team(team)
    if session_row is None or session_row["status"] in ("COMPLETED", "EXPIRED"):
        return jsonify({"ok": False, "error": "Session not active"}), 400
    a = _get_assignment(session_row["id"], assignment_id, team["id"])
    if a is None:
        return jsonify({"ok": False, "error": "Not found"}), 404
    if not _confirm_unlocked(session_row["id"], assignment_id):
        return jsonify({"ok": False, "error": "Challenge locked."}), 403

    conn = db.get_connection()
    try:
        # Always read authoritative state from the DB (server is the source of truth)
        row = conn.execute(
            "SELECT * FROM team_challenge_assignments WHERE id=?",
            (assignment_id,)).fetchone()
        row = dict(row) if row else {}
        lab_status = row.get("lab_status", "NOT_STARTED")
        lab_attempts = int(row.get("lab_attempts") or 0)
        lab_submitted = int(row.get("lab_submitted") or 0)

        # Already completed lab -> return flag (it was already revealed)
        if lab_status == "LAB_COMPLETED":
            return jsonify({
                "ok": True, "completed": True, "status": "correct",
                "flag": _variant_flag(conn, assignment_id)})

        # Permanently locked (max attempts reached, still unsolved)
        if lab_attempts >= max_attempts():
            return jsonify({
                "ok": False, "error": "This question is locked.",
                "locked": True}), 400

        action = request.get_json(silent=True) or request.form.to_dict()

        expected = assign.get_lab_answer(assignment_id)
        lab_data = lab.parse_lab_data(a.get("lab_data"))
        ok, msg = lab.check_lab_success(lab_data, expected, action)

        # Consume one attempt, then immediately freeze (disable further edits /
        # double submissions). Server increments the counter; the user can only
        # resume the next attempt via the explicit unlock endpoint.
        new_attempts = lab_attempts + 1
        settled_locked = int(new_attempts >= max_attempts())

        _log_lab_event(conn, session_row["id"], assignment_id,
                       "lab_attempt" if not ok else "lab_completed",
                       "" if ok else "incorrect")

        if ok:
            conn.execute(
                "UPDATE team_challenge_assignments SET lab_status='LAB_COMPLETED', "
                "lab_completed_at=?, flag_revealed=1, lab_attempts=?, "
                "lab_submitted=1 WHERE id=?",
                (db.now_ms(), new_attempts, assignment_id))
            _log_lab_event(conn, session_row["id"], assignment_id, "flag_revealed")
            conn.commit()
            return jsonify({
                "ok": True, "completed": True, "status": "correct",
                "flag": _variant_flag(conn, assignment_id), "message": msg})

        conn.execute(
            "UPDATE team_challenge_assignments SET lab_attempts=?, "
            "lab_submitted=1 WHERE id=?",
            (new_attempts, assignment_id))
        conn.commit()
        # Wrong but not yet out of attempts -> blue "submitted/locked" state.
        # Out of attempts after this -> permanently locked.
        return jsonify({
            "ok": True, "completed": False,
            "status": "locked" if settled_locked else "submitted",
            "message": msg})
    finally:
        conn.close()


@r1.route("/r1/lab/<int:assignment_id>/next", methods=["POST"])
@login_required_team
def r1_lab_next(team, assignment_id):
    """Allow the next attempt after a previous submission, per the game flow.

    Only permitted when the question is NOT completed and NOT permanently
    locked (i.e. the team still has attempts remaining). Clears the frozen
    state so the answer input is editable once again.
    """
    session_row = _get_session_row_from_team(team)
    if session_row is None or session_row["status"] in ("COMPLETED", "EXPIRED"):
        return jsonify({"ok": False, "error": "Session not active"}), 400
    a = _get_assignment(session_row["id"], assignment_id, team["id"])
    if a is None:
        return jsonify({"ok": False, "error": "Not found"}), 404
    if not _confirm_unlocked(session_row["id"], assignment_id):
        return jsonify({"ok": False, "error": "Challenge locked."}), 403

    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM team_challenge_assignments WHERE id=?",
            (assignment_id,)).fetchone()
        row = dict(row) if row else {}
        lab_status = row.get("lab_status", "NOT_STARTED")
        lab_attempts = int(row.get("lab_attempts") or 0)
        if lab_status == "LAB_COMPLETED":
            return jsonify({"ok": False, "error": "Already completed."}), 400
        if lab_attempts >= max_attempts():
            return jsonify({"ok": False, "error": "Question is locked.",
                            "locked": True}), 400
        conn.execute(
            "UPDATE team_challenge_assignments SET lab_submitted=0 WHERE id=?",
            (assignment_id,))
        conn.commit()
        remaining = max(0, max_attempts() - lab_attempts)
        return jsonify({"ok": True, "remaining": remaining})
    finally:
        conn.close()


def _variant_flag(conn, assignment_id):
    """Fetch the variant flag for an assignment (server-side reveal only)."""
    own = conn is not None
    if not own:
        conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT v.flag FROM team_challenge_assignments a "
            "JOIN challenge_variants v ON a.variant_id = v.id WHERE a.id=?",
            (assignment_id,)).fetchone()
        return row["flag"] if row else ""
    finally:
        if not own:
            conn.close()


def update_session_score(conn, session_id):
    """Recompute the session total from completed assignments.

    Marking the round COMPLETED when every one of the 6 challenges is solved
    (status='COMPLETED') triggers the sequential Round 1 completion state.
    """
    row = conn.execute(
        "SELECT COALESCE(SUM(points_awarded),0) AS total FROM "
        "team_challenge_assignments WHERE session_id=? AND status='COMPLETED'",
        (session_id,)).fetchone()
    solved_count = conn.execute(
        "SELECT COUNT(*) AS n FROM team_challenge_assignments "
        "WHERE session_id=? AND status='COMPLETED'", (session_id,)).fetchone()["n"]
    conn.execute(
        "UPDATE round_sessions SET score=?, challenges_solved=? WHERE id=?",
        (row["total"], solved_count, session_id))
    # Once all 6 are solved, close the round.
    status_row = conn.execute(
        "SELECT status FROM round_sessions WHERE id=?", (session_id,)).fetchone()
    if solved_count >= 6 and status_row and status_row["status"] == "ACTIVE":
        conn.execute(
            "UPDATE round_sessions SET status='COMPLETED', completed_at=? "
            "WHERE id=?", (db.now_ms(), session_id))


@r1.route("/r1/challenge/<int:assignment_id>/hint", methods=["POST"])
@login_required_team
def r1_hint(team, assignment_id):
    session_row = _get_session_row_from_team(team)
    if session_row is None or session_row["status"] in ("COMPLETED", "EXPIRED"):
        return jsonify({"ok": False, "error": "Session not active"}), 400
    a = _get_assignment(session_row["id"], assignment_id, team["id"])
    if a is None:
        return jsonify({"ok": False, "error": "Not found"}), 404
    if not _confirm_unlocked(session_row["id"], assignment_id):
        return jsonify({"ok": False, "error": "Challenge locked."}), 403
    a = dict(a)
    conn = db.get_connection()
    try:
        # re-check already solved -> don't show hint
        solved = conn.execute(
            "SELECT id FROM submissions WHERE assignment_id=? AND is_correct=1 "
            "LIMIT 1", (assignment_id,)).fetchone()
        if solved:
            return jsonify({"ok": False, "error": "Already solved"}), 400
        conn.execute(
            "INSERT INTO hint_usage (assignment_id, used_at) VALUES (?,?)",
            (assignment_id, db.now_ms()))
        conn.commit()
        hints = a.get("hints")
        if not isinstance(hints, list) or not hints:
            hints = [a.get("hint") or "No further hint available."]
        return jsonify({"ok": True, "hint": hints[0]})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Completion / leaderboard
# ---------------------------------------------------------------------------

@r1.route("/r1/complete/<int:session_id>")
@login_required_team
def r1_complete(team, session_id):
    conn = db.get_connection()
    try:
        sess = conn.execute(
            "SELECT * FROM round_sessions WHERE id=? AND team_id=?",
            (session_id, team["id"])).fetchone()
    finally:
        conn.close()
    if sess is None:
        abort(404)
    sess = dict(sess)
    assignments = assign.get_assignments(session_id)
    return render_template("r1_complete.html", team=team, session_row=sess,
                           assignments=assignments)


@r1.route("/r1/timeup", methods=["POST"])
@login_required_team
def r1_timeup(team):
    """Finalize the team's Round 1 session when the 30-minute timer expires.

    Called by the participant-side countdown at 00:00. Server-authoritative:
    only expires the session if its deadline has actually passed, so an early
    POST can never close the round early.
    """
    sess = assign.get_session_by_team(team["id"])
    if sess is None:
        finished = _get_finished_session(team["id"])
        if finished is not None:
            return jsonify(
                {"ok": True,
                 "redirect": url_for("r1.r1_complete",
                                     session_id=finished["id"])})
        return jsonify({"ok": False, "error": "No session."}), 400
    if sess["ends_at"] > db.now_ms():
        return jsonify({"ok": False, "error": "Session still active."})
    conn = db.get_connection()
    try:
        conn.execute(
            "UPDATE round_sessions SET status='EXPIRED', completed_at=? "
            "WHERE id=? AND status='ACTIVE'",
            (db.now_ms(), sess["id"]))
        conn.commit()
    finally:
        conn.close()
    return jsonify(
        {"ok": True,
         "redirect": url_for("r1.r1_complete", session_id=sess["id"])})


@r1.route("/r1/leaderboard")
def r1_leaderboard():
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT t.team_name, s.score, s.challenges_solved, s.completed_at, "
            "s.status, s.ends_at "
            "FROM round_sessions s JOIN teams t ON s.team_id=t.id "
            "WHERE s.status='COMPLETED' "
            "ORDER BY s.score DESC, s.challenges_solved DESC, s.completed_at ASC "
            "LIMIT 20").fetchall()
    finally:
        conn.close()
    return render_template("r1_leaderboard.html", team=get_current_team(),
                           leaderboard=[dict(r) for r in rows])


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@r1.route("/r1/admin/login", methods=["GET", "POST"])
def r1_admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = db.get_connection()
        try:
            row = conn.execute("SELECT * FROM admins WHERE username=?",
                               (username,)).fetchone()
        finally:
            conn.close()
        if row and check_password_hash(row["password_hash"], password):
            session[SESSION_ADMIN_KEY] = row["username"]
            return redirect(url_for("r1.r1_admin_dashboard"))
        return render_template("r1_admin_login.html", error="Invalid credentials.")
    return render_template("r1_admin_login.html", error=None)


@r1.route("/r1/admin/logout")
def r1_admin_logout():
    session.pop(SESSION_ADMIN_KEY, None)
    return redirect(url_for("r1.r1_admin_login"))


def _admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get(SESSION_ADMIN_KEY):
            return redirect(url_for("r1.r1_admin_login"))
        return view(*args, **kwargs)
    return wrapped


@r1.route("/r1/admin")
@_admin_required
def r1_admin_dashboard():
    conn = db.get_connection()
    try:
        stats = {}
        stats["teams"] = conn.execute("SELECT COUNT(*) n FROM teams").fetchone()["n"]
        stats["sessions"] = conn.execute(
            "SELECT COUNT(*) n FROM round_sessions").fetchone()["n"]
        stats["active"] = conn.execute(
            "SELECT COUNT(*) n FROM round_sessions WHERE status='ACTIVE'").fetchone()["n"]
        stats["completed"] = conn.execute(
            "SELECT COUNT(*) n FROM round_sessions WHERE status='COMPLETED'").fetchone()["n"]
        stats["submissions"] = conn.execute(
            "SELECT COUNT(*) n FROM submissions").fetchone()["n"]
        stats["correct"] = conn.execute(
            "SELECT COUNT(*) n FROM submissions WHERE is_correct=1").fetchone()["n"]
        stats["variants"] = conn.execute(
            "SELECT COUNT(*) n FROM challenge_variants").fetchone()["n"]
        stats["assignments"] = conn.execute(
            "SELECT COUNT(*) n FROM team_challenge_assignments").fetchone()["n"]
        stats["labs_open"] = conn.execute(
            "SELECT COUNT(*) n FROM team_challenge_assignments "
            "WHERE lab_status != 'NOT_STARTED'").fetchone()["n"]
        stats["labs_completed"] = conn.execute(
            "SELECT COUNT(*) n FROM team_challenge_assignments "
            "WHERE lab_status = 'LAB_COMPLETED'").fetchone()["n"]
        stats["flags_revealed"] = conn.execute(
            "SELECT COUNT(*) n FROM team_challenge_assignments "
            "WHERE flag_revealed = 1").fetchone()["n"]
    finally:
        conn.close()
    return render_template("r1_admin_dashboard.html", stats=stats)


@r1.route("/r1/admin/teams")
@_admin_required
def r1_admin_teams():
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT t.id, t.team_id, t.team_name, t.participant_names, "
            "t.created_at, "
            "(SELECT s.status FROM round_sessions s WHERE s.team_id=t.id "
            "ORDER BY s.id DESC LIMIT 1) AS last_status, "
            "(SELECT s.score FROM round_sessions s WHERE s.team_id=t.id "
            "ORDER BY s.id DESC LIMIT 1) AS last_score, "
            "(SELECT COUNT(*) FROM team_challenge_assignments a "
            " JOIN round_sessions s ON a.session_id=s.id "
            " WHERE s.team_id=t.id AND a.lab_status != 'NOT_STARTED') AS labs_open, "
            "(SELECT COUNT(*) FROM team_challenge_assignments a "
            " JOIN round_sessions s ON a.session_id=s.id "
            " WHERE s.team_id=t.id AND a.lab_status='LAB_COMPLETED') AS labs_done "
            "FROM teams t ORDER BY t.id").fetchall()
    finally:
        conn.close()
    return render_template("r1_admin_teams.html", teams=[dict(r) for r in rows])


@r1.route("/r1/admin/teams/<int:team_id>")
@_admin_required
def r1_admin_team_detail(team_id):
    conn = db.get_connection()
    try:
        team = conn.execute("SELECT * FROM teams WHERE id=?", (team_id,)).fetchone()
        sessions = conn.execute(
            "SELECT * FROM round_sessions WHERE team_id=? ORDER BY id DESC",
            (team_id,)).fetchall()
        if not team or not sessions:
            abort(404)
        sess = sessions[0]
        assignments = conn.execute(
            "SELECT a.id, a.display_order, a.status, a.started_at, a.completed_at, "
            "a.points_awarded, a.lab_status, a.lab_started_at, a.lab_completed_at, "
            "a.flag_revealed, c.challenge_code, c.title, v.variant_code, v.lab_type, "
            "v.difficulty, "
            "(SELECT COUNT(*) FROM submissions sub WHERE sub.assignment_id=a.id AND sub.is_correct=1) AS solve_count, "
            "(SELECT COUNT(*) FROM submissions sub WHERE sub.assignment_id=a.id) AS total_attempts "
            "FROM team_challenge_assignments a "
            "JOIN challenge_categories c ON a.challenge_category_id=c.id "
            "JOIN challenge_variants v ON a.variant_id=v.id "
            "WHERE a.session_id=? ORDER BY a.display_order",
            (sess["id"],)).fetchall()
        events = conn.execute(
            "SELECT kind, detail, occurred_at FROM lab_events "
            "WHERE session_id=? ORDER BY occurred_at DESC LIMIT 100",
            (sess["id"],)).fetchall()
    finally:
        conn.close()
    return render_template("r1_admin_team_detail.html", team=dict(team),
                           session=dict(sess), assignments=[dict(r) for r in assignments],
                           events=[dict(r) for r in events])


@r1.route("/r1/admin/sessions")
@_admin_required
def r1_admin_sessions():
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT s.id, s.team_id, t.team_name, s.started_at, s.ends_at, "
            "s.completed_at, s.status, s.score, s.challenges_solved "
            "FROM round_sessions s JOIN teams t ON s.team_id=t.id "
            "ORDER BY s.id DESC").fetchall()
    finally:
        conn.close()
    return render_template("r1_admin_sessions.html", sessions=[dict(r) for r in rows])


@r1.route("/r1/admin/submissions")
@_admin_required
def r1_admin_submissions():
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT sub.id, sub.session_id, sub.assignment_id, "
            "sub.submitted_answer, sub.is_correct, sub.submitted_at, "
            "sub.attempt_number, t.team_name, c.challenge_code, v.variant_code "
            "FROM submissions sub "
            "JOIN round_sessions s ON sub.session_id = s.id "
            "JOIN teams t ON s.team_id = t.id "
            "JOIN team_challenge_assignments a ON sub.assignment_id = a.id "
            "JOIN challenge_categories c ON a.challenge_category_id = c.id "
            "JOIN challenge_variants v ON a.variant_id = v.id "
            "ORDER BY sub.id DESC LIMIT 500").fetchall()
    finally:
        conn.close()
    return render_template("r1_admin_submissions.html",
                           submissions=[dict(r) for r in rows])


@r1.route("/r1/admin/statistics")
@_admin_required
def r1_admin_statistics():
    conn = db.get_connection()
    try:
        by_category = conn.execute(
            "SELECT c.challenge_code, c.title, c.difficulty, "
            "COUNT(a.id) AS assigned, "
            "SUM(CASE WHEN a.status='COMPLETED' THEN 1 ELSE 0 END) AS solved, "
            "SUM(CASE WHEN a.lab_status != 'NOT_STARTED' THEN 1 ELSE 0 END) AS labs_open, "
            "SUM(CASE WHEN a.lab_status='LAB_COMPLETED' THEN 1 ELSE 0 END) AS labs_done, "
            "SUM(a.flag_revealed) AS flags "
            "FROM challenge_categories c "
            "LEFT JOIN team_challenge_assignments a ON a.challenge_category_id=c.id "
            "GROUP BY c.id ORDER BY c.id").fetchall()

        by_variant = conn.execute(
            "SELECT c.challenge_code, v.variant_code, v.lab_type, v.title, "
            "v.difficulty, "
            "COUNT(a.id) AS assigned, "
            "SUM(CASE WHEN a.lab_status != 'NOT_STARTED' THEN 1 ELSE 0 END) AS labs_open, "
            "SUM(CASE WHEN a.lab_status='LAB_COMPLETED' THEN 1 ELSE 0 END) AS labs_done, "
            "SUM(a.flag_revealed) AS flags, "
            "SUM(CASE WHEN a.status='COMPLETED' THEN 1 ELSE 0 END) AS solved, "
            "AVG(CASE WHEN a.lab_completed_at IS NOT NULL AND a.lab_started_at IS NOT NULL "
            "     THEN (a.lab_completed_at - a.lab_started_at) ELSE NULL END) AS avg_lab_ms "
            "FROM team_challenge_assignments a "
            "JOIN challenge_categories c ON a.challenge_category_id=c.id "
            "JOIN challenge_variants v ON a.variant_id=v.id "
            "GROUP BY v.id ORDER BY c.id, v.variant_code").fetchall()

        by_lab_type = conn.execute(
            "SELECT v.lab_type, COUNT(DISTINCT v.id) AS variants, "
            "COUNT(a.id) AS assigned, "
            "SUM(CASE WHEN a.lab_status != 'NOT_STARTED' THEN 1 ELSE 0 END) AS labs_open, "
            "SUM(CASE WHEN a.lab_status='LAB_COMPLETED' THEN 1 ELSE 0 END) AS labs_done, "
            "SUM(CASE WHEN a.status='COMPLETED' THEN 1 ELSE 0 END) AS solved "
            "FROM challenge_variants v "
            "LEFT JOIN team_challenge_assignments a ON a.variant_id=v.id "
            "GROUP BY v.lab_type").fetchall()

        avg_solve = conn.execute(
            "SELECT AVG(CASE WHEN s.started_at > 0 THEN "
            "(s.completed_at - s.started_at) ELSE NULL END) AS avg_ms "
            "FROM round_sessions s WHERE s.completed_at IS NOT NULL").fetchone()
    finally:
        conn.close()
    stats = {
        "by_category": [dict(r) for r in by_category],
        "by_variant": [dict(r) for r in by_variant],
        "by_lab_type": [dict(r) for r in by_lab_type],
        "avg_solve_ms": (avg_solve["avg_ms"] if avg_solve else None),
    }
    return render_template("r1_admin_statistics.html", stats=stats)


@r1.route("/r1/admin/export")
@_admin_required
def r1_admin_export():
    """CSV export of all sessions + submissions for a competitive audit."""
    conn = db.get_connection()
    try:
        sessions = conn.execute(
            "SELECT s.id, t.team_id, t.team_name, s.started_at, s.ends_at, "
            "s.completed_at, s.status, s.score, s.challenges_solved "
            "FROM round_sessions s JOIN teams t ON s.team_id=t.id "
            "ORDER BY s.id").fetchall()
    finally:
        conn.close()

    rows = []
    header = ["session_id", "team_id", "team_name", "started_at_ms",
              "ends_at_ms", "completed_at_ms", "status", "score",
              "challenges_solved"]
    for s in sessions:
        rows.append([s["id"], s["team_id"], s["team_name"], s["started_at"],
                     s["ends_at"], s["completed_at"], s["status"], s["score"],
                     s["challenges_solved"]])
    csv_body = _to_csv(header, rows)
    return Response(csv_body, mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=round1_export.csv"})


@r1.route("/r1/admin/export/assignments")
@_admin_required
def r1_admin_export_assignments():
    """Per-assignment CSV incl. lab + flag timestamps for a competition audit."""
    conn = db.get_connection()
    try:
        ass = conn.execute(
            "SELECT a.id, a.session_id, t.team_id, t.team_name, "
            "c.challenge_code, v.variant_code, v.lab_type, "
            "a.display_order, a.status, a.started_at, a.completed_at, "
            "a.points_awarded, a.lab_status, a.lab_started_at, "
            "a.lab_completed_at, a.flag_revealed "
            "FROM team_challenge_assignments a "
            "JOIN round_sessions s ON a.session_id=s.id "
            "JOIN teams t ON s.team_id=t.id "
            "JOIN challenge_categories c ON a.challenge_category_id=c.id "
            "JOIN challenge_variants v ON a.variant_id=v.id "
            "ORDER BY a.id").fetchall()
    finally:
        conn.close()
    header = ["assignment_id", "session_id", "team_id", "team_name",
              "challenge_code", "variant_code", "lab_type", "display_order",
              "status", "started_at_ms", "completed_at_ms", "points_awarded",
              "lab_status", "lab_started_at_ms", "lab_completed_at_ms",
              "flag_revealed"]
    rows = [[x["id"], x["session_id"], x["team_id"], x["team_name"],
             x["challenge_code"], x["variant_code"], x["lab_type"],
             x["display_order"], x["status"], x["started_at"], x["completed_at"],
             x["points_awarded"], x["lab_status"], x["lab_started_at"],
             x["lab_completed_at"], x["flag_revealed"]] for x in ass]
    return Response(_to_csv(header, rows), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=round1_assignments.csv"})


@r1.route("/r1/admin/export/events")
@_admin_required
def r1_admin_export_events():
    """CSV of all lab events for forensic reconstruction of the round."""
    conn = db.get_connection()
    try:
        evs = conn.execute(
            "SELECT e.id, e.assignment_id, e.session_id, t.team_id, "
            "t.team_name, c.challenge_code, e.kind, e.detail, e.occurred_at "
            "FROM lab_events e "
            "JOIN round_sessions s ON e.session_id=s.id "
            "JOIN teams t ON s.team_id=t.id "
            "JOIN team_challenge_assignments a ON e.assignment_id=a.id "
            "JOIN challenge_categories c ON a.challenge_category_id=c.id "
            "ORDER BY e.id").fetchall()
    finally:
        conn.close()
    header = ["event_id", "assignment_id", "session_id", "team_id", "team_name",
              "challenge_code", "kind", "detail", "occurred_at_ms"]
    rows = [[e["id"], e["assignment_id"], e["session_id"], e["team_id"],
             e["team_name"], e["challenge_code"], e["kind"], e["detail"],
             e["occurred_at"]] for e in evs]
    return Response(_to_csv(header, rows), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=round1_lab_events.csv"})


@r1.route("/r1/admin/export/submissions")
@_admin_required
def r1_admin_export_submissions():
    conn = db.get_connection()
    try:
        subs = conn.execute(
            "SELECT sub.id, sub.session_id, sub.assignment_id, "
            "sub.submitted_answer, sub.is_correct, sub.submitted_at, "
            "sub.attempt_number, t.team_id, t.team_name, c.challenge_code, "
            "v.variant_code FROM submissions sub "
            "JOIN round_sessions s ON sub.session_id=s.id "
            "JOIN teams t ON s.team_id=t.id "
            "JOIN team_challenge_assignments a ON sub.assignment_id=a.id "
            "JOIN challenge_categories c ON a.challenge_category_id=c.id "
            "JOIN challenge_variants v ON a.variant_id=v.id "
            "ORDER BY sub.id").fetchall()
    finally:
        conn.close()
    header = ["submission_id", "session_id", "assignment_id",
              "submitted_answer", "is_correct", "submitted_at_ms",
              "attempt_number", "team_id", "team_name", "challenge_code",
              "variant_code"]
    rows = [[s["id"], s["session_id"], s["assignment_id"], s["submitted_answer"],
             s["is_correct"], s["submitted_at"], s["attempt_number"], s["team_id"],
             s["team_name"], s["challenge_code"], s["variant_code"]] for s in subs]
    return Response(_to_csv(header, rows), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=round1_submissions.csv"})


def _csv_escape(v):
    v = "" if v is None else str(v)
    if any(ch in v for ch in ',"\n\r'):
        return '"' + v.replace('"', '""') + '"'
    return v


def _to_csv(header, rows):
    lines = [",".join(_csv_escape(h) for h in header)]
    for row in rows:
        lines.append(",".join(_csv_escape(c) for c in row))
    return "\n".join(lines) + "\n"
