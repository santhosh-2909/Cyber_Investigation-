"""Round 1 - Cyber Puzzle: assignment and randomization logic.

All randomization happens server-side and is persisted to the database.
Assignments are generated exactly once per round session and never reshuffled.
"""
import json
import random
import secrets

import round1.db as db
import round1.lab as lab


# ---------------------------------------------------------------------------
# Difficulty balance helpers
# ---------------------------------------------------------------------------

def normalize_answer(text):
    """Normalize a submitted answer for case-insensitive comparison."""
    if not text:
        return ""
    return " ".join(text.strip().lower().split())


MAX_LAB_ATTEMPTS = 3


def select_balanced_categories(categories, n=6):
    """Select n categories with a preferred difficulty distribution.

    Preferred: 2 Easy, 2 Medium, 1 Medium-Hard, 1 Flexible.
    Falls back gracefully when the pool lacks enough of a given difficulty.
    """
    random.shuffle(categories)

    easy = [c for c in categories if c["difficulty"] == "Easy"]
    medium = [c for c in categories if c["difficulty"] == "Medium"]
    med_hard = [c for c in categories if c["difficulty"] == "Medium-Hard"]

    selected = []

    # Pick 2 easy
    take = min(2, len(easy))
    selected += easy[:take]
    # Pick 2 medium
    take = min(2, len(medium))
    selected += medium[:take]
    # Pick 1 medium-hard
    take = min(1, len(med_hard))
    selected += med_hard[:take]

    # Fill remaining with flexible (any leftover) to reach n
    remaining = []
    for c in categories:
        if c not in selected:
            remaining.append(c)
    needed = n - len(selected)
    selected += remaining[:needed]

    # Shuffle the final selection order
    random.shuffle(selected)
    return selected[:n]


def pick_variant(category_id, difficulty=None):
    """Randomly select one variant for the given category.

    If a specific difficulty is requested and available, prefer it.
    """
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM challenge_variants WHERE challenge_category_id=?",
            (category_id,),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        raise ValueError("No variants for category %s" % category_id)

    variants = [dict(r) for r in rows]
    if difficulty:
        matching = [v for v in variants if v["difficulty"] == difficulty]
        if matching:
            return random.choice(matching)
    return random.choice(variants)


def create_assignment(team_id, round_name="Round 1 - Cyber Puzzle: Mixed Fundamentals"):
    """Create a new round session for a team and assign challenges.

    Returns a dict describing the session. If a session already exists that
    is not COMPLETED/EXPIRED, it is resumed (no new assignment).
    """
    conn = db.get_connection()
    try:
        # 1. Check for an existing active session
        existing = conn.execute(
            "SELECT * FROM round_sessions WHERE team_id=? AND status NOT IN "
            "('COMPLETED','EXPIRED') ORDER BY id DESC LIMIT 1",
            (team_id,),
        ).fetchone()
        if existing:
            return _resume_session(existing)

        # 2. Check if team already completed (prevent duplicate rounds)
        finished = conn.execute(
            "SELECT * FROM round_sessions WHERE team_id=? AND status IN "
            "('COMPLETED','EXPIRED') ORDER BY id DESC LIMIT 1",
            (team_id,),
        ).fetchone()
        if finished:
            return _resume_session(finished, allow_resume=False)

        # 3. Fetch active categories
        cats = [dict(r) for r in conn.execute(
            "SELECT * FROM challenge_categories WHERE active=1"
        ).fetchall()]
        if len(cats) < 6:
            raise ValueError("Not enough active challenge categories")

        # 4. Select 6 balanced categories
        selected_cats = select_balanced_categories(cats, n=6)

        # 5. Pick 1 variant per selected category
        assignments = []
        for cat in selected_cats:
            variant = pick_variant(cat["id"], difficulty=cat["difficulty"])
            assignments.append({
                "cat": cat,
                "variant": variant,
            })

        # 6. Create the session (started/ends timestamps)
        start = db.now_ms()
        duration_ms = int(admin_ops.get_round_settings("round1").get("timer_minutes", 30)) * 60 * 1000
        end = start + duration_ms

        cur = conn.execute(
            "INSERT INTO round_sessions (team_id, round_name, started_at, ends_at, "
            "status, score, challenges_solved) VALUES (?,?,?,?,?,?,?)",
            (team_id, round_name, start, end, "ACTIVE", 0, 0),
        )
        session_id = cur.lastrowid

        # 7. Shuffle order and persist assignments
        random.shuffle(assignments)
        for idx, a in enumerate(assignments):
            conn.execute(
                "INSERT INTO team_challenge_assignments (session_id, "
                "challenge_category_id, variant_id, display_order, status, "
                "points_awarded) VALUES (?,?,?,?,?,?)",
                (session_id, a["cat"]["id"], a["variant"]["id"], idx + 1,
                 "IN_PROGRESS", 0),
            )
        conn.commit()

        return _resume_session(conn.execute(
            "SELECT * FROM round_sessions WHERE id=?", (session_id,)
        ).fetchone())

    finally:
        conn.close()


def _resume_session(row, allow_resume=True):
    """Build the public session view for an existing DB row."""
    row = dict(row)
    if row["status"] == "ACTIVE":
        # Re-evaluate expiry
        remaining = row["ends_at"] - db.now_ms()
        if remaining <= 0:
            row["status"] = "EXPIRED"
    return row


def get_session_by_team(team_id):
    """Return the current session row for a team (or None)."""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM round_sessions WHERE team_id=? "
            "AND status NOT IN ('COMPLETED','EXPIRED') ORDER BY id DESC LIMIT 1",
            (team_id,),
        ).fetchone()
        return _resume_session(row) if row else None
    finally:
        conn.close()


def get_completed_count(session_id):
    """Number of challenges fully solved (flag submitted correctly) in a session."""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM team_challenge_assignments "
            "WHERE session_id=? AND status='COMPLETED'", (session_id,)).fetchone()
        return row["n"] if row else 0
    finally:
        conn.close()


def get_current_unlocked_id(session_id):
    """Return the assignment id that is currently unlocked.

    The unlocked challenge is the lowest display_order that has not been fully
    completed (status != 'COMPLETED') AND has not had its lab attempts exhausted
    (locked after the max wrong attempts). A locked/solved challenge is treated
    as passed so the participant progresses to the next challenge. Returns None
    once every challenge in the session has been solved or locked.
    """
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT id FROM team_challenge_assignments WHERE session_id=? "
            "AND status != 'COMPLETED' "
            "AND (lab_attempts IS NULL OR lab_attempts < ?) "
            "ORDER BY display_order LIMIT 1",
            (session_id, MAX_LAB_ATTEMPTS)).fetchone()
        return row["id"] if row else None
    finally:
        conn.close()


def get_unlocked_assignment(session_id):
    """Return the currently unlocked assignment as a rich public view or None.

    Only the currently unlocked challenge is ever returned so future / completed
    challenge details (names, questions) are never exposed to the frontend.
    """
    unlocked_id = get_current_unlocked_id(session_id)
    if unlocked_id is None:
        return None
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT a.id AS assignment_id, a.display_order, a.status, "
            "a.started_at, a.completed_at, a.points_awarded, "
            "a.lab_status, a.lab_started_at, a.lab_completed_at, a.flag_revealed, "
            "a.lab_attempts, a.lab_submitted, "
            "c.id AS category_id, c.challenge_code, c.title, c.domain, "
            "c.description, c.points, "
            "v.id AS variant_id, v.variant_code, v.question, "
            "v.task_description, v.provided_data, v.difficulty, v.hint, "
            "v.lab_type, v.story, v.objective, v.lab_data "
            "FROM team_challenge_assignments a "
            "JOIN challenge_categories c ON a.challenge_category_id = c.id "
            "JOIN challenge_variants v ON a.variant_id = v.id "
            "WHERE a.id=?",
            (unlocked_id,),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["lab_meta"] = lab.LAB_META.get(d.get("lab_type") or "", {})
        d["lab_payload"] = lab.sanitize_lab_data(
            lab.parse_lab_data(d.get("lab_data")))
        return d
    finally:
        conn.close()


def get_assignments(session_id):
    """Return assigned challenges joined with variant + category data.

    Never includes flags or expected answers.
    """
    conn = db.get_connection()
    try:
        rows = conn.execute(
            "SELECT a.id AS assignment_id, a.display_order, a.status, "
            "a.started_at, a.completed_at, a.points_awarded, "
            "a.lab_status, a.lab_started_at, a.lab_completed_at, a.flag_revealed, "
            "a.lab_attempts, a.lab_submitted, "
            "c.id AS category_id, c.challenge_code, c.title, c.domain, "
            "c.description, c.points, "
            "v.id AS variant_id, v.variant_code, v.question, "
            "v.task_description, v.provided_data, v.difficulty, v.hint, "
            "v.lab_type, v.story, v.objective, v.lab_data "
            "FROM team_challenge_assignments a "
            "JOIN challenge_categories c ON a.challenge_category_id = c.id "
            "JOIN challenge_variants v ON a.variant_id = v.id "
            "WHERE a.session_id=? ORDER BY a.display_order",
            (session_id,),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["lab_meta"] = lab.LAB_META.get(d.get("lab_type") or "", {})
            d["lab_payload"] = lab.sanitize_lab_data(
                lab.parse_lab_data(d.get("lab_data")))
            result.append(d)
        return result
    finally:
        conn.close()


def get_assignment_detail(session_id, assignment_id, team_id):
    """Return a single assignment with lab metadata, safe for a given team.

    Returns None if the assignment does not belong to this team's session.
    """
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT a.*, "
            "c.title, c.challenge_code AS code, c.domain, c.points, "
            "v.variant_code, v.difficulty, v.story, v.objective, "
            "v.lab_type, v.lab_data, v.explanation, "
            "v.estimated_solve_time AS eta, v.hints "
            "FROM team_challenge_assignments a "
            "JOIN challenge_categories c ON a.challenge_category_id = c.id "
            "JOIN challenge_variants v ON a.variant_id = v.id "
            "WHERE a.id=? AND a.session_id=? AND a.session_id IN "
            "(SELECT id FROM round_sessions WHERE id=? AND team_id=?)",
            (assignment_id, session_id, session_id, team_id),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["lab_meta"] = lab.LAB_META.get(d.get("lab_type") or "", {})
        d["lab_payload"] = lab.sanitize_lab_data(lab.parse_lab_data(d["lab_data"]))
        try:
            d["hints"] = json.loads(d["hints"])
        except Exception:
            pass
        return d
    finally:
        conn.close()


def get_lab_answer(assignment_id):
    """Return the stored expected lab answer for an assignment (server-only)."""
    conn = db.get_connection()
    try:
        row = conn.execute(
            "SELECT v.expected_answer FROM team_challenge_assignments a "
            "JOIN challenge_variants v ON a.variant_id = v.id "
            "WHERE a.id=?", (assignment_id,)).fetchone()
        return row["expected_answer"] if row else ""
    finally:
        conn.close()


def generate_secret_flag(index):
    """Generate a unique flag token like CPR1-XXXX-XXXX."""
    part1 = "CPR1"
    token = secrets.token_hex(2).upper()      # 4 hex chars
    token2 = secrets.token_hex(2).upper()     # 4 hex chars
    return f"{part1}-{token}-{token2}"
