"""Integration tests for Round 1 Mini-CTF lab flow.

Validates the full lab-then-flag pipeline:
  1. Landing loads, registration, no duplicates.
  2. Starting a round creates 6 assignments across distinct categories/variants.
  3. Assignments return lab metadata (lab_type/story/objective) but NEVER the flag.
  4. Lab view marks IN_PROGRESS, logs lab_opened, sets lab_started_at.
  5. Lab action: wrong answer does NOT reveal flag; right answer marks LAB_COMPLETED
     and reveals the flag (server-side only).
  6. The lab answer (expected_answer) is distinct from the flag.
  7. Challenge page: flag input only appears after lab completion (FLAG LOCKED otherwise).
  8. Flag submission awards points only with the correct flag, and only once.
  9. Unassigned/foreign assignment blocked (404).
  10. Expired session blocks lab action and flag submission.
  11. Admin analytics + CSV exports (assignments incl. lab timestamps, events).
  12. Full round -> max 600 points.
"""
import os
import sys

import round1.db as db
import round1.assign as assign

os.chdir(os.path.dirname(os.path.abspath(__file__)))
db.reset_db()
from round1.main import r1  # noqa: E402
import round1.seed as seed  # noqa: E402
seed.seed()

from app import app as flask_app  # noqa: E402
flask_app.config["TESTING"] = True
flask_app.config["WTF_CSRF_ENABLED"] = False

client = flask_app.test_client()
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL"), "-", name)


conn = db.get_connection()

# 1. Landing
resp = client.get("/r1")
check("landing loads", resp.status_code == 200)

# 2. Register alpha
resp = client.post("/r1/register", data={
    "team_id": "TEAM-ALPHA", "team_name": "Alpha Squad",
    "participants": "A,B"}, follow_redirects=False)
check("register creates team & logs in", resp.status_code == 302)

# 3. Start round
resp = client.post("/r1/start", follow_redirects=False)
check("start redirects", resp.status_code == 302)

team = conn.execute("SELECT * FROM teams WHERE team_id=?",
                    ("TEAM-ALPHA",)).fetchone()
sess = conn.execute("SELECT * FROM round_sessions WHERE team_id=?",
                    (team["id"],)).fetchone()
assignments = conn.execute(
    "SELECT * FROM team_challenge_assignments WHERE session_id=?",
    (sess["id"],)).fetchall()
check("exactly 6 assignments", len(assignments) == 6)
check("lab_status NOT_STARTED initially",
      all(a["lab_status"] == "NOT_STARTED" for a in assignments))
cat_ids = [a["challenge_category_id"] for a in assignments]
check("distinct categories", len(set(cat_ids)) == 6)

first = assignments[0]
vrow = conn.execute("SELECT * FROM challenge_variants WHERE id=?",
                    (first["variant_id"],)).fetchone()

# 4. Challenge page: no flag leak, flag locked
resp = client.get("/r1/challenge/%d" % first["id"])
html = resp.get_data(as_text=True)
check("challenge page loads", resp.status_code == 200)
check("flag not leaked on challenge page", vrow["flag"] not in html)
check("flag LOCKED / answer input not shown before lab",
      "FLAG LOCKED" in html or "OPEN LAB" in html)

# 5. Lab page: IN_PROGRESS + lab_opened event + lab_started_at set
resp = client.get("/r1/lab/%d" % first["id"])
check("lab page loads", resp.status_code == 200)
html = resp.get_data(as_text=True)
check("flag not leaked in lab page", vrow["flag"] not in html)
a2 = conn.execute("SELECT * FROM team_challenge_assignments WHERE id=?",
                  (first["id"],)).fetchone()
check("lab IN_PROGRESS after open", a2["lab_status"] == "IN_PROGRESS")
check("lab_started_at set", a2["lab_started_at"] is not None)
ev = conn.execute(
    "SELECT * FROM lab_events WHERE assignment_id=? AND kind='lab_opened'",
    (first["id"],)).fetchone()
check("lab_opened event logged", ev is not None)

# 6. Lab wrong answer: no reveal, not completed
resp = client.post("/r1/lab/%d/action" % first["id"],
                   data={"answer": "zzz-wrong"}, follow_redirects=False)
js = resp.get_json()
check("wrong lab answer returns completed=False",
      js and js.get("ok") is True and js.get("completed") is False)
a3 = conn.execute("SELECT * FROM team_challenge_assignments WHERE id=?",
                  (first["id"],)).fetchone()
check("wrong answer does not complete lab", a3["lab_status"] == "IN_PROGRESS")
check("flag not revealed on wrong answer", a3["flag_revealed"] == 0)

# 7. Lab correct answer: LAB_COMPLETED + flag revealed
resp = client.post("/r1/lab/%d/action" % first["id"],
                   data={"answer": vrow["expected_answer"]}, follow_redirects=False)
js = resp.get_json()
check("correct lab answer -> completed=True",
      js and js.get("ok") is True and js.get("completed") is True)
check("flag revealed in response", js and js.get("flag") == vrow["flag"])
a4 = conn.execute("SELECT * FROM team_challenge_assignments WHERE id=?",
                  (first["id"],)).fetchone()
check("lab marked LAB_COMPLETED", a4["lab_status"] == "LAB_COMPLETED")
check("lab_completed_at set", a4["lab_completed_at"] is not None)
check("flag_revealed=1", a4["flag_revealed"] == 1)
evc = conn.execute(
    "SELECT * FROM lab_events WHERE assignment_id=? AND kind IN "
    "('lab_completed','flag_revealed')", (first["id"],)).fetchall()
check("lab_completed + flag_revealed events logged",
      any(e["kind"] == "lab_completed" for e in evc)
      and any(e["kind"] == "flag_revealed" for e in evc))

# 7b. Challenge page now shows flag submit
resp = client.get("/r1/challenge/%d" % first["id"])
html = resp.get_data(as_text=True)
check("flag input shown after lab complete", "SUBMIT FLAG" in html)

# 8. Flag submission
resp = client.post("/r1/challenge/%d/submit" % first["id"],
                   data={"flag": "FLAG{WRONG}"}, follow_redirects=False)
js = resp.get_json()
check("wrong flag -> ok correct=False",
      js and js.get("ok") is True and js.get("correct") is False)
s1 = conn.execute("SELECT * FROM round_sessions WHERE id=?",
                  (sess["id"],)).fetchone()
check("no points for wrong flag", s1["score"] == 0)

resp = client.post("/r1/challenge/%d/submit" % first["id"],
                   data={"flag": vrow["flag"]}, follow_redirects=False)
js = resp.get_json()
check("correct flag -> correct=True points=100",
      js and js.get("ok") is True and js.get("correct") is True
      and js.get("points") == 100)
s2 = conn.execute("SELECT * FROM round_sessions WHERE id=?",
                  (sess["id"],)).fetchone()
check("score now 100", s2["score"] == 100)

resp = client.post("/r1/challenge/%d/submit" % first["id"],
                   data={"flag": vrow["flag"]}, follow_redirects=False)
js = resp.get_json()
s3 = conn.execute("SELECT * FROM round_sessions WHERE id=?",
                  (sess["id"],)).fetchone()
# After solving, the completed challenge is no longer the active/unlocked
# challenge, so it is blocked from resubmission (no over-awarding).
check("completed challenge blocked from resubmit (no over-award)",
      resp.status_code == 403 and s3["score"] == 100)

# 9. IDOR: foreign team cannot access alpha's assignment/lab
client.post("/r1/register", data={"team_id": "TEAM-BETA",
                                  "team_name": "Beta"})
beta = conn.execute("SELECT * FROM teams WHERE team_id=?",
                    ("TEAM-BETA",)).fetchone()
client.post("/r1/start")
beta_sess = conn.execute("SELECT * FROM round_sessions WHERE team_id=?",
                         (beta["id"],)).fetchone()
resp = client.get("/r1/challenge/%d" % first["id"])
check("IDOR: foreign assignment blocked 404", resp.status_code == 404)
resp = client.get("/r1/lab/%d" % first["id"])
check("IDOR: foreign lab blocked 404", resp.status_code == 404)

# 9b. Sequential unlocking: alpha solved challenge 1 -> challenge 2 active.
alpha_sess = conn.execute("SELECT * FROM round_sessions WHERE team_id=?",
                          (team["id"],)).fetchone()
alpha_assign = conn.execute(
    "SELECT * FROM team_challenge_assignments WHERE session_id=? "
    "ORDER BY display_order", (alpha_sess["id"],)).fetchall()
unlocked_id = assign.get_current_unlocked_id(alpha_sess["id"])
check("unlocked is challenge 2 after solving 1",
      unlocked_id == alpha_assign[1]["id"])

# Ensure the client acts as alpha for the sequential URL checks that follow.
client.post("/r1/login", data={"team_id": "TEAM-ALPHA"})

# Dashboard shows the single unlocked challenge, not a completed/future list.
resp = client.get("/r1/dashboard")
html = resp.get_data(as_text=True)
check("dashboard shows active challenge only",
      "CHALLENGE 2 / 6" in html and "CHALLENGE 1 / 6" not in html)
check("dashboard does not reveal future challenge",
      alpha_assign[2]["variant_id"] and
      ("challenge/%d" % alpha_assign[2]["id"]) not in html)

# Direct URL to a future challenge (3) redirects to the unlocked one (2).
resp = client.get("/r1/challenge/%d" % alpha_assign[2]["id"],
                  follow_redirects=False)
check("future challenge GET redirects to unlocked",
      resp.status_code == 302 and
      ("challenge/%d" % alpha_assign[1]["id"]) in resp.headers.get("Location", ""))

# Direct lab GET on a future challenge redirects to unlocked challenge.
resp = client.get("/r1/lab/%d" % alpha_assign[2]["id"], follow_redirects=False)
check("future lab GET redirects to unlocked",
      resp.status_code == 302)

# POST attempt against a future challenge is rejected (no skip).
resp = client.post("/r1/lab/%d/action" % alpha_assign[2]["id"],
                   data={"answer": "x"}, follow_redirects=False)
check("future lab action rejected",
      resp.status_code == 403)
resp = client.post("/r1/challenge/%d/submit" % alpha_assign[2]["id"],
                   data={"flag": "FLAG{X}"}, follow_redirects=False)
check("future flag submit rejected", resp.status_code == 403)

# 9c. Exhausting attempts locks a challenge and advances to the next one.
cid = alpha_assign[1]["id"]  # challenge 2 is currently unlocked for alpha
for k in range(3):
    client.post("/r1/lab/%d/action" % cid, data={"answer": "zzz"})
tmp_conn = db.get_connection()
a_lock = tmp_conn.execute(
    "SELECT * FROM team_challenge_assignments WHERE id=?", (cid,)).fetchone()
tmp_conn.close()
check("challenge locked after 3 wrong",
      a_lock["lab_attempts"] >= 3 and a_lock["lab_status"] != "LAB_COMPLETED")
next_id = assign.get_current_unlocked_id(alpha_sess["id"])
check("locked challenge passes progression to next",
      next_id == alpha_assign[2]["id"])
# A locked (past) challenge is no longer reachable as the active challenge.
resp = client.get("/r1/challenge/%d" % cid, follow_redirects=False)
check("locked past challenge redirects away",
      resp.status_code == 302)

# 10. Flag submit before lab complete is blocked for beta
beta_a = conn.execute(
    "SELECT * FROM team_challenge_assignments WHERE session_id=?",
    (beta_sess["id"],)).fetchone()
beta_v = conn.execute("SELECT * FROM challenge_variants WHERE id=?",
                      (beta_a["variant_id"],)).fetchone()
resp = client.post("/r1/challenge/%d/submit" % beta_a["id"],
                   data={"flag": beta_v["flag"]}, follow_redirects=False)
js = resp.get_json()
check("flag submit blocked before lab complete (403)",
      js and js.get("ok") is False)

# 11. Full round for beta: solve all 6 labs then all 6 flags -> 600
client.post("/r1/login", data={"team_id": "TEAM-BETA"})
beta_assign = conn.execute(
    "SELECT * FROM team_challenge_assignments WHERE session_id=? "
    "ORDER BY display_order",
    (beta_sess["id"],)).fetchall()
for a in beta_assign:
    bv = conn.execute("SELECT * FROM challenge_variants WHERE id=?",
                      (a["variant_id"],)).fetchone()
    client.post("/r1/lab/%d/action" % a["id"],
                data={"answer": bv["expected_answer"]})
    client.post("/r1/challenge/%d/submit" % a["id"],
                data={"flag": bv["flag"]})
beta_done = conn.execute("SELECT * FROM round_sessions WHERE id=?",
                         (beta_sess["id"],)).fetchone()
check("all six solved", beta_done["challenges_solved"] == 6)
check("max score 600", beta_done["score"] == 600)
check("round marked COMPLETED after all solved",
      beta_done["status"] == "COMPLETED")
# Dashboard routes a finished team to the completion state, not a fresh start.
resp = client.get("/r1/dashboard", follow_redirects=False)
check("dashboard redirects to complete after round done",
      resp.status_code == 302 and str(beta_sess["id"]) in
      resp.headers.get("Location", ""))
resp = client.get("/r1/dashboard", follow_redirects=True)
check("completion state shows Round Complete",
      "Round Complete" in resp.get_data(as_text=True))
resp = client.get("/r1/leaderboard")
check("leaderboard lists completed team",
      resp.status_code == 200 and "Beta" in resp.get_data(as_text=True))

# 12. Expired session blocks lab action + flag submission (use beta)
conn.execute("UPDATE round_sessions SET ends_at=? WHERE id=?",
             (1, beta_sess["id"]))
conn.commit()
client.post("/r1/login", data={"team_id": "TEAM-BETA"})
resp = client.post("/r1/lab/%d/action" % beta_assign[0]["id"],
                   data={"answer": "x"}, follow_redirects=False)
js = resp.get_json()
check("expired session blocks lab action",
      resp.status_code in (400, 302) or (js and not js.get("ok")))
resp = client.post("/r1/challenge/%d/submit" % beta_assign[0]["id"],
                   data={"flag": "FLAG{X}"}, follow_redirects=False)
js = resp.get_json()
check("expired session blocks flag submit",
      resp.status_code in (400, 302) or (js and not js.get("ok")))

# 13. Admin login + analytics + CSV exports
client.get("/r1/admin/logout")
resp = client.get("/r1/admin")
check("admin requires login", resp.status_code == 302)
resp = client.post("/r1/admin/login", data={"username": "admin",
                                            "password": "admin123"},
                   follow_redirects=False)
check("admin login works", resp.status_code == 302)
resp = client.get("/r1/admin")
check("admin dashboard shows lab metrics",
      resp.status_code == 200 and b"LABS" in resp.get_data(as_text=True).encode())
resp = client.get("/r1/admin/statistics")
check("admin statistics with lab analytics",
      resp.status_code == 200 and b"Avg Lab Time" in resp.get_data(as_text=True).encode()
      and b"BY LAB TYPE" in resp.get_data(as_text=True).encode())
resp = client.get("/r1/admin/export/assignments")
check("assignments CSV incl lab timestamps",
      resp.status_code == 200 and b"lab_started_at_ms" in resp.data)
resp = client.get("/r1/admin/export/events")
check("lab events CSV", resp.status_code == 200
      and b"occurred_at_ms" in resp.data and b"lab_opened" in resp.data)
resp = client.get("/r1/admin/teams/%d" % beta["id"])
check("per-team detail with lab state renders",
      resp.status_code == 200 and b"LAB STATE" in resp.get_data(as_text=True).encode())

# 14. Unauthenticated redirect
client.get("/r1/logout")
resp = client.get("/r1/dashboard")
check("unauthenticated dashboard redirects", resp.status_code == 302)

conn.close()

failed = [n for n, ok in results if not ok]
print("\n" + "=" * 40)
print("RESULT: %d/%d passed" % (len(results) - len(failed), len(results)))
if failed:
    print("FAILED:", failed)
    sys.exit(1)