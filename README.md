# Cyber Detective 2026 — Forensic Investigation & Cyber Puzzle Platform

A self-contained, single-instance Flask application that runs a two-round technical
competition:

- **Round 1 — Mixed Fundamentals (Cyber Puzzles)**: timed, variant-based capture-the-flag
  style challenges (Web, Crypto, Forensics, Network, OSINT) with a virtual lab sandbox,
  hints, and normalized answer validation.
- **Round 2 — Digital Forensics (Investigation)**: narrative case investigations where
  teams interview persons of interest, examine evidence artifacts, and complete task
  stations to reconstruct what happened.

The product ships with a full **Admin Control Center** for team management, round control,
content authoring, live monitoring, audit trails, scoring, and leaderboards.

This document covers the entire project: architecture, setup, file structure, data model,
and the admin / participant feature surface.

---

## 1. Overview

| Property          | Value                                                        |
| ----------------- | ------------------------------------------------------------ |
| Application       | Cyber Detective 2026                                         |
| Type              | Flask (Python) web application                               |
| Database          | SQLite 3 (single file: `round1/round1.db`)                   |
| Rendering         | Server-side Jinja2 templates + vanilla JavaScript            |
| Auth              | Session cookies (participants + admin)                       |
| Port              | `127.0.0.1:5000` (localhost only, single process)            |
| Python            | 3.x (stdlib + Flask / Werkzeug only)                         |
| Default admin     | `admin` / `admin123`                                          |

Both rounds are represented with **separate access credentials per round** and enforce
session/attempt limits configured by the administrator.

## 2. Key Features

### Participant side
- Unified landing page with round availability notices.
- **Round 1**: challenge dashboard, per-challenge assignments, workspaces, staged virtual
  labs, hint economy, timed sessions, and real-time validation of answers.
- **Round 2**: case list, case detail with stations/persons/evidence, evidence board with
  downloadable artifacts, in-case notes, and final report submission + scoring.
- Rules pages, completion screens, and a global scoreboard / leaderboard.

### Admin side
- **Control Center Overview**: live stats (teams, logins, completions, submissions).
- **Teams (R1 / R2)**: create, import (CSV), edit, enable/disable, provision round access
  IDs, reset progress, clear live sessions.
- **Round 1 content**: challenge gallery (visual cards, filterbar), question/variant bank,
  validation modes, scoring modes, settings, per-challenge previews.
- **Round 2 content**: case management, investigation tasks (stations), person directory,
  evidence items + artifact uploads, validation, scoring, settings, case previews.
- **Ops**: live monitoring, audit log, submission review, leaderboards, system settings,
  CSV exports.
- A polished, dark, fixed on-screen admin frame with internal scrolling.

## 3. Tech Stack

- **Backend**: Python 3, Flask, Werkzeug (password hashing).
- **Data**: `sqlite3` (stdlib), seeded + administered via SQL.
- **Frontend**: Jinja2 templates, custom CSS design system (`admin-panel.css`,
  `design-system.css`, `cyber-hud.css`, `forensics.css`, `pages.css`), vanilla JS.
- **Artifacts**: static evidence files (`evidence/`) served for download during Round 2.

Dependencies (all installable via pip):

```
flask
```

## 4. Getting Started

```bash
# 1. (Recommended) create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. install Flask
pip install flask

# 3. run the application
python app.py
```

Then open <http://127.0.0.1:5000>.

- Admin panel: <http://127.0.0.1:5000/admin> (login `admin` / `admin123`).
- The app intentionally runs **one server on 127.0.0.1:5000** with `debug=False`.
  Templates, routes, and CSS are cached in-process — **restart the server after any
  code/template/static change**:

```bash
kill $(lsof -ti tcp:5000); sleep 1; nohup python3 app.py > /tmp/flask_srv.log 2>&1 &
```

## 5. Project Structure

```
Forencis_Csae
├── app.py                        # Main Flask app: participant R2 + all admin routes
├── access.py                     # Participant/admin auth, round enforcement, sessions
├── admin_ops.py                  # Admin data operations + audit + seeding
├── unify.py / unify.MD           # Migration / unification helper notes
├── round1/
│   ├── __init__.py
│   ├── main.py                   # Round 1 blueprint (participant + R1 legacy admin)
│   ├── db.py                     # SQLite connection + schema (round1.db)
│   ├── assign.py                 # Challenge assignment / attempt limits
│   ├── lab.py                    # Virtual lab workspace logic
│   ├── seed.py                   # Seed data (12 challenges, 48 variants, 3 R2 cases)
│   ├── round1.db                 # The single SQLite database
│   ├── test_integration.py       # (stale) legacy integration test
│   └── templates/                # Round 1 participant + legacy R1 admin templates
├── templates/
│   ├── base.html, landing.html, home.html, start.html
│   ├── dashboard.html, case.html, cases.html, station.html
│   ├── evidence_board.html, report.html, score.html, scoreboard.html
│   ├── challenge_detail.html, puzzle_lab.html, r2_login.html
│   ├── admin_base.html           # Shared admin frame (fixed on-screen shell)
│   └── admin/                    # Admin Control Center pages (see §5.1)
├── static/
│   ├── css/                      # Design systems + admin-panel.css
│   ├── js/app.js                 # Shared front-end helpers
│   └── img/                      # Brand art
├── evidence/                     # Round 2 downloadable artifacts (e.g. .pcap, .eml)
└── data/
    └── case_counter.txt          # Round 2 case-code sequence counter
```

### 5.1 Admin templates (`templates/admin/`)

| Page                  | File                                   |
| --------------------- | -------------------------------------- |
| Overview (home)       | `overview.html`                        |
| Teams R1 / R2         | `teams_round1.html`, `teams_round2.html` |
| Team profile          | `team_profile.html`                    |
| R1 Overview           | `round1/overview.html`                 |
| R1 Challenges         | `round1/challenges.html`               |
| R1 Questions          | `round1/questions.html`                |
| R1 Validation         | `round1/validation.html`               |
| R1 Scoring            | `round1/scoring.html`                  |
| R1 Settings           | `round1/settings.html`                 |
| R1 Preview            | `round1/preview.html`                  |
| R2 Overview           | `round2/overview.html`                 |
| R2 Cases              | `round2/cases.html`                    |
| R2 Case Detail        | `round2/case_detail.html`              |
| R2 Investigation Tasks| `round2/tasks.html`                    |
| R2 Questions          | `round2/questions.html`                |
| R2 Validation         | `round2/validation.html`               |
| R2 Scoring            | `round2/scoring.html`                  |
| R2 Settings           | `round2/settings.html`                 |
| R2 Evidence           | `round2/evidence.html`                 |
| R2 Preview            | `round2/preview.html`                  |
| LiveMonitoring        | `monitoring.html`                      |
| Audit Log             | `audit.html`                           |
| Submissions / Review  | `submissions.html`, `review.html`      |
| Leaderboard           | `leaderboard.html`                     |
| System Settings       | `system.html`                          |

## 6. Data Model (SQLite — `round1/round1.db`)

| Table                          | Purpose                                              |
| ------------------------------ | ---------------------------------------------------- |
| `admins`                       | Admin accounts (hashed passwords)                    |
| `teams`                        | Authorized teams: R1/R2 access IDs, activity flags   |
| `round_settings`               | Per-round status, timer, max attempts, access flag   |
| `challenge_categories`         | Round 1 challenges (code, domain, difficulty, points) |
| `challenge_variants`           | Round 1 question variants + answer validation modes  |
| `team_challenge_assignments`   | R1 assignments per team + progress/state             |
| `participant_sessions`         | R1 session lifecycle (start/completion)              |
| `round_sessions`               | Round session meta per team                          |
| `submissions`                  | Answer submissions + correctness                     |
| `hint_usage`                   | Hint consumption log                                 |
| `lab_events`                   | Virtual lab interaction log                          |
| `r2_cases`                     | Round 2 investigation cases                          |
| `r2_stations`                  | Investigation task stations                          |
| `r2_persons`                   | Persons of interest                                  |
| `r2_evidence`                  | Evidence items + artifact filenames                  |
| `admin_audit_log`              | Admin action audit trail                             |

Seed data: **12 challenges**, **48 variants**, **3 Round 2 cases**, default round settings
(R1: 30 min / 3 attempts / ACTIVE; R2: 90 min / 5 attempts / ACTIVE).

## 7. Main Routes

### Participant (app)
`/`, `/home`, `/start`, `/login`, `/logout`, `/r2/login`, `/r2`, `/dashboard`,
`/case`, `/station`, `/evidence/<station_id>`, `/evidence/download/<path>`,
`/evidence-board`, `/api/notes`, `/api/submit`, `/report`, `/score`, `/scoreboard`,
`/cases`, `/challenge/<cid>`, `/puzzle-lab`, `/reset`.

### Round 1 (blueprint `r1`)
`/r1`, `/r1/rules`, `/r1/register`, `/r1/register/rules-ack`, `/r1/login`,
`/r1/logout`, `/r1/start`, `/r1/dashboard`, `/r1/challenge/<id>`,
`/r1/challenge/<id>/submit`, `/r1/lab/<id>`, `/r1/lab/<id>/action`,
`/r1/lab/<id>/next`, `/r1/challenge/<id>/hint`, `/r1/complete/<session_id>`,
plus legacy `/r1/admin/*` routes.

### Admin (app)
`/admin`, `/admin/monitoring`, `/admin/audit`, `/admin/audit-log`,
`/admin/submissions`, `/admin/review`, `/admin/leaderboard`, `/admin/system`,
`/admin/teams/round1`, `/admin/teams/round2`, `/admin/teams/<id>/profile`,
`/admin/logins/*`, `/admin/teams/import`, `/admin/teams/export`,
`/admin/round1/*` (overview, challenges, questions, validation, scoring, settings,
api/…, preview), `/admin/round2/*` (overview, cases, case_detail, tasks, questions,
validation, scoring, settings, evidence, api/…, preview).

All admin endpoints require the admin session cookie; JSON prefill endpoints return
single-entity payloads so edit modals never blank fields.

## 8. Round Workflow

### Round 1 (Cyber Puzzles)
1. Admin enables Round 1 access and sets timer + max attempts in **R1 Settings**.
2. Team signs in at `/r1/login` using **team name + R1 access ID** (admin-provisioned).
3. Team receives a set of challenge assignments; each lets them open a challenge page,
   rotate through staged virtual lab actions, and request hints (log-aware).
4. Answers are validated with configurable modes (`NORMALIZED`, `EXACT`, `CONTAINS`,
   `CASE_SENSITIVE`); max attempts per lab are enforced from settings.
5. On completion the session closes and results flow to the leaderboard.

### Round 2 (Forensics)
1. Admin publishes cases. Teams sign in at `/r2/login` with **team name + R2 access ID**.
2. Team picks a case, explores evidence artifacts, interviews persons, and answers task
   stations (validation is normalized).
3. Teams submit a final written report and their score is computed across case progress.

## 9. Admin Control Center — quick guide

1. **Overview** — real-time status of teams, rounds, solved counts, submissions.
2. **Team Members (R1 / R2)** — create/edit teams, set round access IDs, toggle access,
   reset or clear sessions.
3. **Round 1 / Round 2 sections** — manage all content and round behavior.
4. **Live Monitoring / Audit Log / Submissions / Leaderboard / System Settings** —
   operational views and exports.

Style conventions: colors come from CSS custom properties (`--ap-*`) in
`static/css/admin-panel.css`. The admin shell (`admin_base.html`) is a fixed on-screen
frame: sidebar + topbar are locked, content scrolls internally.

## 10. Git & Deployment Notes

- Add a `.gitignore` covering `__pycache__/`, `.DS_Store`, `.venv/`, `/tmp` files,
  `round1.db` (optional — include if you want to ship seed data).
- Suggested first commit message: `Initial commit — Cyber Detective 2026 platform`.
- Keep `app.secret_key` out of public log output; it is currently a fixed dev key
  (`forencis-csae-secret-key-2026`) in `app.py:13`.
- The app binds only to `127.0.0.1:5000` — for remote hosting we'd expose it behind a
  reverse proxy (e.g., nginx + gunicorn).

## 11. Troubleshooting

| Symptom                              | Fix                                                            |
| ------------------------------------ | -------------------------------------------------------------- |
| Edits not reflected                  | Server caches routes/templates in-process — restart it.         |
| Admin panel looks unstyled / old     | Hard refresh (Cmd/Ctrl+Shift+R); CSS is cache-busted via `?v=`  |
| Edit modal does not open             | Ensure the server was restarted; modals use class `.open`       |
| Image screenshots can't be analyzed  | Use DOM/computed-style checks rather than visual screenshots    |
| `round1/test_integration.py` fails   | It tests the legacy self-registration flow (admin-provisioned teams replaced it) |

## 12. Useful one-liners

```bash
# restart server
kill $(lsof -ti tcp:5000); sleep 1; nohup python3 app.py > /tmp/flask_srv.log 2>&1 &
# check listeners
lsof -nP -iTCP:5000 -sTCP:LISTEN
# sanity checks
python3 -m py_compile app.py access.py admin_ops.py round1/main.py
```