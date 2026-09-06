"""Unified single-link project helpers.

Bridges Round 1 (Cyber Puzzle, backed by round1.db) and Round 2
(Cyber Detective, in-memory session) so a team signs in ONCE from a single
landing page and moves through Round 1 -> Round 2 sequentially.

Session keys:
    'team'     -> Round 2 team dict (existing)
    'r1_team'  -> Round 1 team row id (existing)
    'r1_profile'-> cached Round 1 team_name/team_id for the hub header
"""
import round1.db as db
import round1.assign as assign
MODIFY THE EXISTING ROUND 1 CYBER PUZZLE WEBSITE

IMPORTANT:
This is an EXISTING working website.

DO NOT rebuild the website from scratch.

DO NOT remove, reset, overwrite, or break ANY functionality that has already been implemented.

All previously requested Round 1 functionality must remain fully working.

The supplied reference image is ONLY for the new UI/visual direction.

REFERENCE UI:
Use the uploaded reference image as the visual design reference for the Round 1 participant dashboard.

The target design should feel like a professional futuristic cybersecurity competition dashboard with:
- Dark black/blue background
- Neon cyan/green accents
- Cybersecurity/Hacker aesthetic
- Thin glowing borders
- Technical typography
- Dashboard-style panels
- Professional spacing
- High contrast
- Modern competition interface
- Subtle futuristic visual effects

==================================================
1. KEEP ALL EXISTING FUNCTIONALITY
==================================================

The following previously implemented functionality MUST remain unchanged:

### Round 1 registration
Existing route:

/r1/register

Keep the existing registration process.

### Rules & Regulations popup

When the Round 1 registration/main page is opened:

Automatically display the Rules & Regulations popup.

The user must read the rules and click:

"READ & VERIFIED"

After clicking:
- Close the popup.
- Remove the overlay.
- Allow the participant to continue.
- Do not reset registration information.
- Do not remove this functionality.

Do NOT add an X close button if the existing requirement says the popup can only be closed through "READ & VERIFIED".

==================================================
2. SEQUENTIAL CHALLENGE SYSTEM — MUST REMAIN
==================================================

The Round 1 participant must NOT see all six challenges simultaneously.

Only ONE challenge can be visible at a time.

Flow:

Challenge 1
↓
Complete Challenge 1
↓
Challenge 2 unlocks
↓
Complete Challenge 2
↓
Challenge 3 unlocks
↓
Complete Challenge 3
↓
Challenge 4 unlocks
↓
Complete Challenge 4
↓
Challenge 5 unlocks
↓
Complete Challenge 5
↓
Challenge 6 unlocks
↓
Round 1 Complete

Do NOT display future challenge cards.

Do NOT display a six-card grid.

Do NOT allow the participant to preview future challenges.

Do NOT allow skipping challenges.

If Challenge 3 is currently active, only Challenge 3 should be visible.

==================================================
3. ATTEMPT SYSTEM — MUST REMAIN
==================================================

Every Round 1 question has a maximum of 3 attempts.

Maximum:

3 attempts per question.

The backend must enforce this limit.

The frontend must also disable interaction appropriately.

Never allow:
- 4th attempt
- Duplicate submission
- Replay submission
- URL manipulation to bypass attempts
- Refreshing to reset attempts

==================================================
4. SUBMISSION FREEZE — MUST REMAIN
==================================================

When the participant submits an answer:

Immediately freeze the submitted question according to the existing Round 1 logic.

Disable:
- Answer input
- Submit button
- Editing
- Duplicate submission

The participant must not be able to modify the submitted answer outside the permitted flow.

Persist this state across page refreshes.

==================================================
5. GREEN / BLUE STATUS SYSTEM — MUST REMAIN
==================================================

Keep the existing green/blue visual status system.

Use:

GREEN
= Successfully completed/correct

BLUE
= Submitted/locked/current status according to the existing application logic

Do not expose the correct answer.

Do not introduce unnecessary answer-revealing error states.

==================================================
6. NO LEADERBOARD FOR PARTICIPANTS
==================================================

The participant/user MUST NOT see a leaderboard anywhere in the Round 1 participant dashboard.

Remove/hide:
- Rankings
- Other team scores
- Participant positions
- Leaderboard cards
- Competitive ranking information

The backend leaderboard functionality may remain if required for administrators.

Only hide it from the participant-facing Round 1 interface.

==================================================
7. NOW CHANGE THE VISUAL DESIGN
==================================================

Using the supplied reference image, redesign ONLY the participant-facing Round 1 dashboard appearance.

Do NOT change the underlying functionality.

The new UI should visually resemble the reference image.

==================================================
8. NEW DASHBOARD STRUCTURE
==================================================

Create a professional cybersecurity dashboard layout.

HEADER:

Top navigation should contain:

LEFT:
R1 logo/icon

CYBER
PUZZLE

Optional small technical navigation text such as:

THINK // EXPLOIT // SOLVE // SECURE

CENTER:
DASHBOARD
RULES

RIGHT:
Team name
● R1 status
Profile/avatar
Logout

Keep the existing team/session information and functionality.

==================================================
9. LEFT SIDEBAR
==================================================

Add a compact cybersecurity-style sidebar similar to the reference.

Possible sections:

OVERVIEW
CHALLENGE
PROGRESS
PROFILE

IMPORTANT:

Do NOT add LEADERBOARD to the participant interface.

The sidebar should be visually integrated into the existing website.

Use simple technical icons.

==================================================
10. MAIN CONTENT AREA
==================================================

The main content should focus entirely on the CURRENT challenge.

At the top:

MY ROUND

ROUND 1

Then:

CHALLENGE 1 / 6

or dynamically:

CHALLENGE 2 / 6
CHALLENGE 3 / 6
etc.

Below that show only the currently unlocked challenge.

Example:

--------------------------------------------

CHALLENGE 1 / 6

CIPH
MEDIUM

CIPHER CHAIN

Cryptography

100 PTS

[ OPEN LAB → ]

--------------------------------------------

When Challenge 1 is completed, replace this content with Challenge 2.

Do NOT keep Challenge 1 beside it.

==================================================
11. PROGRESS PANEL
==================================================

Create a compact progress/status area inspired by the reference design.

Example:

ROUND 1 PROGRESS

● 1 / 6 SOLVED

PROGRESS BAR
████░░░░░░

TIME LEFT
29:36

SCORE
100

Keep the existing timer and score logic.

Do not invent new score calculations.

==================================================
12. CURRENT CHALLENGE CARD
==================================================

The active challenge should be the primary visual focus.

Use:

- Large dark panel
- Neon cyan/green border
- Subtle glow
- Rounded/technical corners
- Challenge identifier
- Difficulty
- Challenge title
- Category
- Points
- Existing "OPEN LAB" functionality

The card should feel like a cybersecurity mission console rather than a normal website card.

Do NOT change challenge content.

==================================================
13. CYBERSECURITY VISUAL DETAILS
==================================================

Use the reference image as inspiration for:

- Neon cyan borders
- Green status indicators
- Dark navy/black panels
- Technical grid backgrounds
- Subtle circuit/code patterns
- Thin glowing separators
- Terminal-inspired labels
- Small uppercase technical labels
- Futuristic HUD-style components
- Subtle background graphics
- Professional cyber competition aesthetic

Keep effects subtle.

Do NOT make the interface visually noisy.

The challenge content must remain highly readable.

==================================================
14. SYSTEM STATUS PANEL
==================================================

A small status panel can be placed near the challenge area.

Example:

SYSTEM STATUS

> FIREWALL        : ACTIVE
> CHALLENGE       : ONLINE
> SESSION         : SECURE
> TEAM            : CONNECTED

This is visual information only.

Do not create fake dynamic data.

If these values already exist in the application, connect them to the real state.

==================================================
15. MISSION / ACTIVITY PANEL
==================================================

A small mission/activity panel may be used on the right side.

Example:

MISSION LOG

[12:14] Challenge initialized
[12:16] Session verified
[12:20] Challenge active

Only display real application events where possible.

Do not expose answers or future challenges.

==================================================
16. IMPORTANT — DO NOT SHOW ALL CHALLENGES
==================================================

This is one of the most important requirements.

DO NOT create:

[Challenge 1] [Challenge 2]
[Challenge 3] [Challenge 4]
[Challenge 5] [Challenge 6]

Instead:

                 CURRENT MISSION

                 CHALLENGE 1 / 6

                 Cipher Chain

                 [ OPEN LAB ]

Only the current challenge exists visually.

After completion:

                 CHALLENGE 2 / 6

                 File Magic

                 [ OPEN LAB ]

Then Challenge 3, etc.

==================================================
17. ROUND COMPLETE SCREEN
==================================================

After Challenge 6 is successfully completed, show a professional completion screen inspired by the reference image.

Example:

✓ COMPLETED

ROUND 1 COMPLETE

Your Round 1 session has concluded.

600 / 600
6 / 6 CHALLENGES SOLVED

Then use the existing appropriate next-step action.

Do not display the six challenge cards.

==================================================
18. RESPONSIVE DESIGN
==================================================

The new dashboard must work properly on:

Desktop
Laptop
Tablet
Mobile

On smaller screens:

- Sidebar should collapse appropriately.
- Panels should stack.
- Current challenge remains the primary focus.
- No horizontal overflow.
- Timer remains visible.
- Team information remains accessible.

==================================================
19. BACKEND SECURITY
==================================================

Do not implement the visual sequential flow only in frontend JavaScript.

Backend must enforce:

current unlocked challenge
completed challenges
attempt count
submission state
question lock state
Round 1 completion

A participant must not be able to bypass the sequence by manually modifying:

URL
challenge ID
API request
frontend state
browser refresh

Future challenges must remain inaccessible until the current challenge is completed.

==================================================
20. PRESERVE EXISTING ROUTES
==================================================

Do not break existing routes.

In particular preserve:

/r1/register

and the existing Round 1 challenge routes/API endpoints.

If route changes are absolutely necessary, maintain backward compatibility.

==================================================
21. FINAL DESIGN GOAL
==================================================

The final participant dashboard should look like a professional cybersecurity competition platform.

REFERENCE STYLE:

Dark futuristic cyber command center
+
Neon cyan/green HUD interface
+
Technical panels
+
Mission console
+
Clean typography
+
Professional spacing

BUT:

FUNCTIONALITY > DECORATION.

Do not sacrifice usability for visual effects.

==================================================
FINAL ACCEPTANCE TEST
==================================================

Verify all of the following before considering the modification complete:

[ ] Rules popup appears on Round 1 entry.
[ ] "READ & VERIFIED" closes the popup.
[ ] Only one challenge is visible at a time.
[ ] Challenge 2 remains hidden until Challenge 1 is completed.
[ ] Challenge 3 remains hidden until Challenge 2 is completed.
[ ] Same sequential logic continues through Challenge 6.
[ ] Maximum 3 attempts per question.
[ ] Submitted answer freezes correctly.
[ ] Refresh does not reset attempts.
[ ] Refresh does not reset challenge progression.
[ ] Future challenges cannot be accessed directly.
[ ] Green/blue status behavior remains.
[ ] No participant leaderboard.
[ ] Existing timer remains functional.
[ ] Existing scoring remains functional.
[ ] Existing challenge content remains unchanged.
[ ] Existing registration remains functional.
[ ] Existing routes remain functional.
[ ] New UI visually follows the supplied reference image.
[ ] Desktop and mobile layouts work correctly.

MOST IMPORTANT:

Do not remove any previously implemented functionality.

This is a UI modernization of the existing Round 1 website, NOT a replacement of the existing application logic.


def get_round1_profile():
    """Return a small dict describing the Round 1 team (or None)."""
    team_id = __import__("flask").session.get("r1_team")
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
    """Round 2 is unlocked only after Round 1 is completed."""
    return round1_stage() == "complete"


def is_round2_logged_in():
    return "team" in __import__("flask").session


def is_logged_in():
    return is_round2_logged_in() or get_round1_profile() is not None