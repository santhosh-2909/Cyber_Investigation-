import os
import re
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, abort, send_from_directory)

app = Flask(__name__)
app.secret_key = "forencis-csae-secret-key-2026"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidence")

# ---------------------------------------------------------------------------
# DATA MODELS
# ---------------------------------------------------------------------------

# Each case has: id, title, short title, story fields, 5 stations, person IDs
CASES = {
    "case1": {
        "id": "case1",
        "code": "CASE-A",
        "title": "The Ransomware Hold-Up",
        "file": "case1_ransomware.md",
        "company": "Meridian Logistics Pvt. Ltd.",
        "incident": "A phishing lure and a midnight encryption brought the company to its knees.",
        "objective": "Reconstruct the full attack chain and identify every person involved.",
        "stations": [
            {
                "id": "S1",
                "name": "Email Evidence",
                "domain": "Email Forensics",
                "desc": "Analyze the phishing email headers and mail server logs.",
                "evidence": "phish.eml",
                "question": "What IP sent the phishing email and what was the malicious attachment?",
                "finding": "sender_ip",
                "flag": "203.0.113.42",
                "hint": "Check the Received and Return-Path headers; SPF is failing.",
            },
            {
                "id": "S2",
                "name": "Network PCAP",
                "domain": "Network Forensics",
                "desc": "Examine the network capture for C2 beaconing.",
                "evidence": "traffic.pcap",
                "question": "What is the Command-and-Control server IP address?",
                "finding": "c2_ip",
                "flag": "198.51.100.77",
                "hint": "Look for periodic outbound connections on a high port.",
            },
            {
                "id": "S3",
                "name": "Malware Artifact",
                "domain": "Malware Triage",
                "desc": "Identify the ransomware family and its persistence key.",
                "evidence": "malware.zip",
                "question": "What is the ransomware family name and the persistence registry key?",
                "finding": "family",
                "flag": "BloodRansom",
                "hint": "Run strings on the binary; check the startup registry subkey.",
            },
            {
                "id": "S4",
                "name": "Access Logs",
                "domain": "Log Correlation",
                "desc": "Find the suspicious late-night admin login.",
                "evidence": "access_logs.txt",
                "question": "Which user logged in at the suspicious time just before encryption?",
                "finding": "patient_zero_user",
                "flag": "akhanna",
                "hint": "Cross-reference the DC login against the firewall log timeline.",
            },
            {
                "id": "S5",
                "name": "Ransom Evidence",
                "domain": "Crypto Tracing",
                "desc": "Decode the ransom note and trace the wallet.",
                "evidence": "ransom_note.txt",
                "question": "What is the bitcoin wallet address in the ransom note?",
                "finding": "wallet",
                "flag": "1A2b3C4d5E6f7G8h9I0j",
                "hint": "The wallet string is hidden in an obfuscated part of the note.",
            },
        ],
        "persons": [
            {
                "role": "Victim / Primary Target",
                "key": "victim",
                "answer": ["Meridian Logistics", "meridian"],
                "clue": "The organization that held the data.",
            },
            {
                "role": "Attacker / Ransomware Operator",
                "key": "attacker",
                "answer": ["Elias Vortex", "elias", "vortex"],
                "clue": "The actor demanding the ransom.",
            },
            {
                "role": "Patient-Zero User (insider who clicked)",
                "key": "insider",
                "answer": ["akhanna", "arjun khanna", "khanna", "arjun"],
                "clue": "The employee who opened the malicious attachment.",
            },
            {
                "role": "Accomplice",
                "key": "accomplice",
                "answer": ["", "none"],
                "clue": "Optional - was there an inside helper?",
            },
        ],
    },

    "case2": {
        "id": "case2",
        "code": "CASE-B",
        "title": "The Silent Insider Leak",
        "file": "case2_insider.md",
        "company": "Apex Retail Group",
        "incident": "A confidential pricing document appeared at a rival firm with no external breach.",
        "objective": "Trace how data walked out the front door and identify who leaked it.",
        "stations": [
            {
                "id": "S1",
                "name": "Email Headers",
                "domain": "Email Forensics",
                "desc": "Trace the internal email that exfiltrated the document.",
                "evidence": "trade_email.eml",
                "question": "Who sent the confidential document out of the company?",
                "finding": "sender",
                "flag": "dmehta",
                "hint": "Check the From field and the actual sending account in logs.",
            },
            {
                "id": "S2",
                "name": "PCAP Exfiltration",
                "domain": "Network Forensics",
                "desc": "Find the upload session in the network capture.",
                "evidence": "exfil.pcap",
                "question": "What external IP received the uploaded data?",
                "finding": "dest_ip",
                "flag": "192.0.2.88",
                "hint": "Search for a large one-way upload to a non-standard port.",
            },
            {
                "id": "S3",
                "name": "Document Metadata",
                "domain": "Digital Forensics",
                "desc": "Extract the author and editing device info from the leaked file.",
                "evidence": "leaked_doc.docx",
                "question": "What is the document author's username in the metadata?",
                "finding": "author",
                "flag": "dmehta",
                "hint": "Use strings or exiftool on the docx.",
            },
            {
                "id": "S4",
                "name": "Access Logs",
                "domain": "Log Analysis",
                "desc": "Find unauthorized access to the shared drive.",
                "evidence": "share_logs.txt",
                "question": "Which employee accessed the confidential file outside normal hours?",
                "finding": "access_user",
                "flag": "dmehta",
                "hint": "Look for a 02:00 AM access on the shared drive.",
            },
            {
                "id": "S5",
                "name": "Employee Records",
                "domain": "User Forensics",
                "desc": "Correlate HR records to a specific employee.",
                "evidence": "employee_records.txt",
                "question": "Which full employee name maps to all the clues?",
                "finding": "employee",
                "flag": "david mehta",
                "hint": "The department head with access to pricing.",
            },
        ],
        "persons": [
            {
                "role": "Victim / Data Owner",
                "key": "victim",
                "answer": ["Apex Retail Group", "apex"],
                "clue": "The company whose data was stolen.",
            },
            {
                "role": "Leaker / Insider Suspect",
                "key": "leaker",
                "answer": ["dmehta", "david mehta", "mehta", "david"],
                "clue": "The employee who sent the data out.",
            },
            {
                "role": "Receiver / Rival Contact",
                "key": "receiver",
                "answer": ["Nova Retail", "nova", "jasmin cole", "cole"],
                "clue": "The external party that received the data.",
            },
            {
                "role": "Accomplice",
                "key": "accomplice",
                "answer": ["", "none"],
                "clue": "Optional - was there an inside helper?",
            },
        ],
    },

    "case3": {
        "id": "case3",
        "code": "CASE-C",
        "title": "The CEO Fraud Deception",
        "file": "case3_bec.md",
        "company": "StellarWorks Manufacturing",
        "incident": "A six-figure payment was wired based on an email the CEO never sent.",
        "objective": "Prove the impersonation, trace the fraudster, and name everyone involved.",
        "stations": [
            {
                "id": "S1",
                "name": "Email Headers",
                "domain": "Email Forensics",
                "desc": "Trace the spoofed CEO email.",
                "evidence": "spoofed_ceo.eml",
                "question": "What is the real sender IP (SPF/DKIM failing)?",
                "finding": "sender_ip",
                "flag": "203.0.113.200",
                "hint": "The Return-Path does not match the From; SPF fails.",
            },
            {
                "id": "S2",
                "name": "Reply-To Analysis",
                "domain": "Email Forensics",
                "desc": "Find the attacker-controlled Reply-To address.",
                "evidence": "spoofed_ceo.eml",
                "question": "What Reply-To address would receive the fraud reply?",
                "finding": "reply_to",
                "flag": "accounts.verify@fraudmail.net",
                "hint": "Look at the Reply-To header - it differs from the CEO's real address.",
            },
            {
                "id": "S3",
                "name": "Wire Request",
                "domain": "Social Engineering",
                "desc": "Inspect the forged bank details in the email.",
                "evidence": "wire_request.txt",
                "question": "What is the fraudulent bank account number?",
                "finding": "account",
                "flag": "0987654321",
                "hint": "Compare against the legitimate vendor account list.",
            },
            {
                "id": "S4",
                "name": "Email Timeline",
                "domain": "Log Analysis",
                "desc": "Reconstruct the phishing delivery timeline.",
                "evidence": "mail_logs.txt",
                "question": "At what time was the spoofed email actually delivered?",
                "finding": "delivery_time",
                "flag": "2026-08-27 09:14",
                "hint": "Cross-check the Received trace timestamps.",
            },
            {
                "id": "S5",
                "name": "Money Trail",
                "domain": "OSINT / Network",
                "desc": "Trace where the funds were routed.",
                "evidence": "bank_transfer.txt",
                "question": "What is the destination account holder's name?",
                "finding": "beneficiary",
                "flag": "Rajan Iyer",
                "hint": "The funds moved from the fake account to a named beneficiary.",
            },
        ],
        "persons": [
            {
                "role": "Victim / Spoofed Person (CEO)",
                "key": "victim",
                "answer": ["sonia kapoor", "kapoor", "sonia"],
                "clue": "The CEO whose identity was impersonated.",
            },
            {
                "role": "Attacker / Fraudster",
                "key": "attacker",
                "answer": ["masked hacker", "hacker", "operator"],
                "clue": "The actor behind the spoofed email.",
            },
            {
                "role": "Compromised Insider (moved funds)",
                "key": "insider",
                "answer": ["arvind nair", "nair", "arvind"],
                "clue": "The finance employee who wired the money.",
            },
            {
                "role": "Money-Receiver / Beneficiary",
                "key": "beneficiary",
                "answer": ["rajan iyer", "iyer", "rajan"],
                "clue": "The person who received the fraudulent payment.",
            },
        ],
    },
}


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def normalize(text):
    if not text:
        return ""
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def normalize_flag(text):
    if not text:
        return ""
    return text.strip().lower()


# Representation of the attack / evidence chain per case for the evidence board
BOARDS = {
    "case1": [
        {"label": "EMAIL", "detail": "Phishing email received", "icon": "📧"},
        {"label": "MALWARE", "detail": "BloodRansom dropped via attachment", "icon": "🦠"},
        {"label": "NETWORK", "detail": "C2 beaconing to 198.51.100.77", "icon": "🌐"},
        {"label": "FILE SERVER", "detail": "FS01 encrypted 16:42 UTC", "icon": "🗄️"},
        {"label": "RANSOM", "detail": "Wallet 1A2b3C4d5E6f7G8h9I0j", "icon": "💰"},
    ],
    "case2": [
        {"label": "DOCUMENT", "detail": "Pricing file accessed 02:00", "icon": "📄"},
        {"label": "EMAIL", "detail": "Sent to external address", "icon": "📧"},
        {"label": "NETWORK", "detail": "Uploaded to 192.0.2.88", "icon": "🌐"},
        {"label": "RIVAL", "detail": "Nova Retail received it", "icon": "🏢"},
        {"label": "LEAK", "detail": "Insider: David Mehta", "icon": "🕵️"},
    ],
    "case3": [
        {"label": "SPOOFED EMAIL", "detail": "CEO impersonated", "icon": "📧"},
        {"label": "REPLY-TO", "detail": "fraudmail.net address", "icon": "✉️"},
        {"label": "WIRE REQUEST", "detail": "Forged bank details", "icon": "🏦"},
        {"label": "PAYMENT", "detail": "₹ routed to fake account", "icon": "💸"},
        {"label": "BENEFICIARY", "detail": "Rajan Iyer", "icon": "🕵️"},
    ],
}


# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "team" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "team" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    team_name = request.form.get("team_name", "").strip()
    team_id = request.form.get("team_id", "").strip()
    captain = request.form.get("captain", "").strip()
    if not (team_name and team_id and captain):
        return render_template("login.html", error="All fields are required.")
    # Assign case deterministically-ish but random per team via a rotating index
    case_list = list(CASES.keys())
    with open(os.path.join(BASE_DIR, "data", "case_counter.txt"), "a+") as f:
        pass
    counter = 0
    try:
        with open(os.path.join(BASE_DIR, "data", "case_counter.txt"), "r") as f:
            counter = int(f.read().strip() or "0")
    except Exception:
        counter = 0
    selected_case = case_list[counter % len(case_list)]
    counter += 1
    with open(os.path.join(BASE_DIR, "data", "case_counter.txt"), "w") as f:
        f.write(str(counter))
    session["team"] = {
        "name": team_name,
        "team_id": team_id,
        "captain": captain,
        "case": selected_case,
    }
    session["findings"] = {}      # station_id -> (value, status)
    session["persons"] = {}       # person_key -> {value, evidence, status}
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    case = CASES[session["team"]["case"]]
    return render_template("dashboard.html", team=session["team"], case=case)


@app.route("/case")
@login_required
def case_study():
    case = CASES[session["team"]["case"]]
    return render_template("case.html", team=session["team"], case=case)


@app.route("/evidence/<station_id>")
@login_required
def evidence(station_id):
    case = CASES[session["team"]["case"]]
    station = next((s for s in case["stations"] if s["id"] == station_id), None)
    if not station:
        abort(404)
    return render_template("station.html", team=session["team"], case=case,
                           station=station)


@app.route("/evidence/download/<path:filename>")
@login_required
def download_evidence(filename):
    return send_from_directory(EVIDENCE_DIR, filename)


@app.route("/api/submit", methods=["POST"])
@login_required
def submit_finding():
    data = request.get_json() or {}
    station_id = data.get("station_id")
    value = data.get("value", "").strip()
    case = CASES[session["team"]["case"]]
    station = next((s for s in case["stations"] if s["id"] == station_id), None)
    if not station:
        return jsonify({"error": "Invalid station"}), 400
    correct = normalize_flag(value) == normalize_flag(station["flag"]) or \
              normalize_flag(station["flag"]) in normalize_flag(value)
    findings = dict(session.get("findings", {}))
    findings[station_id] = {
        "value": value,
        "status": "verified" if correct else "incorrect"
    }
    session["findings"] = findings
    return jsonify({"correct": correct, "value": value})


@app.route("/evidence-board")
@login_required
def evidence_board():
    case_id = session["team"]["case"]
    board = BOARDS[case_id]
    findings = session.get("findings", {})
    return render_template("evidence_board.html", team=session["team"],
                           case=CASES[case_id], board=board, findings=findings)


@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    case = CASES[session["team"]["case"]]
    if request.method == "POST":
        for person in case["persons"]:
            key = person["key"]
            value = request.form.get(f"person_{key}", "").strip()
            evidence = request.form.get(f"evidence_{key}", "").strip()
            accepted = []
            for a in person["answer"]:
                if normalize(a):
                    accepted.append(normalize(a))
            if not accepted:
                status = "skip"
            elif any(normalize(value) and normalize(a) in normalize(value) or
                     (normalize(value) and normalize(value) in normalize(a))
                     for a in accepted):
                status = "verified"
            else:
                status = "incorrect"
            persons = dict(session.get("persons", {}))
            persons[key] = {"value": value, "evidence": evidence,
                            "status": status}
            session["persons"] = persons
        entry = request.form.get("entry_point", "").strip()
        timeline = request.form.get("timeline", "").strip()
        conclusion = request.form.get("conclusion", "").strip()
        session["report"] = {
            "entry_point": entry, "timeline": timeline, "conclusion": conclusion
        }
        return redirect(url_for("score"))
    return render_template("report.html", team=session["team"], case=case,
                           persons=session.get("persons", {}))


@app.route("/score")
@login_required
def score():
    case = CASES[session["team"]["case"]]
    findings = session.get("findings", {})
    persons = session.get("persons", {})

    station_points = 0
    station_max = 0
    for s in case["stations"]:
        station_max += 100
        f = findings.get(s["id"])
        if f and f["status"] == "verified":
            station_points += 100

    person_points = 0
    person_max = len(case["persons"]) * 75
    for p in case["persons"]:
        rec = persons.get(p["key"])
        if rec and rec["status"] == "verified":
            person_points += 75

    report = session.get("report", {})
    report_points = 0
    if report.get("conclusion"):
        report_points += 50
    if report.get("timeline"):
        report_points += 25
    if report.get("entry_point"):
        report_points += 25

    total = station_points + person_points + report_points
    grand_max = station_max + person_max + 100

    return render_template("score.html", team=session["team"], case=case,
                           station_points=station_points, station_max=station_max,
                           person_points=person_points, person_max=person_max,
                           report_points=report_points, total=total,
                           grand_max=grand_max)


@app.route("/reset")
@login_required
def reset():
    session["findings"] = {}
    session["persons"] = {}
    session.pop("report", None)
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    print("==============================================")
    print(" CYBER DETECTIVE - FORENSIC INVESTIGATION APP")
    print(" Running at: http://127.0.0.1:5000")
    print("==============================================")
    app.run(host="0.0.0.0", port=5000, debug=True)
