"""Seed script: 12 challenge categories x 4 variants, each a Mini-CTF lab.

Every variant carries:
  - story / objective (narrative + task)
  - lab_type          (drives the interactive lab UI)
  - lab_data          (JSON, the renderable lab content - never contains the
                       lab answer or the flag)
  - expected_answer   (the LAB success answer the participant types in the lab)
  - flag              (unique FLAG{...}, revealed ONLY after the lab is solved)
  - hints / explanation / difficulty / eta

The lab answer (expected_answer) is deliberately distinct from the flag.
Points are awarded ONLY when the participant submits the correct flag.

Usage:
    python -m round1.seed            # seed into DB (idempotent-ish)
    python -m round1.seed --reset    # wipe DB then seed
"""
import json
import sys

from werkzeug.security import generate_password_hash

import round1.db as db

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"


# ---------------------------------------------------------------------------
# 12 CHALLENGE CATEGORIES
# ---------------------------------------------------------------------------
CATEGORIES = [
    {"code": "SQLI",  "title": "SQL Injection Basics", "domain": "Web Application Security", "description": "Obtain unauthorized access through a deliberately vulnerable simulated login.", "difficulty": "Easy", "points": 100, "lab_type": "login_bypass"},
    {"code": "PWDA",  "title": "Password Strength Audit", "domain": "Password Security", "description": "Audit a fictional password database and find the target weakness.", "difficulty": "Easy", "points": 100, "lab_type": "password_audit"},
    {"code": "BIND",  "title": "Binary Decoding", "domain": "Data Encoding", "description": "Decode a data value hidden in binary, octal, or hex. ", "difficulty": "Easy", "points": 100, "lab_type": "decoder"},
    {"code": "NETP",  "title": "Network Port Mapping", "domain": "Networking", "description": "Analyze a simulated scan and map ports to services / anomalies.", "difficulty": "Medium", "points": 100, "lab_type": "port_map"},
    {"code": "PHIS",  "title": "Phishing Spotter", "domain": "Social Engineering", "description": "Identify the manipulation red-flags in a simulated phishing message.", "difficulty": "Medium", "points": 100, "lab_type": "phishing"},
    {"code": "META",  "title": "Metadata Detective", "domain": "Digital Artifacts", "description": "Inspect a fictional artifact's metadata for the requested clue.", "difficulty": "Medium", "points": 100, "lab_type": "metadata"},
    {"code": "CIPH",  "title": "Cipher Chain", "domain": "Cryptography", "description": "Decode a value through a specific multi-layer encoding chain.", "difficulty": "Medium", "points": 100, "lab_type": "cipher_chain"},
    {"code": "HASH",  "title": "Hash Analysis", "domain": "Hashing", "description": "Analyze fictional hash data (type / weak record / match).", "difficulty": "Medium", "points": 100, "lab_type": "hash_analysis"},
    {"code": "WEBH",  "title": "Web Source Hunt", "domain": "Web Security Basics", "description": "Inspect a simulated site's source for a hidden clue.", "difficulty": "Medium-Hard", "points": 100, "lab_type": "source_view"},
    {"code": "FILE",  "title": "File Magic", "domain": "File Forensics", "description": "Identify a real file type from its magic bytes / signature.", "difficulty": "Medium-Hard", "points": 100, "lab_type": "file_magic"},
    {"code": "CSAR",  "title": "Caesar / ROT Decode", "domain": "Cryptography", "description": "Decode a message shifted with Caesar / ROT.", "difficulty": "Medium-Hard", "points": 100, "lab_type": "caesar"},
    {"code": "OSNT",  "title": "OSINT Link Puzzle", "domain": "OSINT / Logic", "description": "Correlate fictional public-style clues to determine the answer.", "difficulty": "Medium-Hard", "points": 100, "lab_type": "osint"},
]


# ---------------------------------------------------------------------------
# VARIANTS. Each category has exactly 4.
# ---------------------------------------------------------------------------
VARIANTS = {
    "SQLI": [
        {
            "v": "V1", "difficulty": "Easy", "eta": "3-5 min",
            "story": "You have been given access to a simulated employee portal. The login form builds its SQL query from your input directly - a classic injection point.",
            "objective": "Discover an input payload for the username field that makes the login succeed and grants access to the protected area.",
            "lab_type": "login_bypass",
            "lab_data": {
                "app": "MegaCorp Employee Portal",
                "fields": [{"name": "username", "label": "Username"},
                           {"name": "password", "label": "Password"}],
                "submit_label": "LOGIN",
                "on_fail": "Invalid credentials. Access denied.",
                "on_success": "ACCESS GRANTED",
                "protected": "Protected Area - Incident ID: INC-1001",
                "query_hint": "query = SELECT * FROM users WHERE username = '<in>' AND password = '<in>'"
            },
            "expected_answer": "' OR '1'='1",
            "flag": "FLAG{CPR1-SQL1-AP04}",
            "hints": ["The username field is concatenated straight into the query.", "Try closing the quote and adding an always-true OR."],
            "explanation": "Entering ' OR '1'='1 makes the WHERE clause always true, bypassing the password check and letting you in.",
            "title": "SQL Injection Basics",
        },
        {
            "v": "V2", "difficulty": "Easy", "eta": "3-5 min",
            "story": "The HR self-service portal has a login bug. There is an administrator account you need to reach.",
            "objective": "Craft a username that logs you in as the admin user, ignoring the password, using a SQL comment.",
            "lab_type": "login_bypass",
            "lab_data": {
                "app": "HR Self-Service Portal",
                "fields": [{"name": "username", "label": "Username"},
                           {"name": "password", "label": "Password"}],
                "submit_label": "SIGN IN",
                "on_fail": "Invalid credentials. Access denied.",
                "on_success": "ADMIN ACCESS GRANTED",
                "protected": "Administrator Panel - Record: EMP-0009",
                "query_hint": "query = SELECT * FROM users WHERE username = '<in>' AND password = '<in>'"
            },
            "expected_answer": "admin' --",
            "flag": "FLAG{CPR1-SQL2-HR54}",
            "hints": ["The account 'admin' exists.", "SQL comments (--) stop the rest of the query from running."],
            "explanation": "admin' -- sets username to admin and comments out the password check, logging you in as admin.",
            "title": "SQL Injection Basics",
        },
        {
            "v": "V3", "difficulty": "Medium", "eta": "4-6 min",
            "story": "The incident ticketing tool has a vulnerable password reset endpoint exposed in a local sandbox.",
            "objective": "Provide a payload that passes the username validation and grants access to the ticketing console.",
            "lab_type": "login_bypass",
            "lab_data": {
                "app": "Ticketing Console",
                "fields": [{"name": "ticket_id", "label": "Ticket ID"},
                           {"name": "operator_code", "label": "Operator Code"}],
                "submit_label": "AUTHENTICATE",
                "on_fail": "Invalid ticket. Access denied.",
                "on_success": "TICKET ACCESS GRANTED",
                "protected": "Console - Queue: SEC-LEVEL-4",
                "query_hint": "query = SELECT * FROM tickets WHERE ticket_id = '<in>' AND operator = '<in>'"
            },
            "expected_answer": "' OR 1=1",
            "flag": "FLAG{CPR1-SQL3-TIC8}",
            "hints": ["Work in the ticket_id field.", "A numeric OR condition like 1=1 is always true."],
            "explanation": "' OR 1=1 makes the condition true and grants access to the console.",
            "title": "SQL Injection Basics",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "5-7 min",
            "story": "A customer lookup tool uses single quotes on both fields. You found the source in the sandbox.",
            "objective": "Combine a quote-break and comment to bypass authentication in the first field.",
            "lab_type": "login_bypass",
            "lab_data": {
                "app": "Customer Lookup Tool",
                "fields": [{"name": "email", "label": "Email"},
                           {"name": "pin", "label": "PIN"}],
                "submit_label": "LOOKUP",
                "on_fail": "No matching customer. Access denied.",
                "on_success": "CUSTOMER ACCESS GRANTED",
                "protected": "Customer Vault - Role: ROOT",
                "query_hint": "query = SELECT * FROM customers WHERE email = '<in>' AND pin = '<in>'"
            },
            "expected_answer": "a' OR 'a'='a",
            "flag": "FLAG{CPR1-SQL4-VLT3}",
            "hints": ["Close the quote in the email field.", "Add an always-true OR, then close the final quote."],
            "explanation": "a' OR 'a'='a closes the first quote, adds an always-true OR, and closes cleanly - the query returns the first row.",
            "title": "SQL Injection Basics",
        },
    ],
    "PWDA": [
        {
            "v": "V1", "difficulty": "Easy", "eta": "3-4 min",
            "story": "You're auditing a fictional company's profile database for weak credentials.",
            "objective": "Identify which user has the WEAKEST password (the one most likely to be cracked first).",
            "lab_type": "password_audit",
            "lab_data": {
                "prompt": "Which user has the weakest (most guessable) password?",
                "answer_hint": "Submit the user id (e.g. user03)",
                "records": [
                    {"id": "user01", "password": "Tr0ub4dor&3"},
                    {"id": "user02", "password": "123456"},
                    {"id": "user03", "password": "Giraffe#2024!"},
                    {"id": "user04", "password": "M4rketing@Blue"},
                    {"id": "user05", "password": "9Gz!kL2#mQ8"},
                ],
                "answer_field": "id",
                "columns": [{"key": "id", "label": "User"}, {"key": "password", "label": "Password"}],
            },
            "expected_answer": "user02",
            "flag": "FLAG{CPR1-PW1-WEA0}",
            "hints": ["Look for the shortest, most common-style password.", "123456 is famously weak."],
            "explanation": "123456 (user02) is a top-common weak password - the most guessable of the set.",
            "title": "Password Strength Audit",
        },
        {
            "v": "V2", "difficulty": "Medium", "eta": "4-6 min",
            "story": "Cross-account password reuse is a serious risk. You're reviewing a fictional account list.",
            "objective": "Find the password that is REUSED across two different accounts.",
            "lab_type": "password_audit",
            "lab_data": {
                "prompt": "Submit the user id of the account sharing a reused password.",
                "answer_hint": "Submit a user id (e.g. user01). The reused password belongs to two users.",
                "records": [
                    {"id": "user01", "password": "W1nter@2024"},
                    {"id": "user02", "password": "Green!Forest4"},
                    {"id": "user03", "password": "W1nter@2024"},
                    {"id": "user04", "password": "P@ssw0rd!X"},
                    {"id": "user05", "password": "MoNdAy2024!"},
                ],
                "answer_field": "id",
                "columns": [{"key": "id", "label": "User"}, {"key": "password", "label": "Password"}],
            },
            "expected_answer": "user01",
            "flag": "FLAG{CPR1-PW2-RU00}",
            "hints": ["The same password appears more than once.", "W1nter@2024 is used by two users."],
            "explanation": "W1nter@2024 is used by both user01 and user03, showing reuse (submit user01 or user03).",
            "title": "Password Strength Audit",
        },
        {
            "v": "V3", "difficulty": "Medium", "eta": "4-6 min",
            "story": "A predictable 'pattern' password is a cracked one. Review this fictional list.",
            "objective": "Identify the user whose password follows a predictable keyboard/word pattern.",
            "lab_type": "password_audit",
            "lab_data": {
                "prompt": "Submit the user id whose password is a predictable pattern (keyboard row + common suffix).",
                "answer_hint": "Submit a user id.",
                "records": [
                    {"id": "user01", "password": "Qwerty123!"},
                    {"id": "user02", "password": "9Gz!kL2#mQ8"},
                    {"id": "user03", "password": "tjgJ7#xR3wE"},
                    {"id": "user04", "password": "MoNdAy2024!"},
                    {"id": "user05", "password": "x7$!pWq2@Lz"},
                ],
                "answer_field": "id",
                "columns": [{"key": "id", "label": "User"}, {"key": "password", "label": "Password"}],
            },
            "expected_answer": "user01",
            "flag": "FLAG{CPR1-PW3-PAT0}",
            "hints": ["Qwerty is the top keyboard row.", "A common suffix makes it guessable."],
            "explanation": "Qwerty123! starts with the predictable 'qwerty' row plus a common suffix - a weak pattern.",
            "title": "Password Strength Audit",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "5-7 min",
            "story": "The org policy requires 12+ chars, an uppercase, a number, and a symbol. Audit the records.",
            "objective": "Find the user whose password violates the MOST policy requirements.",
            "lab_type": "password_audit",
            "lab_data": {
                "prompt": "Submit the user id whose password violates the most policy rules (length<12, no uppercase, no number, no symbol).",
                "answer_hint": "Submit a user id.",
                "records": [
                    {"id": "user01", "password": "sunflower"},
                    {"id": "user02", "password": "MyDog#2024"},
                    {"id": "user03", "password": "aS9!kMm2#"},
                    {"id": "user04", "password": "RiverFlow"},
                    {"id": "user05", "password": "C0mpl3x!Pass980"},
                ],
                "answer_field": "id",
                "columns": [{"key": "id", "label": "User"}, {"key": "password", "label": "Password"}],
            },
            "expected_answer": "user01",
            "flag": "FLAG{CPR1-PW4-POL0}",
            "hints": ["'sunflower' is all lowercase, short, no number, no symbol.", "Count how many rules each breaks."],
            "explanation": "user01 (sunflower) is lowercase only, short, with no number or symbol - it violates all four rules.",
            "title": "Password Strength Audit",
        },
    ],
    "BIND": [
        {
            "v": "V1", "difficulty": "Easy", "eta": "3-4 min",
            "story": "You intercepted a binary-encoded value in a log. Decode it to a word.",
            "objective": "Convert the 8-bit binary groups to ASCII and submit the decoded word.",
            "lab_type": "decoder",
            "lab_data": {
                "encoded": "01000010 01101001 01110100",
                "encoding": "binary (8-bit) -> ASCII",
                "notes": "Split the binary into 8-bit groups and convert each to its character.",
            },
            "expected_answer": "Bit",
            "flag": "FLAG{CPR1-BN1-BIT01}",
            "hints": ["01000010 = 66 = 'B'", "Each 8-bit group is one letter."],
            "explanation": "01000010->B, 01101001->i, 01110100->t = 'Bit'.",
            "title": "Binary Decoding",
        },
        {
            "v": "V2", "difficulty": "Easy", "eta": "3-4 min",
            "story": "A config dump holds a value encoded in binary. Decode it.",
            "objective": "Decode the binary to ASCII and submit the word.",
            "lab_type": "decoder",
            "lab_data": {
                "encoded": "01110011 01100001 01100110 01100101",
                "encoding": "binary (8-bit) -> ASCII",
                "notes": "Convert each 8-bit group to its ASCII character.",
            },
            "expected_answer": "safe",
            "flag": "FLAG{CPR1-BN2-SAF2}",
            "hints": ["01110011 = 115 = 's'", "Convert each group."],
            "explanation": "01110011->s, 01100001->a, 01100110->f, 01100101->e = 'safe'.",
            "title": "Binary Decoding",
        },
        {
            "v": "V3", "difficulty": "Medium", "eta": "4-6 min",
            "story": "An attacker left memory values in octal. Decode them.",
            "objective": "Convert the octal triplets to ASCII characters and submit the word.",
            "lab_type": "decoder",
            "lab_data": {
                "encoded": "150 141 162 144",
                "encoding": "octal -> ASCII",
                "notes": "octal 150 = decimal 104 = character 'h'.",
            },
            "expected_answer": "hard",
            "flag": "FLAG{CPR1-BN3-HRD3}",
            "hints": ["150(oct) = 104(dec) = 'h'", "Convert each octal group."],
            "explanation": "150->h, 141->a, 162->r, 144->d = 'hard'.",
            "title": "Binary Decoding",
        },
        {
            "v": "V4", "difficulty": "Medium", "eta": "4-6 min",
            "story": "A file left a continuous binary string. Recover the word.",
            "objective": "Split the continuous binary string into 8-bit groups, then decode to ASCII.",
            "lab_type": "decoder",
            "lab_data": {
                "encoded": "01101100011011110111001101110101",
                "encoding": "continuous binary -> ASCII",
                "notes": "This string has no spaces - split it yourself into 8-bit groups from the left.",
            },
            "expected_answer": "loss",
            "flag": "FLAG{CPR1-BN4-L0S4}",
            "hints": ["Split into groups of 8.", "01101100 = 108 = 'l'"],
            "explanation": "01101100->l, 01101111->o, 01110011->s, 01110101->u = 'loss'.",
            "title": "Binary Decoding",
        },
    ],
    "NETP": [
        {
            "v": "V1", "difficulty": "Medium", "eta": "3-5 min",
            "story": "A scan of a corporate web host shows several open ports.",
            "objective": "Identify which open service is UNUSUAL for a web server (likely unauthorized).",
            "lab_type": "port_map",
            "lab_data": {
                "prompt": "Which PORT is unusual for a web server?",
                "answer_hint": "Submit the port number.",
                "columns": [{"key": "port", "label": "PORT"}, {"key": "service", "label": "SERVICE"}, {"key": "state", "label": "STATE"}],
                "records": [
                    {"port": "22", "service": "ssh", "state": "open"},
                    {"port": "80", "service": "http", "state": "open"},
                    {"port": "443", "service": "https", "state": "open"},
                    {"port": "5900", "service": "vnc", "state": "open"},
                ],
            },
            "expected_answer": "5900",
            "flag": "FLAG{CPR1-NP1-UNU1}",
            "hints": ["Web servers usually only expose 80 and 443.", "VNC/remote desktop is odd on a public web host."],
            "explanation": "Port 5900 (VNC remote desktop) is unusual for a public web server and often signals an unauthorized service.",
            "title": "Network Port Mapping",
        },
        {
            "v": "V2", "difficulty": "Medium", "eta": "3-5 min",
            "story": "A host exposes a database port that should not be on the internet.",
            "objective": "Identify the database port in the scan.",
            "lab_type": "port_map",
            "lab_data": {
                "prompt": "Which PORT is the exposed database?",
                "answer_hint": "Submit the port number.",
                "columns": [{"key": "port", "label": "PORT"}, {"key": "service", "label": "SERVICE"}, {"key": "state", "label": "STATE"}],
                "records": [
                    {"port": "80", "service": "http", "state": "open"},
                    {"port": "443", "service": "https", "state": "open"},
                    {"port": "3306", "service": "mysql", "state": "open"},
                    {"port": "22", "service": "ssh", "state": "open"},
                ],
            },
            "expected_answer": "3306",
            "flag": "FLAG{CPR1-NP2-DB02}",
            "hints": ["MySQL listens on port 3306.", "Databases should not be internet-facing."],
            "explanation": "Port 3306 is MySQL - exposing it to the internet is a security concern.",
            "title": "Network Port Mapping",
        },
        {
            "v": "V3", "difficulty": "Medium", "eta": "4-6 min",
            "story": "Two servers scanned. One has an extra, suspicious service.",
            "objective": "Identify the indicative service code present only on the anomalous host.",
            "lab_type": "port_map",
            "lab_data": {
                "prompt": "Which SERVICE code appears on host B but NOT host A?",
                "answer_hint": "Submit the service name.",
                "columns": [{"key": "host", "label": "HOST"}, {"key": "port", "label": "PORT"}, {"key": "service", "label": "SERVICE"}],
                "records": [
                    {"host": "A", "port": "22", "service": "ssh"},
                    {"host": "A", "port": "80", "service": "http"},
                    {"host": "A", "port": "443", "service": "https"},
                    {"host": "B", "port": "22", "service": "ssh"},
                    {"host": "B", "port": "80", "service": "http"},
                    {"host": "B", "port": "443", "service": "https"},
                    {"host": "B", "port": "137", "service": "netbios-ssn"},
                ],
            },
            "expected_answer": "netbios-ssn",
            "flag": "FLAG{CPR1-NP3-SVC3}",
            "hints": ["Compare host A and host B service lists.", "Port 137 = NetBIOS file sharing."],
            "explanation": "netbios-ssn (port 137) is present on Host B but not Host A - an unusual file-sharing exposure.",
            "title": "Network Port Mapping",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "5-7 min",
            "story": "You are mapping the services on a fictional lab server.",
            "objective": "Which service does NOT belong in this environment (a production web tier)?",
            "lab_type": "port_map",
            "lab_data": {
                "prompt": "Which SERVICE does not belong in a production web environment?",
                "answer_hint": "Submit the service name.",
                "columns": [{"key": "port", "label": "PORT"}, {"key": "service", "label": "SERVICE"}, {"key": "state", "label": "STATE"}],
                "records": [
                    {"port": "443", "service": "https", "state": "open"},
                    {"port": "3306", "service": "mysql", "state": "open"},
                    {"port": "80", "service": "http", "state": "open"},
                    {"port": "1433", "service": "mssql", "state": "open"},
                ],
            },
            "expected_answer": "mssql",
            "flag": "FLAG{CPR1-NP4-MSS4}",
            "hints": ["Two database engines on one web tier is wrong.", "MSSQL listens on 1433."],
            "explanation": "Having both mysql (3306) and mssql (1433) databases on a web tier is anomalous; mssql is the outlier requested.",
            "title": "Network Port Mapping",
        },
    ],
    "PHIS": [
        {
            "v": "V1", "difficulty": "Medium", "eta": "3-5 min",
            "story": "You received an urgent-looking email. Analyze it for manipulation.",
            "objective": "Identify the social-engineering TECHNIQUE being used to pressure you.",
            "lab_type": "phishing",
            "lab_data": {
                "prompt": "Which social-engineering technique does this email use?",
                "answer_hint": "Submit the technique name (e.g. urgency).",
                "from": "no-reply@megamail.example",
                "reply_to": "reset@secure-login.example",
                "subject": "URGENT: Your account will be suspended in 24 HOURS",
                "body": "Click this link immediately and enter your password RIGHT NOW to avoid suspension.",
                "link_text": "Verify my account",
                "link_href": "https://secure-login.example/verify",
                "headers": "Return-Path: reset@secure-login.example",
            },
            "expected_answer": "urgency",
            "flag": "FLAG{CPR1-PH1-URG1}",
            "hints": ["Words like URGENT, immediately, 24 HOURS, RIGHT NOW.", "It pressures you to act fast."],
            "explanation": "The email creates false urgency and time pressure to force a hasty, insecure action - the 'urgency' technique.",
            "title": "Phishing Spotter",
        },
        {
            "v": "V2", "difficulty": "Medium", "eta": "3-5 min",
            "story": "A bank-ish email landed in your simulated inbox. Check the addresses.",
            "objective": "Identify the SUSPICIOUS SENDER domain (where replies actually go).",
            "lab_type": "phishing",
            "lab_data": {
                "prompt": "Which suspicious domain does the Reply-To use?",
                "answer_hint": "Submit the domain only (no @).",
                "from": "Support @ SafeBank <support@safebank.example>",
                "reply_to": "reset@phish-site.example",
                "subject": "Verify your SafeBank account",
                "body": "Dear customer, confirm your identity to keep your account active.",
                "link_text": "Verify now",
                "link_href": "https://login.safebank.example/confirm",
                "headers": "Reply-To: reset@phish-site.example",
            },
            "expected_answer": "phish-site.example",
            "flag": "FLAG{CPR1-PH2-SND2}",
            "hints": ["The Reply-To differs from the sender domain.", "phish-site.example is not the bank's domain."],
            "explanation": "The Reply-To points to phish-site.example, not the bank's domain - the attacker's address.",
            "title": "Phishing Spotter",
        },
        {
            "v": "V3", "difficulty": "Medium-Hard", "eta": "5-7 min",
            "story": "A link in an email LOOKS legitimate. Check where it actually goes.",
            "objective": "Identify the ACTUAL destination domain in the link's href (not the display text).",
            "lab_type": "phishing",
            "lab_data": {
                "prompt": "What is the REAL destination domain of the link (the href)?",
                "answer_hint": "Submit the domain only (no protocol).",
                "from": "no-reply@safebank.example",
                "reply_to": "no-reply@safebank.example",
                "subject": "Security alert: sign in",
                "body": "Click to verify your identity.\nDisplay text: https://login-safebank.example/verify",
                "link_text": "https://login-safebank.example/verify",
                "link_href": "https://fake-login-abc.example/verify",
                "headers": "Return-Path: bounce@safebank.example",
            },
            "expected_answer": "fake-login-abc.example",
            "flag": "FLAG{CPR1-PH3-LNK3}",
            "hints": ["The display text and the href can differ.", "Look at the actual link destination."],
            "explanation": "The visible text says safebank but the href points to fake-login-abc.example - the attack destination.",
            "title": "Phishing Spotter",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "5-7 min",
            "story": "An email claims to be from your company's CEO. Verify the sender.",
            "objective": "Identify the giveaway: the CEO uses a NON-CORPORATE email domain.",
            "lab_type": "phishing",
            "lab_data": {
                "prompt": "Which non-corporate domain shows this isn't really the CEO?",
                "answer_hint": "Submit the domain only (no @).",
                "from": "CEO Sarah <sarah.ceo@gmail.example>",
                "reply_to": "sarah.ceo@gmail.example",
                "subject": "Urgent: wire transfer needed",
                "body": "Sarah, our CEO, needs you to approve the payment immediately.",
                "link_text": "Approve",
                "link_href": "https://payments.finance.example/approve",
                "headers": "Sender: sarah.ceo@gmail.example",
            },
            "expected_answer": "gmail.example",
            "flag": "FLAG{CPR1-PH4-CEO4}",
            "hints": ["A CEO uses the company domain.", "A public mail domain is the giveaway."],
            "explanation": "The CEO impersonator used a public mail domain (gmail.example) instead of the corporate domain - the deception.",
            "title": "Phishing Spotter",
        },
    ],
    "META": [
        {
            "v": "V1", "difficulty": "Medium", "eta": "3-4 min",
            "story": "You received a 'final' report doc. Its metadata may reveal who wrote it.",
            "objective": "Identify the AUTHOR stored in the document metadata.",
            "lab_type": "metadata",
            "lab_data": {
                "prompt": "Who is the author stored in the metadata?",
                "answer_hint": "Submit the author value.",
                "file": "report_final.docx",
                "columns": [{"key": "field", "label": "FIELD"}, {"key": "value", "label": "VALUE"}],
                "records": [
                    {"field": "Author", "value": "j.morales"},
                    {"field": "Last Modified By", "value": "j.morales"},
                    {"field": "Created", "value": "2025-11-12"},
                    {"field": "Software", "value": "LibreOffice 7.4"},
                ],
            },
            "expected_answer": "j.morales",
            "flag": "FLAG{CPR1-MD1-AUT1}",
            "hints": ["The Author field holds the answer.", "Look at the first metadata row."],
            "explanation": "The Author metadata field shows j.morales.",
            "title": "Metadata Detective",
        },
        {
            "v": "V2", "difficulty": "Medium", "eta": "3-4 min",
            "story": "An invoice PDF's metadata reveals when it was last changed.",
            "objective": "Identify the MODIFICATION timestamp in the metadata.",
            "lab_type": "metadata",
            "lab_data": {
                "prompt": "What is the Last Modified timestamp?",
                "answer_hint": "Submit the value exactly as shown.",
                "file": "invoice.pdf",
                "columns": [{"key": "field", "label": "FIELD"}, {"key": "value", "label": "VALUE"}],
                "records": [
                    {"field": "Author", "value": "finance-svc"},
                    {"field": "Creation", "value": "2025-09-01 09:00"},
                    {"field": "Modified", "value": "2025-09-01 11:32"},
                    {"field": "Producer", "value": "PDFKit"},
                ],
            },
            "expected_answer": "2025-09-01 11:32",
            "flag": "FLAG{CPR1-MD2-MOD2}",
            "hints": ["Look at the Modified / last-saved field."],
            "explanation": "The Modified field records 2025-09-01 11:32.",
            "title": "Metadata Detective",
        },
        {
            "v": "V3", "difficulty": "Medium", "eta": "4-5 min",
            "story": "An image's EXIF metadata reveals which editor was used on it.",
            "objective": "Identify the SOFTWARE that produced / edited this image.",
            "lab_type": "metadata",
            "lab_data": {
                "prompt": "Which software was used on this image (from EXIF)?",
                "answer_hint": "Submit the software name.",
                "file": "photo_001.jpg",
                "columns": [{"key": "field", "label": "FIELD"}, {"key": "value", "label": "VALUE"}],
                "records": [
                    {"field": "Make", "value": "SampleCam"},
                    {"field": "Model", "value": "SN-500"},
                    {"field": "Software", "value": "GIMP 2.10"},
                    {"field": "DateTime", "value": "2025-06-15 14:22"},
                ],
            },
            "expected_answer": "GIMP 2.10",
            "flag": "FLAG{CPR1-MD3-SFT3}",
            "hints": ["Look at the Software field."],
            "explanation": "The EXIF Software field shows GIMP 2.10, indicating the image was edited with GIMP.",
            "title": "Metadata Detective",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "5-6 min",
            "story": "A contract claims it was prepared on one date, but the metadata disagrees.",
            "objective": "Spot the inconsistency - find the ACTUAL metadata modification date.",
            "lab_type": "metadata",
            "lab_data": {
                "prompt": "The document text says 'Prepared on 2025-08-20', but what does the METADATA say?",
                "answer_hint": "Submit the metadata modification date.",
                "file": "contract.pdf",
                "columns": [{"key": "field", "label": "FIELD"}, {"key": "value", "label": "VALUE"}],
                "records": [
                    {"field": "Document text", "value": "Prepared on 2025-08-20"},
                    {"field": "Author", "value": "legal-dept"},
                    {"field": "Modified", "value": "2025-08-27"},
                    {"field": "Created", "value": "2025-08-19"},
                ],
            },
            "expected_answer": "2025-08-27",
            "flag": "FLAG{CPR1-MD4-DTA4}",
            "hints": ["The stored metadata is the reliable timestamp.", "Compare the text date to the Modified field."],
            "explanation": "The metadata Modified field shows 2025-08-27, a week after the claimed date - revealing tampering.",
            "title": "Metadata Detective",
        },
    ],
    "CIPH": [
        {
            "v": "V1", "difficulty": "Easy", "eta": "5-7 min",
            "story": "A value was first Caesar-shifted by +1, then Base64-encoded.",
            "objective": "Reverse the chain: Caesar-shift each letter back 1, then Base64-decode. Submit the plaintext.",
            "lab_type": "cipher_chain",
            "lab_data": {
                "encoded": "QnV1YmRs",
                "chain": ["1) Caesar shift each letter back by 1", "2) Base64-decode"],
                "notes": "The encoding was: plaintext -> Caesar(+1) -> Base64.",
            },
            "expected_answer": "Attack",
            "flag": "FLAG{CPR1-CP1-ATT1}",
            "hints": ["ROT-1 each letter first (B->A, n->m, ...).", "Then Base64-decode the result."],
            "explanation": "ROT-1 of 'QnV1YmRs' then Base64-decode yields 'Attack'.",
            "title": "Cipher Chain",
        },
        {
            "v": "V2", "difficulty": "Medium", "eta": "6-8 min",
            "story": "A plaintext was hex-encoded, then that hex text was Base64-encoded.",
            "objective": "Decode Base64 (you get hex), then convert the hex to ASCII.",
            "lab_type": "cipher_chain",
            "lab_data": {
                "encoded": "NGU2OTc0NjU=",
                "chain": ["1) Base64-decode (you get hex characters)", "2) Convert hex to ASCII"],
                "notes": "Encoding: plaintext -> hex (as text) -> Base64.",
            },
            "expected_answer": "Nite",
            "flag": "FLAG{CPR1-CP2-NIT2}",
            "hints": ["Base64-decode first to reveal hex like 4e697465.", "Then convert hex pairs to letters."],
            "explanation": "Base64-decode gives hex 4e697465 which spells 'Nite'.",
            "title": "Cipher Chain",
        },
        {
            "v": "V3", "difficulty": "Medium", "eta": "6-8 min",
            "story": "A string was hex-encoded after a Caesar shift of +3.",
            "objective": "Hex-decode to ASCII (letters), then Caesar-shift each letter back 3.",
            "lab_type": "cipher_chain",
            "lab_data": {
                "encoded": "4e6868736875",
                "chain": ["1) Hex-decode to ASCII letters", "2) Caesar shift each letter back 3"],
                "notes": "Encoding: plaintext -> Caesar(+3) -> hex.",
            },
            "expected_answer": "Keeper",
            "flag": "FLAG{CPR1-CP3-KEE3}",
            "hints": ["4e6868736875 hex => 'Nhhshu'.", "Then shift Nhhshu back 3."],
            "explanation": "Hex gives 'Nhhshu'; Caesar back 3 gives 'Keeper'.",
            "title": "Cipher Chain",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "8-10 min",
            "story": "Three layers: Caesar(+1) -> Base64 -> Hex.",
            "objective": "Reverse the whole chain: hex-decode, Base64-decode, then Caesar back 1.",
            "lab_type": "cipher_chain",
            "lab_data": {
                "encoded": "556e5a716257303d",
                "chain": ["1) Hex-decode (you get a Base64 string)", "2) Base64-decode", "3) Caesar shift each letter back 1"],
                "notes": "Encoding: plaintext -> Caesar(+1) -> Base64 -> hex.",
            },
            "expected_answer": "Quill",
            "flag": "FLAG{CPR1-CP4-QUI4}",
            "hints": ["Hex gives a Base64 string.", "Decode Base64, then ROT-1."],
            "explanation": "Following the chain in reverse yields the word 'Quill'.",
            "title": "Cipher Chain",
        },
    ],
    "HASH": [
        {
            "v": "V1", "difficulty": "Medium", "eta": "3-5 min",
            "story": "An account stores a 32-char hash. Identify the algorithm.",
            "objective": "Identify the hash ALGORITHM that produced this value.",
            "lab_type": "hash_analysis",
            "lab_data": {
                "prompt": "What hash algorithm produced this 32-character hexadecimal value?",
                "encoded": "e10adc3949ba59abbe56e057f20f883e",
                "notes": "32 hex chars = 128 bits.",
            },
            "expected_answer": "MD5",
            "flag": "FLAG{CPR1-HS1-MD51}",
            "hints": ["32 hex characters => 128 bits.", "MD5 output is 128 bits."],
            "explanation": "A 32-character hexadecimal hash of 128 bits is MD5.",
            "title": "Hash Analysis",
        },
        {
            "v": "V2", "difficulty": "Medium", "eta": "5-7 min",
            "story": "You found a hash and a short wordlist. Match the password.",
            "objective": "Find which word, when MD5-hashed, equals the given hash.",
            "lab_type": "hash_analysis",
            "lab_data": {
                "prompt": "Which wordlist password matches this MD5 hash?",
                "encoded": "5f4dcc3b5aa765d61d8327deb882cf99",
                "notes": "Try MD5 of each word below.",
                "wordlist": ["admin", "password", "temp123", "secret"],
            },
            "expected_answer": "password",
            "flag": "FLAG{CPR1-HS2-MTH2}",
            "hints": ["MD5('password') = 5f4dcc3b...882cf99.", "Hash each word and compare."],
            "explanation": "The MD5 5f4dcc3b5aa765d61d8327deb882cf99 is the hash of 'password'.",
            "title": "Hash Analysis",
        },
        {
            "v": "V3", "difficulty": "Medium-Hard", "eta": "5-7 min",
            "story": "A record stores this SHA256 hash. Find the matching wordlist entry.",
            "objective": "Find the word whose SHA256 equals the given hash.",
            "lab_type": "hash_analysis",
            "lab_data": {
                "prompt": "Which wordlist password (SHA256) matches this hash?",
                "encoded": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                "notes": "Try SHA256 of each candidate.",
                "wordlist": ["hello", "qwerty", "letmein", "pass123"],
            },
            "expected_answer": "qwerty",
            "flag": "FLAG{CPR1-HS3-SH53}",
            "hints": ["SHA256('qwerty') matches.", "Hash each word with SHA256."],
            "explanation": "The SHA256 digest corresponds to the word 'qwerty'.",
            "title": "Hash Analysis",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "5-7 min",
            "story": "An account uses an MD5 hash. Which stored word is the weakest match?",
            "objective": "Identify the weakest / most-common password that matches the hash.",
            "lab_type": "hash_analysis",
            "lab_data": {
                "prompt": "Which word mirrors this weak account hash?",
                "encoded": "5f4dcc3b5aa765d61d8327deb882cf99",
                "notes": "The hash matches one of these words.",
                "wordlist": ["admin", "password", "cookie", "winter"],
            },
            "expected_answer": "password",
            "flag": "FLAG{CPR1-HS4-WK01}",
            "hints": ["Find the word that hashes to this value.", "It is also the most common weak choice."],
            "explanation": "The hash is MD5('password'); 'password' is the weak and most-guessable entry.",
            "title": "Hash Analysis",
        },
    ],
    "WEBH": [
        {
            "v": "V1", "difficulty": "Medium-Hard", "eta": "3-5 min",
            "story": "A simulated site's HTML contains a clue in a comment.",
            "objective": "View the page source and submit the clue found inside a comment.",
            "lab_type": "source_view",
            "lab_data": {
                "prompt": "What clue is in the HTML comment?",
                "answer_hint": "Submit the exact value.",
                "url": "https://dev.local/",
                "html_source": "<!-- hint: the admin panel is at /console -->\n<html>\n<body>\n  <h1>Welcome to the site</h1>\n</body>\n</html>",
            },
            "expected_answer": "/console",
            "flag": "FLAG{CPR1-WB1-CMT1}",
            "hints": ["HTML comments are between <!-- and -->."],
            "explanation": "The comment reveals the hidden admin route /console.",
            "title": "Web Source Hunt",
        },
        {
            "v": "V2", "difficulty": "Medium-Hard", "eta": "3-5 min",
            "story": "A page element carries a hidden data attribute.",
            "objective": "Submit the value of the data-secret attribute.",
            "lab_type": "source_view",
            "lab_data": {
                "prompt": "What is the value of data-secret?",
                "answer_hint": "Submit the attribute value.",
                "url": "https://app.local/",
                "html_source": "<div id=\"app\" data-version=\"2.3\" data-secret=\"blueprint\">App</div>\n<html><body>Spare content...</body></html>",
            },
            "expected_answer": "blueprint",
            "flag": "FLAG{CPR1-WB2-DAT2}",
            "hints": ["Look for data-secret=\"...\" in the tag."],
            "explanation": "The data-secret attribute holds the value 'blueprint'.",
            "title": "Web Source Hunt",
        },
        {
            "v": "V3", "difficulty": "Medium-Hard", "eta": "4-6 min",
            "story": "A robots.txt file hints at a hidden path.",
            "objective": "Submit the path that robots.txt says is DISALLOWED.",
            "lab_type": "source_view",
            "lab_data": {
                "prompt": "Which path is disallowed in robots.txt?",
                "answer_hint": "Submit the exact path.",
                "url": "https://site.local/robots.txt",
                "html_source": "User-agent: *\nDisallow: /private/\nDisallow: /admin",
            },
            "expected_answer": "/private/",
            "flag": "FLAG{CPR1-WB3-RBT3}",
            "hints": ["Read the first Disallow line."],
            "explanation": "robots.txt disallows /private/, which may hide unlinked content.",
            "title": "Web Source Hunt",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "4-6 min",
            "story": "A page's meta tag reveals the author.",
            "objective": "Submit the meta author content.",
            "lab_type": "source_view",
            "lab_data": {
                "prompt": "What is the meta author content?",
                "answer_hint": "Submit the exact value.",
                "url": "https://blog.local/",
                "html_source": "<meta name=\"author\" content=\"t.owens\">\n<html><body>Welcome to the dev blog.</body></html>",
            },
            "expected_answer": "t.owens",
            "flag": "FLAG{CPR1-WB4-MET4}",
            "hints": ["Look in the <meta> tag's content attribute."],
            "explanation": "The meta author tag reveals t.owens as the hidden detail.",
            "title": "Web Source Hunt",
        },
    ],
    "FILE": [
        {
            "v": "V1", "difficulty": "Medium-Hard", "eta": "3-5 min",
            "story": "A file is named report.png, but its magic bytes look like a PDF.",
            "objective": "Submit the REAL file type, despite the extension.",
            "lab_type": "file_magic",
            "lab_data": {
                "prompt": "What is the real file type?",
                "answer_hint": "Submit the type name (e.g. PDF).",
                "filename": "report.png",
                "magic": "25 50 44 46 2D",
                "notes": "25 50 44 46 2D is the hex for '%PDF-'.",
            },
            "expected_answer": "PDF",
            "flag": "FLAG{CPR1-FM1-PDF1}",
            "hints": ["25 50 44 46 spells 0x%PDF.", "Magic bytes beat the extension."],
            "explanation": "The magic bytes '%PDF-1.' identify it as a PDF despite the .png extension.",
            "title": "File Magic",
        },
        {
            "v": "V2", "difficulty": "Medium-Hard", "eta": "3-4 min",
            "story": "Identify a file type from its signature bytes.",
            "objective": "Submit the file type matching these magic bytes.",
            "lab_type": "file_magic",
            "lab_data": {
                "prompt": "What file type has these magic bytes?",
                "answer_hint": "Submit the type name.",
                "filename": "image.bin",
                "magic": "89 50 4E 47 0D 0A 1A 0A",
                "notes": "89 50 4E 47 spells 'PNG'.",
            },
            "expected_answer": "PNG",
            "flag": "FLAG{CPR1-FM2-PNG2}",
            "hints": ["0x89 'PNG' is the PNG signature."],
            "explanation": "The signature 0x89 'PNG' identifies a PNG image.",
            "title": "File Magic",
        },
        {
            "v": "V3", "difficulty": "Medium-Hard", "eta": "4-5 min",
            "story": "A file called notes.txt actually has ZIP magic bytes.",
            "objective": "Submit the real file type.",
            "lab_type": "file_magic",
            "lab_data": {
                "prompt": "What is the real type of this file?",
                "answer_hint": "Submit the type name.",
                "filename": "notes.txt",
                "magic": "50 4B 03 04",
                "notes": "50 4B is 'PK', the ZIP signature.",
            },
            "expected_answer": "ZIP",
            "flag": "FLAG{CPR1-FM3-ZIP3}",
            "hints": ["PK (50 4B) starts ZIP archives."],
            "explanation": "The PK signature indicates a ZIP archive disguised with a .txt extension.",
            "title": "File Magic",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "3-4 min",
            "story": "Match a file format from its leading bytes.",
            "objective": "Submit the file type for these magic bytes.",
            "lab_type": "file_magic",
            "lab_data": {
                "prompt": "What file type begins with these bytes?",
                "answer_hint": "Submit the type name.",
                "filename": "anim.bin",
                "magic": "47 49 46 38 37 61",
                "notes": "This spells 'GIF87a'.",
            },
            "expected_answer": "GIF",
            "flag": "FLAG{CPR1-FM4-GIF4}",
            "hints": ["GIF87a literally spells 'GIF87a'."],
            "explanation": "The bytes spell 'GIF87a', the signature for GIF images.",
            "title": "File Magic",
        },
    ],
    "CSAR": [
        {
            "v": "V1", "difficulty": "Easy", "eta": "2-3 min",
            "story": "A message was rotated with ROT13.",
            "objective": "Decode the ROT13 string and submit the plaintext word.",
            "lab_type": "caesar",
            "lab_data": {
                "encoded": "pbqr",
                "shift_label": "ROT13",
                "notes": "ROT13 shifts letters by 13.",
            },
            "expected_answer": "code",
            "flag": "FLAG{CPR1-CR1-COD1}",
            "hints": ["p->c, b->o, q->d, r->e."],
            "explanation": "ROT13 of 'pbqr' is 'code'.",
            "title": "Caesar / ROT Decode",
        },
        {
            "v": "V2", "difficulty": "Medium", "eta": "5-6 min",
            "story": "A word was Caesar-shifted by +3 (A->D).",
            "objective": "Decode by shifting each letter back 3 and submit the plaintext.",
            "lab_type": "caesar",
            "lab_data": {
                "encoded": "Vshdulxqlqj",
                "shift_label": "Caesar shift +3",
                "notes": "Shift each letter back 3.",
            },
            "expected_answer": "Securing",
            "flag": "FLAG{CPR1-CR2-SEC2}",
            "hints": ["V->S, s->p, h->e, d->a, u->r, l->i, x->u, q->n, l->i, q->n, j->g."],
            "explanation": "Caesar -3 of 'Vshdulxqlqj' yields 'Securing'.",
            "title": "Caesar / ROT Decode",
        },
        {
            "v": "V3", "difficulty": "Medium-Hard", "eta": "6-8 min",
            "story": "A message was reversed, then Caesar-shifted by +3.",
            "objective": "First reverse the string, then Caesar-shift back 3.",
            "lab_type": "caesar",
            "lab_data": {
                "encoded": "Grohq dsdg",
                "shift_label": "Reverse then Caesar +3",
                "notes": "Reverse 'Grohq dsdg', then unshift each letter by 3.",
            },
            "expected_answer": "alert",
            "flag": "FLAG{CPR1-CR3-ALE3}",
            "hints": ["Reverse to a Caesar string, then shift back 3."],
            "explanation": "Reversing and Caesar -3 yields 'alert'.",
            "title": "Caesar / ROT Decode",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "6-8 min",
            "story": "The shift amount is unknown. Brute-force all 25 shifts to find English.",
            "objective": "Find the readable English word among all Caesar shifts.",
            "lab_type": "caesar",
            "lab_data": {
                "encoded": "Lzdfq",
                "shift_label": "Unknown Caesar shift",
                "notes": "Try every shift (ROT1..ROT25); one gives a real word.",
            },
            "expected_answer": "Cipher",
            "flag": "FLAG{CPR1-CR4-CIP4}",
            "hints": ["A shift of +9 yields an English word.", "The word starts with 'C'."],
            "explanation": "Among all shifts, the readable result is 'Cipher'.",
            "title": "Caesar / ROT Decode",
        },
    ],
    "OSNT": [
        {
            "v": "V1", "difficulty": "Medium-Hard", "eta": "3-5 min",
            "story": "A fictional employee's public profile is the clue.",
            "objective": "Correlate the fictional profile info to find the username.",
            "lab_type": "osint",
            "lab_data": {
                "prompt": "What is Alice's public profile username?",
                "answer_hint": "Submit the handle.",
                "scenario": "Alice works at Acme. Her public Hubsight profile lists her handle as 'alice_dev' and location 'Bengaluru'.",
                "clues": [
                    "Name: Alice",
                    "Company: Acme",
                    "Profile handle: alice_dev",
                    "Location: Bengaluru",
                ],
            },
            "expected_answer": "alice_dev",
            "flag": "FLAG{CPR1-OS1-ALC1}",
            "hints": ["The 'Profile handle' clue is the answer."],
            "explanation": "The public profile clearly lists the handle alice_dev.",
            "title": "OSINT Link Puzzle",
        },
        {
            "v": "V2", "difficulty": "Medium-Hard", "eta": "3-5 min",
            "story": "A fictional company blog reveals the author of a project.",
            "objective": "Correlate the blog post to the person who built the project.",
            "lab_type": "osint",
            "lab_data": {
                "prompt": "Which first name signed the blog post?",
                "answer_hint": "Submit the first name.",
                "scenario": "A blog post about Project Nova is signed by its author Rajesh.",
                "clues": [
                    "Post: 'Project Nova v2 launched today!'",
                    "Signed: '-- Rajesh'",
                    "Role: project author",
                ],
            },
            "expected_answer": "Rajesh",
            "flag": "FLAG{CPR1-OS2-RJ2}",
            "hints": ["The signature directly names the author."],
            "explanation": "The post is signed by Rajesh.",
            "title": "OSINT Link Puzzle",
        },
        {
            "v": "V3", "difficulty": "Medium-Hard", "eta": "4-6 min",
            "story": "A fictional project README lists a maintainer email.",
            "objective": "Extract the email domain from the README.",
            "lab_type": "osint",
            "lab_data": {
                "prompt": "What is the maintainer email domain (after the @)?",
                "answer_hint": "Submit the domain only.",
                "scenario": "The README lists a maintainer contact email.",
                "clues": [
                    "README: 'Maintainer: dev-team@openforge.example'",
                ],
            },
            "expected_answer": "openforge.example",
            "flag": "FLAG{CPR1-OS3-D3V3}",
            "hints": ["The domain is everything after the @."],
            "explanation": "The domain after @ is openforge.example.",
            "title": "OSINT Link Puzzle",
        },
        {
            "v": "V4", "difficulty": "Medium-Hard", "eta": "4-6 min",
            "story": "Two fictional public clues point to the announcement author.",
            "objective": "Correlate the clues to find the announcement poster's handle.",
            "lab_type": "osint",
            "lab_data": {
                "prompt": "Who posted the announcement?",
                "answer_hint": "Submit the handle.",
                "scenario": "An announcement post and a docs repo share a maintainer.",
                "clues": [
                    "Announcement posted by: docs_mgr",
                    "Docs repo managed by: km_team",
                ],
            },
            "expected_answer": "docs_mgr",
            "flag": "FLAG{CPR1-OS4-DOC4}",
            "hints": ["The announcement post states its author."],
            "explanation": "The announcement is posted by docs_mgr.",
            "title": "OSINT Link Puzzle",
        },
    ],
}


# ---------------------------------------------------------------------------
# Seed routine
# ---------------------------------------------------------------------------

def seed(reset=False):
    if reset:
        db.reset_db()
    else:
        db.init_db()

    conn = db.get_connection()
    try:
        cat_id_by_code = {}
        for cat in CATEGORIES:
            conn.execute(
                "INSERT OR IGNORE INTO challenge_categories "
                "(challenge_code, title, domain, description, difficulty, points, active) "
                "VALUES (?,?,?,?,?,?,1)",
                (cat["code"], cat["title"], cat["domain"], cat["description"],
                 cat["difficulty"], cat["points"]),
            )
            row = conn.execute(
                "SELECT id FROM challenge_categories WHERE challenge_code=?",
                (cat["code"],),
            ).fetchone()
            cat_id_by_code[cat["code"]] = row["id"]

        for code, variants in VARIANTS.items():
            clist = VARIANTS[code]
            assert len(clist) == 4, \
                f"Category {code} must have exactly 4 variants (got {len(clist)})"
            cat_id = cat_id_by_code[code]
            for i, v in enumerate(clist, start=1):
                title = v.get("title") or CATEGORIES[[c["code"] for c in CATEGORIES].index(code)]["title"]
                conn.execute(
                    "INSERT OR IGNORE INTO challenge_variants "
                    "(challenge_category_id, variant_code, title, question, task_description, "
                    "provided_data, expected_answer, flag, difficulty, hint, explanation, "
                    "estimated_solve_time, lab_type, story, objective, lab_data, hints) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        cat_id, v["v"], title, v["objective"], v["objective"],
                        json.dumps(v["lab_data"]),        # provided_data (renderable lab content)
                        v["expected_answer"], v["flag"], v["difficulty"],
                        v["hints"][0] if v["hints"] else "", v["explanation"],
                        v["eta"], v["lab_type"], v["story"], v["objective"],
                        json.dumps(v["lab_data"]), json.dumps(v["hints"]),
                    ),
                )
        conn.commit()
        num_variants = sum(len(v) for v in VARIANTS.values())
        print(f"Seeded {len(CATEGORIES)} categories and {num_variants} lab variants.")

        conn.execute(
            "INSERT OR IGNORE INTO admins (username, password_hash) VALUES (?,?)",
            (DEFAULT_ADMIN_USERNAME, generate_password_hash(DEFAULT_ADMIN_PASSWORD)),
        )
        conn.commit()
        print(f"Admin account ready: username='{DEFAULT_ADMIN_USERNAME}', "
              f"password='{DEFAULT_ADMIN_PASSWORD}'")
    finally:
        conn.close()


if __name__ == "__main__":
    reset_flag = "--reset" in sys.argv
    seed(reset=reset_flag)