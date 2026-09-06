"""Round 1 - Mini CTF Lab engine.

Each challenge variant is a small, self-contained, interactive "lab". The
participant performs a real task (decode, analyze, inject, correlate, ...)
inside the lab, submits a single answer to the lab action endpoint, and the
SERVER validates that answer against the variant's `expected_answer`.

On success the lab transitions to LAB_COMPLETED and REVEALS the variant's flag
(which is different from the lab answer). The participant then submits that
flag back on the challenge page for points.

The lab_answer / expected_answer is NEVER the flag.
"""
import json

# ---------------------------------------------------------------------------
# Lab type metadata (drives the interactive UI shell per challenge)
# ---------------------------------------------------------------------------
LAB_META = {
    "login_bypass": {
        "label": "Simulated Login",
        "ui": "webform",
        "title": "Web Application Lab",
        "subtitle": "A deliberately vulnerable local login form",
        "instructions": "Interact with the login form below. Discover a value (payload) that lets you gain access to the protected area, then submit that payload in the lab.",
    },
    "password_audit": {
        "label": "Password Audit Console",
        "ui": "records_pick",
        "title": "Password Audit Console",
        "subtitle": "Fictional account database",
        "instructions": "Analyze the provided (fictional) account records, then submit the identifier you were asked to find.",
    },
    "decoder": {
        "label": "Decoding Terminal",
        "ui": "decoder",
        "title": "Data Decoding Terminal",
        "subtitle": "Decode the provided data",
        "instructions": "Decode the encoded data below and submit the decoded plaintext.",
    },
    "port_map": {
        "label": "Network Analysis Terminal",
        "ui": "records_pick",
        "title": "Network Analysis Terminal",
        "subtitle": "Simulated scan of a fictional host",
        "instructions": "Analyze the simulated scan output and submit the port / service / value you are asked to identify.",
    },
    "phishing": {
        "label": "Simulated Inbox",
        "ui": "email",
        "title": "Phishing Spotter Inbox",
        "subtitle": "Simulated message analysis",
        "instructions": "Inspect the message (sender, subject, headers, link destination) and submit the suspicious indicator / technique you identify.",
    },
    "metadata": {
        "label": "Forensic Metadata Viewer",
        "ui": "records_pick",
        "title": "Forensic File Metadata Viewer",
        "subtitle": "Digital artifact metadata",
        "instructions": "Inspect the artifact's metadata and submit the specific piece of information you are asked to find.",
    },
    "cipher_chain": {
        "label": "Crypto Terminal",
        "ui": "decoder",
        "title": "Cipher Chain Terminal",
        "subtitle": "Multi-layer decoding",
        "instructions": "Perform the required decoding chain in the correct order and submit the final plaintext.",
    },
    "hash_analysis": {
        "label": "Hash Analysis Console",
        "ui": "decoder",
        "title": "Hash Analysis Console",
        "subtitle": "Fictional hash dataset",
        "instructions": "Analyze the provided hash / dataset and submit the hash type, matched password, or weak record you are asked to identify.",
    },
    "source_view": {
        "label": "Simulated Web Page",
        "ui": "source",
        "title": "Source Code Inspection",
        "subtitle": "A local simulated website",
        "instructions": "View the page source of the simulated site and submit the hidden clue you find.",
    },
    "file_magic": {
        "label": "File Signature Analyzer",
        "ui": "decoder",
        "title": "File Magic Analyzer",
        "subtitle": "Fictional sample file",
        "instructions": "Inspect the file's magic bytes / signature and submit the REAL file type (or other requested value).",
    },
    "caesar": {
        "label": "Caesar Cipher Terminal",
        "ui": "decoder",
        "title": "Caesar / ROT Cipher Lab",
        "subtitle": "Decode the shifted message",
        "instructions": "Decode the cipher text (ROT or Caesar shift) and submit the plaintext.",
    },
    "osint": {
        "label": "OSINT Investigation Workspace",
        "ui": "records_pick",
        "title": "OSINT Investigation Workspace",
        "subtitle": "Fictional public-style clues",
        "instructions": "Correlate the fictional public clues and submit the final entity / value you determine.",
    },
}

# Lab types that present a list/set to pick from (records_pick UI)
PICK_TYPES = {"password_audit", "port_map", "metadata", "osint"}
# Lab types that ask the participant to decode/type a result
DECODE_TYPES = {"decoder", "cipher_chain", "hash_analysis", "file_magic", "caesar"}

VALID_LAB_TYPES = set(LAB_META.keys())


def sanitize_lab_data(lab_data):
    """Return only the renderable (non-answer) portion of lab_data.

    The full lab_data dict may carry fields that are only relevant to the
    client UI. Nothing here leaks the lab answer or flag.
    """
    if not lab_data:
        return {}
    if isinstance(lab_data, str):
        try:
            lab_data = json.loads(lab_data)
        except Exception:
            return {}
    if isinstance(lab_data, dict):
        # Never send a nested 'expected'/'answer' regardless of structure
        d = dict(lab_data)
        d.pop("expected", None)
        d.pop("answer", None)
        return d
    return {}


def check_lab_success(lab_data, expected_answer, action):
    """Validate a participant's single lab action against the expected answer.

    Returns (bool, message). This is the ONLY gate between a completed lab and
    the revealed flag.
    """
    submitted = ""
    if isinstance(action, dict):
        submitted = action.get("answer", "")
        if submitted is None:
            submitted = ""
    elif isinstance(action, str):
        submitted = action
    else:
        submitted = str(action)

    ok = _norm(submitted) == _norm(expected_answer or "")
    if ok:
        return True, "Objective complete."
    return False, "That result wasn't right. Re-check the lab and try again."


def parse_lab_data(raw):
    """Parse stored lab_data JSON into a dict (safe)."""
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


def _norm(text):
    """Case-insensitive, whitespace-collapsed normalisation."""
    if not text:
        return ""
    return " ".join(str(text).strip().lower().split())