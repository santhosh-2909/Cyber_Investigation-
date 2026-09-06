# CASE-B: THE SILENT INSIDER LEAK

## Narrated Story

The board meeting was scheduled for Thursday. But an hour before it began, Apex Retail Group's CEO received a devastating call: their key competitor, Nova Retail, had just presented the *exact* revised pricing structure Apex had planned to roll out next quarter.

The document existed in only one place — the company's confidential shared drive, locked behind a pricing team with strict access control. No external breach. No firewall alerts. No malware. The data had walked out the front door, clean and quiet.

The forensic team pulled three threads: an internal email sent to an external address, a network capture showing a large upload to an unknown IP, and metadata buried inside the leaked document itself.

The document's metadata held the first fingerprint — the **author username**. The shared-drive access logs showed a file opened at **02:00 AM**, hours after every normal employee had left. The network capture showed that upload session, sending the file almost in real time to `192.0.2.88`.

Somewhere in the payroll records, an employee with access to pricing, the late-night logins, and the metadata matched. One of Apex's own had sold the secret.

---

## Company Background

- **Organization:** Apex Retail Group — retail chain, 400 employees.
- **Leaked asset:** Confidential Q4 pricing structure (single privileged document).
- **Key departments:** Pricing team (access-restricted), HR, IT.

## Incident Description

- **08-27** — Confidential pricing doc leaks to rival Nova Retail.
- **08-28** — Discovery; no external breach found; insider suspected.
- Rival contact: **Jasmin Cole** at Nova Retail.

## Initial Observations

- Shared-drive file opened at **02:00 AM** by a privileged account.
- Large one-way data upload to `192.0.2.88` in the same window.
- Document metadata author username points to an internal employee.

## Investigation Objective

Identify the **data owner/victim**, the **leaker/insider suspect**, the **external receiver**, and any **accomplice**, using 5 evidence stations.

## Rules

- Investigate the 5 evidence stations; submit verified findings.
- Complete the report identifying persons by name with supporting evidence.
