# CASE-A: THE RANSOMWARE HOLD-UP

## Narrated Story

The Tuesday morning sun rose over Meridian Logistics' headquarters, but the servers never woke up.

As employees logged in, files across the company's file server `FS01` had been renamed with a `.locked` extension. A single ransom note, `HOW_TO_DECRYPT.txt`, stared back from every desktop. `FS01` — and then the domain controller and mail server — were encrypted. The company was held hostage.

IT admin Ravi Chetan raced to the servers. The first encrypted file carried the timestamp **2026-08-27 16:42 UTC**. His firewall logs told a chilling story: in the hour before encryption, a single external IP — `203.0.113.42` — had made repeated contact with many internal workstations, then an unknown payload was dropped onto the network.

But what grabbed Ravi's attention most was the access log. Just before the first file was encrypted, **one user account** logged in across the network — the same account that had clicked a suspicious "invoice" email the previous afternoon: **Arjun Khanna**, the warehouse supervisor.

The trail pointed inward. Someone opened the door. The question was: who, and on whose orders?

---

## Company Background

- **Organization:** Meridian Logistics Pvt. Ltd. — mid-sized freight-logistics firm, ~240 employees.
- **Infrastructure:** 12 office workstations, 3 Windows servers (DC, File Server `FS01`, Mail Server).
- **Key personnel:** IT admin Ravi Chetan, CEO Meera Mehta, Finance lead Sunil Verma, Warehouse supervisor Arjun Khanna.
- **Security posture:** No EDR; Windows Defender only; shared file server; no MFA on webmail.

## Incident Description

- **08-28 09:00** — `FS01` files renamed with `.locked`; ransom note on all desktops; systems offline.
- **08-28 09:40** — IT confirms lateral spread to DC + Mail Server.
- **08-28 10:00** — SOC called; environment preserved; **no ransom paid**.

## Initial Observations

- First encrypted file on `FS01`: **2026-08-27 16:42 UTC**.
- External IP `203.0.113.42` contacted many internal hosts in the hour before encryption.
- User **Arjun Khanna (akhanna)** logged in just before first encryption.

## Investigation Objective

Reconstruct the **full attack chain** — identify the victim organization, the attacker/operator, the patient-zero user, and any accomplice — using the 5 evidence stations. **Every conclusion must be backed by evidence.**

## Rules

- Investigate the 5 evidence stations; submit a verified finding for each.
- After stations, complete the Final Incident Report identifying persons by name.
- Hints deduct points; limited attempts.
