# CASE-C: THE CEO FRAUD DECEPTION

## Narrated Story

The finance department at StellarWorks Manufacturing did exactly what they'd been trained to do: when an email arrived from the CEO, Sonia Kapoor, asking for an urgent six-figure wire to a "new vendor," they processed it that same afternoon.

The problem? The CEO never sent it.

The email looked flawless — the CEO's name, her signature, even her usual tone. But the headers told another story. The email's **Return-Path** pointed somewhere completely different from the CEO's real address, and the **SPF/DKIM check failed**. It was a Business Email Compromise — a perfect impersonation.

The attacker had set a **Reply-To** address (`accounts.verify@fraudmail.net`) to capture any follow-up from finance. The forged wire request named a bank account that didn't match any legitimate vendor. And the gullible employee who processed the payment? Finance officer **Arvind Nair**.

The money moved through a staged account and ended up in the hands of a beneficiary named **Rajan Iyer** — a name the investigators now had to prove was the receiver of stolen funds.

---

## Company Background

- **Organization:** StellarWorks Manufacturing — mid-size manufacturer, 300 employees.
- **CEO:** Sonia Kapoor.
- **Finance officer who wired funds:** Arvind Nair.
- **Event:** BEC / CEO-fraud wire transfer.

## Incident Description

- **08-27** — Fraudulent wire of ₹ (six figures) to a "new vendor."
- Spoofed email appeared from the CEO but was never sent by her.
- **SPF/DKIM fail**; Reply-To points to external attacker address.

## Initial Observations

- Spoofed CEO email; real source IP `203.0.113.200`.
- Reply-To: `accounts.verify@fraudmail.net`.
- Fraudulent account number `0987654321`.
- Funds ultimately routed to beneficiary **Rajan Iyer**.

## Investigation Objective

Identify the **victim/spoofed CEO**, the **attacker/fraudster**, the **compromised insider** who moved funds, and the **money-receiver/beneficiary**, using 5 evidence stations.

## Rules

- Investigate the 5 evidence stations; submit verified findings.
- Complete the report identifying persons by name with supporting evidence.
