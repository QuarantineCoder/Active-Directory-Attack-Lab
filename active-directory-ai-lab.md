# AI-Assisted Active Directory Threat Detection Lab

**Stack:** Windows Server · Kali Linux · KVM / virt-manager · Microsoft Sentinel · Python · Azure SDK · LLM API  
**Goal:** Build a full attack-detect-triage pipeline that combines Active Directory security with AI-powered incident analysis — simulating what modern enterprise SOC tooling looks like.

---

## Project Summary

Most student security projects stop at "I set up a SIEM and wrote some detection rules." This project goes further — you simulate real AD attacks, collect the logs in Sentinel, and build a Python application that uses an LLM to automatically triage alerts and produce natural language incident reports.

The result is a project that sits at the intersection of **cloud security**, **identity security**, and **AI in security operations** — where very few students have anything concrete to show.

---

## Architecture Overview

```
┌──────────────────────────────────────┐
│  Fedora 44 Host (KVM / virt-manager) │
│                                      │
│  Windows Server 2022 (DC) ──┐        │
│  Windows 11 (Client)        │        │
│  Kali Linux (Attacker)      │        │
│  [Isolated virtual network] ─┘       │
└──────────────────────┬───────────────┘
                         │ Windows Security Events
                         ▼
┌─────────────────────────────┐
│         Microsoft Azure     │
│                             │
│  Microsoft Sentinel (SIEM)  │
│  Entra ID (Azure AD)        │
│  Entra Connect (Sync)       │
└─────────────────┬───────────┘
                  │ Alerts + Raw Logs
                  ▼
┌─────────────────────────────┐
│      AI Triage Application  │
│                             │
│  Python + Azure SDK         │
│  LLM API (Claude / OpenAI)  │
│  Structured Incident Report │
└─────────────────────────────┘
```

---

## Phase 1 — Local Active Directory Environment

**Goal:** Build the AD foundation, understand how it works, and practice real attacks against it.  
**Time estimate:** 2–3 weekends  
**Cost:** Free (Windows Server 180-day evaluation ISO)

### What you're building
- 1x **Windows Server 2022 VM** → promoted to Domain Controller (4 GB RAM, 40 GB thin-provisioned qcow2 disk — actual usage ~12–15 GB)
- 1x **Windows 11 VM** → joined to the domain as a client machine (2 GB RAM, 40 GB thin-provisioned qcow2 disk — actual usage ~12–18 GB)
- **Kali Linux VM** → attacker machine (2 GB RAM, already set up in KVM)
- All hosted inside **Fedora 44 using KVM / virt-manager** (already set up)
- **Isolated virtual network** in KVM so all three VMs communicate without touching the host's real network

### RAM budget (16 GB total)

| Component | RAM |
|---|---|
| Fedora host | ~8 GB (remaining after VMs) |
| Windows Server 2022 (DC) | 4 GB |
| Windows 11 (client) | 2 GB |
| Kali Linux (attacker) | 2 GB |


### Configure a realistic fake company
Create users and groups that simulate a real org — this makes the attacks meaningful:

| Department | Users | Privileges |
|---|---|---|
| IT Admin | `jsmith.admin` | Domain Admin |
| IT Helpdesk | `helpdesk01` | Local admin on workstations |
| Finance | `alee`, `mwang` | Standard users |
| HR | `tpatel` | Standard users |
| Service Account | `svc_backup` | Has an SPN set (Kerberoastable) |

### Intentional misconfigurations to add
These make the attacks work and give you something to find:
- Set weak passwords on service accounts (`svc_backup` → `Password123`)
- Give `helpdesk01` more privileges than needed (over-permissioned)
- Leave Kerberos pre-auth disabled on one user account (AS-REP Roastable)
- Set an SPN on `svc_backup` (makes it Kerberoastable)

### Attacks to practice from Kali

| Attack | Tool | What it demonstrates |
|---|---|---|
| **Kerberoasting** | `impacket-GetUserSPNs` | Request service tickets and crack offline |
| **AS-REP Roasting** | `impacket-GetNPUsers` | Target accounts without pre-auth |
| **Pass-the-Hash** | `crackmapexec` / `evil-winrm` | Authenticate using NTLM hash, no password needed |
| **BloodHound Enumeration** | `bloodhound-python` / `SharpHound` | Map AD and find privilege escalation paths |
| **DCSync** | `impacket-secretsdump` | Mimic a DC to dump all password hashes |
| **Golden Ticket** | `mimikatz` | Forge Kerberos tickets after owning KRBTGT |

### Resources
- TCM Security "Practical Ethical Hacking" — AD sections, free on YouTube (Heath Adams)
- Josh Madakor AD lab series on YouTube
- TryHackMe "Attacktive Directory" room — good guided intro before going free-form

### Checkpoint
Before moving to Phase 2, you should be able to:
- [ ] All three VMs are on the same isolated KVM virtual network and can ping each other
- [ ] Log into the domain from the Windows 11 VM
- [ ] Successfully Kerberoast `svc_backup` and crack the hash
- [ ] Run BloodHound and identify a path to Domain Admin
- [ ] Document what you found with screenshots

---

## Phase 2 — Microsoft Sentinel Integration

**Goal:** Connect your AD environment to Sentinel and build detection rules for the attacks you ran in Phase 1.  
**Time estimate:** 1–2 weekends  
**Cost:** Minimal — Log Analytics ingestion costs (stays within Azure for Students credit)

### What you're building
- Windows Security Event logs flowing from your AD VMs into Sentinel
- KQL detection rules that fire alerts when attack patterns are detected
- An incident dashboard showing what happened

### Setup steps
1. In Azure portal → create a Log Analytics Workspace (if not already from honeynet)
2. Enable Microsoft Sentinel on that workspace
3. Install the **Windows Security Events** data connector on your Windows Server VM
4. Install the **Microsoft Monitoring Agent (MMA)** or **Azure Monitor Agent (AMA)** on the DC and Windows 11 VM
5. Verify events are flowing: run a KQL query in Sentinel → `SecurityEvent | take 10`

### Key Windows Event IDs to collect

| Event ID | What it means |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos service ticket requested (Kerberoasting shows here) |
| 4771 | Kerberos pre-auth failed (AS-REP Roasting shows here) |
| 4672 | Special privileges assigned (admin logon) |
| 4728 / 4732 | User added to privileged group |
| 4662 | Directory service object access (DCSync shows here) |

### KQL detection rules to write

**Kerberoasting detection:**
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where AccountName !endswith "$"
| summarize count() by AccountName, IpAddress, bin(TimeGenerated, 1h)
| where count_ > 5
```

**Multiple failed logons (brute force / Pass-the-Hash attempts):**
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by AccountName, IpAddress, bin(TimeGenerated, 15m)
| where FailedAttempts > 10
```

**DCSync detection:**
```kql
SecurityEvent
| where EventID == 4662
| where ObjectType contains "domainDNS"
| where AccessMask == "0x100"
| project TimeGenerated, AccountName, IpAddress, ObjectName
```

### Checkpoint
Before moving to Phase 3:
- [ ] Events flowing from DC into Sentinel
- [ ] At least 3 custom KQL detection rules written and tested
- [ ] Re-run Phase 1 attacks and confirm alerts fire in Sentinel
- [ ] Screenshot your incidents dashboard

---

## Phase 3 — AI Triage Layer

**Goal:** Build a Python application that pulls Sentinel alerts, enriches them with log context, and uses an LLM to generate natural language incident reports.  
**Time estimate:** 1–2 weekends  
**Cost:** LLM API usage (minimal — a few dollars at most for a lab)

### What you're building
A Python script / small app that:
1. Authenticates to Azure and pulls triggered Sentinel incidents
2. Fetches the raw log events behind each incident
3. Constructs a prompt with the alert context
4. Sends it to an LLM API (Claude or OpenAI)
5. Outputs a structured incident report: attack type, affected accounts, severity, recommended response

### Why this matters
This is what Microsoft Copilot for Security does commercially — but you built it yourself. It demonstrates you understand both the security concepts *and* how to integrate AI into a real security workflow.

### Tech stack
- **Python 3.x**
- **azure-mgmt-securityinsight** — Sentinel incidents API
- **azure-monitor-query** — Log Analytics query API
- **anthropic** or **openai** Python SDK — LLM API calls
- **azure-identity** — authentication (DefaultAzureCredential)

### High-level application flow
```python
# 1. Authenticate to Azure
credential = DefaultAzureCredential()

# 2. Pull open Sentinel incidents
incidents = sentinel_client.incidents.list(
    resource_group, workspace_name
)

# 3. For each incident, fetch related raw events from Log Analytics
logs_client.query_workspace(
    workspace_id,
    kql_query,
    timespan=timedelta(hours=1)
)

# 4. Build prompt with incident + raw event context
prompt = f"""
You are a SOC analyst. Analyse the following security incident and raw log data.
Incident: {incident_details}
Raw events: {raw_events}

Provide:
1. Attack technique (use MITRE ATT&CK name if applicable)
2. What the attacker was likely doing
3. Affected accounts and machines
4. Severity (Critical / High / Medium / Low)
5. Recommended immediate containment steps
"""

# 5. Send to LLM and output structured report
response = anthropic_client.messages.create(...)
```

### Sample output
```
INCIDENT REPORT — 2026-06-15 14:32 UTC
──────────────────────────────────────
Attack Technique:  Kerberoasting (T1558.003)
Severity:          High

Summary:
An unusually high volume of Kerberos service ticket requests (TGT encryption
type RC4-HMAC) were detected from IP 192.168.1.105 targeting the service
account svc_backup. This pattern is consistent with a Kerberoasting attack
where an adversary requests service tickets to crack offline.

Affected Accounts:  svc_backup
Source IP:          192.168.1.105 (Kali VM)
Timeframe:          14:28 – 14:31 UTC

Recommended Actions:
1. Immediately reset svc_backup credentials
2. Enforce AES256 encryption on all service account tickets
3. Investigate 192.168.1.105 for further lateral movement
4. Review all accounts with SPNs — consider managed service accounts
```

### Checkpoint
Before moving to Phase 4:
- [ ] Script successfully authenticates to Azure
- [ ] Pulls at least one real Sentinel incident
- [ ] LLM generates a coherent incident report
- [ ] Test against at least 3 different attack types from Phase 1
- [ ] Document sample outputs with screenshots

---

## Phase 4 — Hybrid Identity (Optional but Strong)

**Goal:** Extend the lab into a true hybrid environment by syncing on-prem AD to Azure Entra ID via Entra Connect.  
**Time estimate:** 1–2 weekends  
**Cost:** Some Azure compute credit for a VM (tear down after documenting)

### What you're building
- Windows Server VM in Azure acting as a secondary DC (or standalone)
- Microsoft Entra Connect installed and configured
- On-prem AD users synced to your Azure Entra ID tenant
- Re-run attacks and observe how they surface in both environments

### Why this matters
Hybrid identity is how the majority of real enterprises operate. The security implications of syncing on-prem AD to the cloud are significant:

- The **Entra Connect sync account** needs elevated on-prem privileges — a known attack target
- Password hash sync means on-prem credential attacks can cascade into cloud access
- DCSync in a hybrid environment can expose cloud-valid credentials

Being able to talk about this architecture in an interview — and having built it — is genuinely rare at the student level.

### Setup steps
1. In Azure portal → create a Windows Server 2022 VM
2. Install Microsoft Entra Connect on the server
3. Run the configuration wizard → connect to your `corp.local` domain
4. Enable **Password Hash Synchronization**
5. Verify users appear in Entra ID → Azure portal → Users
6. Re-run Kerberoasting and DCSync from Phase 1
7. Check what shows up in Entra ID logs and Sentinel

### Checkpoint
- [ ] Entra Connect configured and syncing
- [ ] On-prem users visible in Azure Entra ID
- [ ] At least one attack rerun with hybrid logs captured
- [ ] Document how the attack surface changes in hybrid vs. on-prem only

---

## Phase 5 — Documentation and Portfolio Writeup

**Goal:** Turn the lab into something you can show, explain, and reference in interviews.  
**Time estimate:** 1 weekend spread across all phases (document as you go)

### What to produce
- **Architecture diagram** — draw the full stack (local VMs → Sentinel → AI layer → Entra ID)
- **Attack runbook** — for each attack: what you ran, what fired, what the AI triage output was
- **GitHub repository** — Python triage script with a clean README
- **Blog post or PDF writeup** — 500–1000 words explaining what you built and what you learned
- **Resume bullet** — one tight sentence that captures the whole project

### Resume bullet (draft)
> "Built an AI-assisted Active Directory threat detection pipeline on Azure: deployed a Windows Server domain, simulated attacks (Kerberoasting, Pass-the-Hash, DCSync, BloodHound), collected logs in Microsoft Sentinel, and developed a Python application using the Azure SDK and Claude API to automatically triage incidents and generate structured MITRE ATT&CK-mapped reports."

---

## Full Timeline

| Phase | What | Estimate |
|---|---|---|
| Phase 1 | Local AD lab + attacks | 2–3 weekends |
| Phase 2 | Sentinel integration + KQL rules | 1–2 weekends |
| Phase 3 | AI triage Python app | 1–2 weekends |
| Phase 4 | Hybrid identity with Entra Connect | 1–2 weekends (optional) |
| Phase 5 | Documentation + writeup | 1 weekend |
| **Total** | | **6–10 weekends** |

---

## How This Connects to Your Existing Work

| Project | What it shows |
|---|---|
| Azure Honeynet (done ✓) | External attack detection, SIEM, KQL, log analysis |
| AD + AI Lab (this project) | Identity attacks, lateral movement, AI in SOC workflows |
| **Combined narrative** | "I understand how attackers get in, how they move, and how to detect and triage it — including with AI" |

---

## Resources

- TCM Security "Practical Ethical Hacking" — AD sections, free on YouTube
- Josh Madakor AD lab series — YouTube
- TryHackMe "Attacktive Directory" room — guided intro
- Microsoft Sentinel documentation — docs.microsoft.com/sentinel
- MITRE ATT&CK — attack.mitre.org (reference for technique names)
- Anthropic API docs — docs.anthropic.com
