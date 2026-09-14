# SentinelX — Verify Before You Trust

**Evidence-Verified AI for Cybersecurity Incident Investigation**

---

## What is SentinelX?

**SentinelX** is an automated evidence-verification system for Security Operations Centers (SOC). It acts as an independent auditing layer between AI-generated cybersecurity investigation findings and human security analysts.

Instead of blindly trusting AI hypotheses, SentinelX deterministically verifies every AI claim against immutable security log evidence before presenting it to an analyst.

---

## What is the input?

**Cybersecurity event and security log telemetry**, including:
- SSH authentication logs (`/var/log/auth.log`)
- Process execution events and command history (`sudo`, `bash`)
- System task scheduling records (`/etc/cron*`)
- File system access events (`/etc/shadow`, sensitive files)
- Network socket connections and process telemetry

---

## What does the AI do?

The AI investigator analyzes chronological security event streams and synthesizes structured incident findings. Each finding includes:
- **Attack Stage** (e.g., Initial Access, Privilege Escalation, Persistence, Impact)
- **MITRE ATT&CK Technique** (e.g., `T1110.001`, `T1078.003`, `T1486`)
- **AI Confidence Score** (0%–100%)
- **Cited Event IDs** supporting the hypothesis
- **Defensive Remediation Recommendations**

---

## What does SentinelX do differently?

Traditional AI systems output claims with high confidence, even when they hallucinate attack vectors that never occurred.

**SentinelX never trusts AI confidence alone.** It retrieves the raw security logs cited by the AI and independently verifies:
1. **Event Existence**: Do the cited event IDs actually exist in the security database?
2. **Content & Process Matching**: Do the log processes and actions match what the AI claimed?
3. **MITRE ATT&CK Alignment**: Does the logged telemetry match the claimed technique?
4. **Chronological Consistency**: Did the events happen in the claimed sequence?
5. **Contradiction Detection**: Does the actual log evidence contradict the AI claim?

---

## Verification statuses

Every AI finding receives one of three clear audit verdicts:

| Status | Meaning |
| :--- | :--- |
| 🟢 **SUPPORTED** | Real security logs directly substantiate the claim with matching processes, timestamps, and MITRE techniques. |
| 🔴 **UNSUPPORTED** | The underlying security log evidence explicitly contradicts the AI claim (e.g., AI claims a web exploit, but logs prove an SSH brute-force attack). |
| 🟡 **INSUFFICIENT EVIDENCE** | The cited events do not contain proof of the claim, or cited event IDs do not exist in the database. |

---

## Example

| Attribution Metric | What the AI Claimed | What the Logs Actually Prove |
| :--- | :--- | :--- |
| **Claimed Attack** | Apache Zero-Day Buffer Overflow (CVE-2025-9999) | Automated Hydra SSH Password Brute-Force |
| **Target Service / Port** | HTTP/HTTPS (Port 80 / 443) | SSH Daemon (Port 22) |
| **Attacking Process** | `httpd / apache2` exploit payload | `hydra` dictionary tool (`T1110.001`) |
| **Scores** | **AI Confidence: 98% (High)** | **Evidence Score: 6/100 (Severe Contradiction)** |
| **SentinelX Verdict** | 🔴 **UNSUPPORTED** | *(Caught Hallucination — Discards Invalid Recommendations)* |

---

## Architecture

```text
Security Event Logs (Raw System Telemetry)
               │
               ▼
   [1. Log Normalization Engine]
   (Standardizes schema across sources)
               │
               ▼
   [2. LangGraph 6-Node Investigation Workflow]
    ├── Node 1: Load Events
    ├── Node 2: Investigate (Controlled Benchmark / Optional Live Gemini AI)
    ├── Node 3: Retrieve Evidence
    ├── Node 4: Independent Deterministic Verifier
    ├── Node 5: Calculate Trust Score
    └── Node 6: Generate Incident Report
               │
               ▼
   [3. Evidence Trust Score Engine (0–100)]
   (Coverage + Timeline + MITRE Match + Integrity - Contradictions)
               │
               ▼
   [4. Streamlit Analyst Dashboard]
   (Interactive Evidence Inspector, Side-by-Side Audits, Exportable JSON Reports)
```

---

## Technology Stack

- **Core Engine**: Python 3.10+
- **Workflow Orchestration**: LangGraph, LangChain Core
- **AI Investigation**: Google GenAI SDK (`google-genai` / Gemini 2.5 Flash)
- **Web Dashboard**: Streamlit
- **Data Engineering**: Pandas, Standard JSON/CSV
- **Taxonomy Framework**: MITRE ATT&CK Enterprise Matrix

---

## Dataset

- **Dataset**: CAM-LDS (Cyber Attack Manifestations Log Data Set)
- **Attack Scenario**: `3_ssh_apt` (Multi-stage Linux Enterprise Attack Campaign)
- **Official Source**: [https://zenodo.org/records/18390561](https://zenodo.org/records/18390561)
- **Attack Kill-Chain**:
  1. *Initial Access*: Hydra SSH Password Brute-Force (`T1110.001`)
  2. *Privilege Escalation*: Sudo Elevation to Root (`T1078.003`)
  3. *Credential Access*: Dumping `/etc/shadow` password hashes (`T1003.008`)
  4. *Persistence*: Malicious cron job in `/etc/cron.d/` (`T1053.003`)
  5. *Lateral Movement*: Remote command execution (`T1072`)
  6. *Impact*: `donotcry` Ransomware file encryption (`T1486`)

---

## Run locally

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/your-username/SentinelX.git
cd SentinelX
pip install -r requirements.txt
```

### 2. (Optional) Configure Gemini API for Live AI Mode
If you wish to test live dynamic LLM investigations, copy `.env.example` to `.env` and set your key:
```bash
cp .env.example .env
```
*(Note: SentinelX includes a fast, reproducible **Controlled Benchmark Demo** that runs 100% offline without an API key).*

### 3. Run Automated Tests
```bash
python test_loader.py
python tests/test_verifier.py
python run_pipeline.py
```

### 4. Launch the Web Application
```bash
streamlit run app.py
```
Open `http://localhost:8501` in your browser.

---

## Live deployment

- **Public Live Demo**: `https://sentinelx.streamlit.app` *(Streamlit Community Cloud)*
- **Hackathon**: CraftVerse 2.0 (Round-1 Submission)

