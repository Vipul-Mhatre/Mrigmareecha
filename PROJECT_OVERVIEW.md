# Mrigmareecha (मृगमरीचा) — Project Overview & Comprehensive Guide
> **"One signal can change the way we defend."**  
> *AI-Powered Collective Cyber Defense through Controlled Deception, Human-Governed Learning, and Tamper-Evident Evidence.*

---

## 🌟 Table of Contents
1. [The Story & The Metaphor: Why "Mrigmareecha"?](#1-the-story--the-metaphor-why-mrigmareecha)
2. [The Real-World Problem: Why Was This Built?](#2-the-real-world-problem-why-was-this-built)
3. [What Is Mrigmareecha? (In Simple Words)](#3-what-is-mrigmareecha-in-simple-words)
4. [The 4 Superpowers of Mrigmareecha](#4-the-4-superpowers-of-mrigmareecha)
5. [How It Works: The Step-by-Step Journey of an Attack](#5-how-it-works-the-step-by-step-journey-of-an-attack)
6. [Why Responsible AI Matters (Facts vs. Hypotheses)](#6-why-responsible-ai-matters-facts-vs-hypotheses)
7. [The Collective Defense Ring: Sharing Without Leaking Secrets](#7-the-collective-defense-ring-sharing-without-leaking-secrets)
8. [The Cryptographic Evidence Ledger: How We Prove Nothing Was Tampered](#8-the-cryptographic-evidence-ledger-how-we-prove-nothing-was-tampered)
9. [Under the Hood: Architecture & Code Structure](#9-under-the-hood-architecture--code-structure)
10. [Summary & Key Takeaways for Hackathon Judges](#10-summary--key-takeaways-for-hackathon-judges)

---

## 1. The Story & The Metaphor: Why "Mrigmareecha"?

### The Mythological Backstory
In the ancient Indian epic *Ramayana*, the demon **Mareecha** transformed himself into an enchanting, radiant **Golden Deer (*Mriga*)**. The deer was an irresistible, shining decoy designed to lure Lord Rama away from his hermitage. It was an act of deceptive distraction.

### The Cybersecurity Twist
In modern warfare and cybersecurity, **attackers constantly deceive us** with phishing emails, fake logins, and disguised viruses. 

**Mrigmareecha flips this concept on its head.**

Instead of letting hackers trick us, **we set up our own Golden Deer** inside our networks! 
* We plant fake servers that look like sensitive databases.
* We leave fake password files lying around that look like administrator keys.
* We open fake SSH ports that look like high-value internal servers.

These are called **Honeypots** and **Canary Tokens**. 

When a cybercriminal breaks into a corporate network, they can’t resist touching the "Golden Deer". The moment they touch it, **the trap springs**. They have revealed their presence, their tools, their IP address, and their attack strategy—giving defenders complete visibility!

---

## 2. The Real-World Problem: Why Was This Built?

To understand why Mrigmareecha is necessary, imagine being a security guard in a massive shopping mall:

```
Traditional Security: Thousands of noisy alarms ringing every minute. 
                      You can't tell if a cat tripped a sensor or a bank robber is inside.
                      
Deception Security:   You place a fake diamond in an empty, locked glass case. 
                      If anyone touches the glass, it is 100% a thief. ZERO FALSE ALARMS.
```

### The 5 Huge Pain Points in Cyber Defense Today:

### 1. Alert Fatigue (The "Boy Who Cried Wolf" Problem)
Modern companies use firewalls, antivirus software, and cloud monitors that generate **10,000+ alerts every day**. More than 95% of them are false alarms (e.g., an employee forgetting their password, an automatic system update, or random internet background noise). Security analysts are exhausted and overwhelmed. Real hackers easily slip through the noise.

### 2. Slow and Repetitive Manual Investigations
When an alarm rings, an analyst has to spend hours piecing together clues: *Where did this IP come from? What did they try to do? Is this dangerous or just an IT test? What firewall rule should I write?* By the time they finish, the attacker has already stolen sensitive data.

### 3. The Danger of "Wild AI Automation"
Many people think: *"Just connect an AI to the firewall and let it block hackers automatically!"*  
**This is extremely dangerous.** If an AI model hallucinates or makes a mistake, it could block legitimate customers, ban the company CEO, or shut down the entire corporate website, causing millions of dollars in damages.

### 4. Companies Fight Alone in Silos (Isolated Defense)
If Company A gets hit by a brand new zero-day attack, their engineers might eventually figure out how to block it. But Company B, C, and D have no idea this attack exists until they get hacked too!  
Why don't companies share threat info? Because sharing raw server logs risks leaking **private passwords, customer names, internal IP addresses, and trade secrets**.

### 5. The Evidence Gap (Insurance & Legal Headaches)
When a company suffers a cyber attack and files an insurance claim or goes to court, they must prove what happened. But log files can easily be deleted, edited, or forged by clever attackers. Without a tamper-proof audit trail, claims get denied and court cases fail.

---

## 3. What Is Mrigmareecha? (In Simple Words)

> **Mrigmareecha is an intelligent cyber defense platform that turns intentional traps (honeypots and decoys) into instant, explainable threat reports, safe human-reviewed defense rules, and mathematically tamper-proof legal evidence.**

It acts as an automated, super-intelligent security co-pilot for IT and security teams:
1. It listens to deliberately placed traps inside your network.
2. The instant a trap is triggered, an AI engine analyzes what the intruder is trying to do.
3. It separates **cold hard facts** from **AI hypotheses** so humans are never misled.
4. It drafts a precise defensive rule (like a firewall or antivirus signature) to block the attack.
5. It asks a human security analyst to review and click **"Approve"**.
6. Once approved, it scrubs all private company data and broadcasts the generic defensive pattern to friendly peer organizations.
7. It permanently locks every step into an immutable, blockchain-style **SHA-256 cryptographic chain**.

---

## 4. The 4 Superpowers of Mrigmareecha

Mrigmareecha is built around four fundamental pillars:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 MRIGMAREECHA WORKFLOW                                  │
├───────────────────┬───────────────────┬────────────────────────┬───────────────────────┤
│  1. DECEPTION     │   2. AI TRIAGE    │  3. GOVERNED RULES     │  4. COLLECTIVE RING   │
│  Controlled Traps │  Facts vs. Guess  │  Human-in-the-Loop     │  Shared Defense &     │
│  Zero False Noise │  Confidence Score │  Safe Validation       │  Tamper-Proof Audit   │
└───────────────────┴───────────────────┴────────────────────────┴───────────────────────┘
```

### Pillar 1: Controlled Deception (Zero-Noise Signals)
Instead of monitoring the entire chaotic internet, Mrigmareecha connects to controlled decoys (like **OpenCanary** and **Thinkst Canarytokens**). Because legitimate workers have no reason to access these decoys, **any signal has nearly 100% confidence**. No false alarms, no wasted time.

### Pillar 2: AI-Assisted Threat Triage
When an alert arrives, the system doesn't just dump a raw log on the analyst. It automatically translates the technical jargon into clear, human-understandable English:
* What happened?
* How severe is it?
* What is the attacker likely trying to achieve?
* What should the defender do right now?

### Pillar 3: Governed Rule Studio (Human-in-the-Loop)
The AI writes the code needed to block the attack (for example, a **Suricata IDS rule**, an **AWS WAF pattern**, or an **IPTables firewall filter**). But it **never** pushes the rule live on its own. It presents the rule to an authorized human analyst with a simulated test report. The human analyst remains in total control.

### Pillar 4: Collective Defense & Verifiable Evidence
* **Collective Defense:** Validated lessons are sanitized (all private IPs and company names are stripped) and shared with peer organizations so they can block the threat before it ever touches them.
* **Tamper-Evident Evidence:** Every single alert, AI reasoning step, human click, and rule update is chained together with **SHA-256 mathematical hashes**. If anyone tries to modify or delete a past log, the math fails immediately, alerting everyone to the tamper attempt.

---

## 5. How It Works: The Step-by-Step Journey of an Attack

Let's walk through an actual scenario to see how Mrigmareecha works in real life:

```
[Attacker Scans Network]
         │
         ▼
[Bites Decoy SSH Trap (Port 2222)]
         │
         ▼
[Mrigmareecha Normalizes Telemetry] ────► [SHA-256 Ledger: Event Recorded]
         │
         ▼
[AI Triage: Facts vs. Hypotheses]  ────► [SHA-256 Ledger: AI Analysis Logged]
         │
         ▼
[Rule Synthesizer Drafts Firewall Rule]
         │
         ▼
[Human Analyst Reviews & Approves] ────► [SHA-256 Ledger: Approval Stamped]
         │
         ├─────────────────────────────────────────┐
         ▼                                         ▼
[Rule Deployed Locally]               [Sanitized & Shared to Peer Ring]
                                                   │
                                                   ▼
                                      [Peer Org Adopts in Dry-Run Mode]
```

### Step 1: The Trap is Set
A company deploys an OpenCanary decoy that listens on port `2222`, pretending to be an internal SSH server named `lab-ssh-honeypot-01`.

### Step 2: The Attacker Probes the Trap
An attacker scans the company’s internal network, discovers port `2222`, and tries to log in using usernames like `root`, `admin`, and password `P@ssw0rd2026!`.

### Step 3: Ingestion & Normalization
The decoy sends a raw syslog event to Mrigmareecha's ingestion endpoint (`POST /api/events/ingest`). Mrigmareecha:
* Checks the payload structure.
* Masks sensitive values (passwords are replaced with `****` so secrets aren't exposed).
* Assigns a unique event identifier (`evt_demo_001`).
* Records the event into the tamper-proof ledger.

### Step 4: AI Analysis — Separating Facts from Hypotheses
The threat engine processes the normalized data. Crucially, it creates two separate views:
* **The Cold Facts:** *"At 10:15 AM, IP 198.51.100.44 connected to port 2222 on decoy lab-ssh-honeypot-01 and attempted username 'root'."*
* **The AI Hypotheses:** *"This looks like an automated credential-stuffing bot or an intruder attempting lateral movement across the network. Severity: HIGH. Confidence: 88%."*
* **The Honest Uncertainty:** *"Cannot prove attacker identity; could also be an unannounced penetration test by your internal security team."*

### Step 5: Drafting the Shield
The platform automatically generates a candidate defensive rule. For this SSH attack, it generates a **Suricata network signature**:
```suricata
alert tcp any any -> $HOME_NET 2222 (msg:"MRIGMAREECHA - Decoy SSH Connection Spike"; flags:S; threshold:type both, track by_src, count 5, seconds 10; sid:9002001; rev:1;)
```
The system runs this rule through a syntax validator to guarantee it won't crash the network.

### Step 6: Human-in-the-Loop Review
The candidate rule appears in the **Governed Rule Studio** on the analyst dashboard. The security analyst looks over the rule, inspects the evidence, types a note (*"Verified malicious IP probe. Approved for mitigation"*), and clicks **Approve**.

### Step 7: Anonymizing & Sharing to the Collective Ring
The moment the rule is approved:
1. The **Privacy Sanitization Engine** runs. It strips out the internal IP address (`192.168.1.100` becomes `$HOME_NET`), removes the internal asset name, and hides proprietary details.
2. The clean, generic rule is published to the **Collective Defense Ring**.
3. Other friendly companies connected to the ring receive the rule and can test it in **"Dry-Run Monitoring Mode"** to protect themselves before they are ever targeted!

### Step 8: Sealing the Forensic Evidence
The analyst clicks **"Download Evidence Bundle"**. Mrigmareecha packages the original event, the AI assessment, the analyst's approval timestamp, and the full cryptographic ledger into a signed `.json` file. This bundle can be handed to a cyber insurance company or police investigators as verifiable, mathematically sound evidence.

---

## 6. Why Responsible AI Matters (Facts vs. Hypotheses)

One of the most important design principles of Mrigmareecha is **Responsible, Explainable AI**.

Most modern AI apps treat the AI as an infallible oracle. If the AI says *"This is a Russian state-sponsored cyber attack"*, people might believe it without question.

**In Mrigmareecha, AI is treated as an assistant, not an unquestionable truth.**

```
┌──────────────────────────────────────┐  ┌──────────────────────────────────────┐
│       OBSERVED FACTS (GREEN)         │  │       MODEL HYPOTHESES (PURPLE)      │
├──────────────────────────────────────┤  ├──────────────────────────────────────┤
│ 100% Verified Telemetry              │  │ Probabilistic AI Interpretation      │
│ • Asset: lab-decoy-01                │  │ • "Likely automated credential      │
│ • Source IP: 198.51.100.44           │  │   stuffing script"                   │
│ • Protocol: SSH (Port 2222)          │  │ • "Could be unauthorized lateral     │
│ • User attempted: root               │  │   movement"                          │
└──────────────────────────────────────┘  └──────────────────────────────────────┘
```

### The Safeguards Built Into Mrigmareecha:
1. **Strict Segregation:** The dashboard uses different visual cards and colors for what was *actually observed* vs. what the AI *thinks might be happening*.
2. **Transparent Uncertainty:** The AI must explicitly declare what it *doesn't* know (e.g., *"Cannot distinguish between an external adversary and an internal authorized vulnerability test"*).
3. **Deterministic Fallback:** If an LLM API (like OpenAI or Gemini) is down, slow, or expensive, Mrigmareecha falls back to a deterministic, rule-based cybersecurity engine. **The system never crashes or halts.**
4. **Prompt Injection Protection:** Logs and usernames sent by attackers are treated as untrusted text, preventing attackers from injecting malicious instructions into the AI prompt.

---

## 7. The Collective Defense Ring: Sharing Without Leaking Secrets

The cybersecurity industry has a famous saying:  
> *"Attackers work in teams; defenders work alone."*

When hackers find a new exploit, they share it on underground forums within minutes. But when companies get attacked, they rarely share defensive rules because they fear leaking confidential data.

Mrigmareecha solves this with its **Privacy-Preserving Sanitization Engine**:

```
ORIGINAL LOCAL INCIDENT                     SANITIZED COLLECTIVE RULE
(Kept Private Inside Company A)             (Shared to Peer Companies B, C, D)
───────────────────────────────             ──────────────────────────────────
• Origin IP: 192.168.1.100            ───►  • Scope: $HOME_NET (Generic)
• Server: prod-db-worker-09           ───►  • Asset: [REDACTED_FOR_PRIVACY]
• AWS Key: AKIAIOSFODNN7EXAMPLE       ───►  • Token: CANARY_TOKEN_REDACTED
• Raw logs with employee names        ───►  • Only pure behavioral pattern shared!
```

### How Peer Companies Adopt Rules Safely:
When Company B sees a new rule in the collective feed, they don't immediately apply it to their production servers. Instead:
1. They inspect the rule's rationale and test results.
2. They click **Adopt in Dry-Run / Monitoring Mode**.
3. Their security system monitors for the pattern without blocking any real traffic.
4. Once they are confident that the rule has zero false positives in their unique environment, they promote it to active enforcement.

---

## 8. The Cryptographic Evidence Ledger: How We Prove Nothing Was Tampered

In high-stakes investigations (and when filing cyber insurance claims), a common question is:  
*"How do we know someone didn't edit this log file after the fact to hide their mistakes or commit insurance fraud?"*

Mrigmareecha implements a **SHA-256 Cryptographic Hash Chain** (the same mathematical principle behind blockchains and Git commits):

```
[Block #0: Genesis]
  Hash: 49fa14df...
        │
        ▼ (prev_hash: 49fa14df...)
[Block #1: Event Ingested]
  Hash: 8a7c1209...
        │
        ▼ (prev_hash: 8a7c1209...)
[Block #2: AI Analysis Complete]
  Hash: c314b990...
        │
        ▼ (prev_hash: c314b990...)
[Block #3: Analyst Review Approved]
  Hash: e881fa22...
```

### How the Math Works:
1. Each record contains its index, timestamp, action, actor, details, and the **hash of the previous record** (`prev_hash`).
2. The system computes a **SHA-256 digest** over the entire canonical JSON record.
3. If an attacker tries to change even a single character in Block #1, its hash changes completely.
4. Because Block #2 relies on Block #1's hash, Block #2 breaks.
5. The dashboard provides a **"Verify Ledger Integrity"** button that recalculates all hashes in real time. If any tampering occurred, it highlights the exact record that was altered.

---

## 9. Under the Hood: Architecture & Code Structure

The repository is organized as a clean, production-grade monorepo:

```
Mrigmareecha/
│
├── packages/
│   │
│   ├── api/                               # Backend Node.js Engine (Port 5000)
│   │   └── src/
│   │       ├── index.js                   # HTTP Server & 20 REST API endpoints
│   │       ├── normalizer.js              # Ingestion & schema normalization
│   │       ├── analysisEngine.js          # AI threat analysis (Facts vs Hypotheses)
│   │       ├── ruleEngine.js              # Defensive rule generator & sanitizer
│   │       ├── auditTrail.js              # Cryptographic SHA-256 ledger
│   │       ├── evidenceExporter.js        # Signed JSON evidence bundle generator
│   │       ├── simulator.js               # 4 Honeypot & canary attack generators
│   │       └── store.js                   # In-memory repository with pre-seeded data
│   │
│   └── client/                            # Frontend SOC Analyst Dashboard (Port 3000)
│       └── app/
│           ├── page.tsx                   # 5-Tab Next.js Dashboard with live simulator
│           ├── layout.tsx                 # Dark cybersecurity aesthetic
│           └── globals.css                # Tailwind CSS styling
│
├── Mrigmareecha.postman_collection.json   # Ready-to-import Postman & Bruno Collection (20 APIs)
├── mrigmareecha-360degree.pdf             # Original Project Proposal
├── PROJECT_OVERVIEW.md                    # This Comprehensive Guide
└── package.json                           # Root monorepo configuration
```

### The 20 API Endpoints:
The system includes a single Postman collection ([`Mrigmareecha.postman_collection.json`](./Mrigmareecha.postman_collection.json)) covering all 20 individual API endpoints:
* **Health & Vitals:** Health check and route discovery.
* **Attack Simulator:** Triggers for SSH probes, AWS Canarytoken leaks, Redis sweeps, and web traversals.
* **Deception Ingestion:** Ingests OpenCanary syslogs, Canarytokens webhooks, and fetches event details.
* **AI Threat Triage:** Detailed threat assessment with facts, hypotheses, and ATT&CK mappings.
* **Governed Rules:** Rule list, human review approval, and rejection endpoints.
* **Collective Defense:** Public sanitized rule feed and peer organization adoption.
* **Cryptographic Evidence:** Ledger block list, SHA-256 mathematical verification, and signed forensic bundle download.

---

## 10. Summary & Key Takeaways for Hackathon Judges

When presenting or evaluating Mrigmareecha, remember these key highlights:

| Question | Mrigmareecha's Answer |
| :--- | :--- |
| **What is the core idea?** | Turning controlled-deception signals (honeypots & canaries) into explainable threat reports, reviewable defensive rules, and traceable forensic evidence. |
| **Why is deception better than traditional monitoring?** | Honeypots have near-zero false alarms. If someone touches a trap, it is 100% unauthorized. It completely eliminates alert fatigue. |
| **How does it use AI safely?** | It strictly separates **Observed Facts** from **AI Hypotheses**. It requires an authorized human analyst to approve rules before they can touch firewalls. |
| **How does it protect company privacy?** | Before defensive rules are shared with other companies, internal IP addresses, server names, and passwords are automatically scrubbed. |
| **How does it prove incident authenticity?** | Every alert, analysis, and human approval is chained in a SHA-256 cryptographic audit trail, creating downloadable, tamper-proof legal evidence bundles. |

> **Submission Thesis:**  
> *"Mrigmareecha does not replace a security operations team. It aims to reduce the distance between a suspicious signal and a reviewable, reusable defensive action."*
