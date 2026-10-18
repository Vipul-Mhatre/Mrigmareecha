# MRIGMAREECHA (मृगमरीचा)
> **AI-Powered Collective Cyber Defense**  
> *Turning controlled-deception signals into explainable threat assessments, reviewable defensive rules, and traceable incident evidence.*  
> **Team 360degree** · Vipul Mhatre & Samarth Pachpile · **CyberForge Hackathon**

---

## 📖 Complete Documentation
For an in-depth, beginner-friendly explanation of the project, its purpose, and how it works:
👉 **[PROJECT_OVERVIEW.md](./PROJECT_OVERVIEW.md)**

---

## ⚡ Architecture Overview

```
Mrigmareecha/
├── packages/
│   ├── api/                 # Node.js backend & cyber defense engine (Port 5000)
│   │   └── src/
│   │       ├── index.js             # HTTP REST API server (20 endpoints)
│   │       ├── normalizer.js        # Event normalization & schema validation
│   │       ├── analysisEngine.js    # Facts vs Hypotheses triage (Deterministic + LLM)
│   │       ├── ruleEngine.js        # Governed candidate rules & sanitization
│   │       ├── auditTrail.js        # SHA-256 cryptographic hash-chain ledger
│   │       ├── evidenceExporter.js  # Signed forensic evidence bundle generator
│   │       ├── simulator.js         # Honeypot & canary attack simulator
│   │       └── store.js             # Central in-memory state repository
│   │
│   └── client/              # Next.js 16 + React 19 SOC Analyst Dashboard (Port 3000)
│       └── app/
│           ├── page.tsx             # Interactive dashboard (Triage, Rules, Collective, Ledger)
│           └── layout.tsx           # Dark cybersecurity theme
│
├── Mrigmareecha.postman_collection.json # Single Postman & Bruno Collection (20 APIs)
├── mrigmareecha-360degree.pdf        # Hackathon Proposal Document
├── PROJECT_OVERVIEW.md              # Detailed, beginner-friendly project guide
└── package.json                     # Monorepo root (npm workspaces)
```

---

## 🚀 Quick Start

### 1. Prerequisites
- **Node.js** ≥ 18
- **npm** ≥ 9

### 2. Install Dependencies
```bash
npm install
```

### 3. Run the Monorepo

Open two terminal windows:

#### Terminal 1 — Start the Backend API (Port 5000)
```bash
npm run dev:api
```

#### Terminal 2 — Start the Next.js Dashboard (Port 3000)
```bash
npm run dev:client
```

Open your browser to: **[http://localhost:3000](http://localhost:3000)**

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Server health check & engine mode |
| `GET` | `/api/events` | List all ingested & normalized deception signals |
| `POST` | `/api/events/ingest` | Ingest OpenCanary, Canarytoken, or custom webhook alerts |
| `GET` | `/api/events/:id` | Get individual event with analysis and rules |
| `GET` | `/api/rules` | List candidate & approved defensive rules |
| `POST` | `/api/rules/:ruleId/review` | Analyst review (approve/reject candidate rules) |
| `GET` | `/api/collective/feed` | Privacy-sanitized rule feed for peer organizations |
| `POST` | `/api/collective/adopt` | Adopt federated rule in monitoring mode |
| `GET` | `/api/evidence/audit` | View cryptographic SHA-256 audit ledger |
| `GET` | `/api/evidence/verify` | Verify mathematical integrity of the hash chain |
| `GET` | `/api/evidence/export` | Download signed forensic incident evidence bundle |
| `POST` | `/api/simulator/trigger` | Trigger honeypot/canary attack scenario |