# Mrigmareecha

A monorepo containing a **Next.js** frontend and a **Node.js** HTTP backend.

```
Mrigmareecha/
├── frontend/          # Next.js (TypeScript, Tailwind CSS, App Router)
├── backend/           # Node.js HTTP server (no framework)
│   └── src/
│       └── index.js   # Entry point
├── package.json       # Monorepo root (npm workspaces)
└── .gitignore
```

## Getting Started

### Prerequisites

- Node.js ≥ 18
- npm ≥ 9

### Install all dependencies

```bash
npm install
```

---

## Frontend — Next.js

**Stack:** TypeScript · Tailwind CSS · App Router · ESLint

```bash
# Development server (http://localhost:3000)
npm run dev:frontend
```

---

## Backend — Node.js HTTP Server

**Stack:** Pure Node.js `http` module · No framework · JSON responses

```bash
# Development server with hot-reload (http://localhost:5000)
npm run dev:backend

# Production
npm run start:backend
```

### Available endpoints

| Method | Path          | Description              |
|--------|---------------|--------------------------|
| GET    | `/`           | Welcome message          |
| GET    | `/api/health` | Server health check      |
| GET    | `/api/hello`  | Sample hello endpoint    |

### Environment variables

Copy `.env.example` to `.env` inside the `backend/` folder and adjust as needed:

```bash
cp backend/.env.example backend/.env
```

---

## Running both simultaneously

Open two terminals:

```bash
# Terminal 1 — frontend
npm run dev:frontend

# Terminal 2 — backend
npm run dev:backend
```