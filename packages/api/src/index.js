/**
 * Mrigmareecha - Node.js HTTP Server & REST API
 * AI-Powered Collective Cyber Defense POC Engine
 */

const http = require("http");
const store = require("./store");
const { normalizeEvent } = require("./normalizer");
const { analyzeEvent } = require("./analysisEngine");
const { generateCandidateRule } = require("./ruleEngine");
const { createEvidenceBundle } = require("./evidenceExporter");
const { getAvailableScenarios, generateScenarioEvent } = require("./simulator");

const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || "0.0.0.0";

// ─── Body Parser & Response Helpers ──────────────────────────────────────────

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("Invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  res.end(body);
}

// ─── Request Handler & Route Dispatcher ───────────────────────────────────────

async function requestHandler(req, res) {
  const { method, url } = req;

  // Handle CORS preflight
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    });
    return res.end();
  }

  const [path, queryString] = url.split("?");
  const query = new URLSearchParams(queryString || "");

  try {
    // 1. Health & Status
    if (method === "GET" && path === "/") {
      return sendJSON(res, 200, {
        platform: "Mrigmareecha - AI-Powered Collective Cyber Defense",
        version: "1.0.0",
        tagline: "Detect carefully. Understand clearly. Defend together.",
        status: "active",
        endpoints: [
          "/api/health",
          "/api/events",
          "/api/events/ingest",
          "/api/rules",
          "/api/collective/feed",
          "/api/evidence/audit",
          "/api/evidence/verify",
          "/api/evidence/export",
          "/api/simulator/scenarios",
          "/api/simulator/trigger",
        ],
      });
    }

    if (method === "GET" && path === "/api/health") {
      return sendJSON(res, 200, {
        status: "ok",
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        ai_provider: process.env.GEMINI_API_KEY
          ? "Gemini 1.5 Flash (API Active)"
          : "Deterministic Rule Engine (Fallback Active)",
        audit_records_count: store.auditTrail.chain.length,
        events_count: store.events.size,
        candidate_rules_count: store.rules.size,
      });
    }

    // 2. Simulator Endpoints
    if (method === "GET" && path === "/api/simulator/scenarios") {
      return sendJSON(res, 200, {
        scenarios: getAvailableScenarios(),
      });
    }

    if (method === "POST" && path === "/api/simulator/trigger") {
      const body = await parseBody(req);
      const scenarioId = body.scenario_id || "ssh_brute_force";
      const rawEvent = generateScenarioEvent(scenarioId);

      // Ingest and process end-to-end
      const normalized = normalizeEvent(rawEvent);
      store.addEvent(normalized);

      // Perform AI / deterministic threat analysis
      const analysis = await analyzeEvent(normalized);
      store.saveAnalysis(normalized.event_id, analysis);

      // Generate candidate defensive rule
      const candidateRule = generateCandidateRule(normalized, analysis);
      store.saveRule(candidateRule);

      return sendJSON(res, 201, {
        message: "Simulation event generated and analyzed successfully",
        scenario_id: scenarioId,
        event: normalized,
        analysis,
        candidate_rule: candidateRule,
      });
    }

    // 3. Events Ingestion & Retrieval
    if (method === "GET" && path === "/api/events") {
      const allEvents = store.getAllEvents();
      const enriched = allEvents.map((evt) => ({
        ...evt,
        analysis: store.getAnalysis(evt.event_id) || null,
        rules: Array.from(store.rules.values()).filter((r) => r.origin_event_id === evt.event_id),
      }));
      return sendJSON(res, 200, { events: enriched });
    }

    if (method === "POST" && path === "/api/events/ingest") {
      const body = await parseBody(req);
      const normalized = normalizeEvent(body);
      store.addEvent(normalized);

      // Trigger automatic threat triage
      const analysis = await analyzeEvent(normalized);
      store.saveAnalysis(normalized.event_id, analysis);

      // Generate candidate defensive rule
      const candidateRule = generateCandidateRule(normalized, analysis);
      store.saveRule(candidateRule);

      return sendJSON(res, 201, {
        message: "Event ingested and processed",
        event: normalized,
        analysis,
        candidate_rule: candidateRule,
      });
    }

    // Dynamic: GET /api/events/:id
    const eventMatch = path.match(/^\/api\/events\/([a-zA-Z0-9_-]+)$/);
    if (method === "GET" && eventMatch) {
      const eventId = eventMatch[1];
      const event = store.getEvent(eventId);
      if (!event) return sendJSON(res, 404, { error: `Event ${eventId} not found` });

      const analysis = store.getAnalysis(eventId);
      const rules = Array.from(store.rules.values()).filter((r) => r.origin_event_id === eventId);
      const auditRecords = store.auditTrail.getByResource(eventId);

      return sendJSON(res, 200, { event, analysis, rules, auditRecords });
    }

    // 4. Threat Analysis APIs
    const analysisMatch = path.match(/^\/api\/analysis\/([a-zA-Z0-9_-]+)$/);
    if (method === "GET" && analysisMatch) {
      const eventId = analysisMatch[1];
      const analysis = store.getAnalysis(eventId);
      if (!analysis) return sendJSON(res, 404, { error: `Analysis for ${eventId} not found` });
      return sendJSON(res, 200, { analysis });
    }

    // 5. Rules Registry & Review Workflow
    if (method === "GET" && path === "/api/rules") {
      return sendJSON(res, 200, { rules: store.getAllRules() });
    }

    // POST /api/rules/:ruleId/review
    const ruleReviewMatch = path.match(/^\/api\/rules\/([a-zA-Z0-9_-]+)\/review$/);
    if (method === "POST" && ruleReviewMatch) {
      const ruleId = ruleReviewMatch[1];
      const body = await parseBody(req);
      const decision = body.decision; // "approve" or "reject"
      const reviewer = body.reviewer || "analyst@mrigmareecha.sec";
      const notes = body.notes || "";

      if (!["approve", "reject"].includes(decision)) {
        return sendJSON(res, 400, { error: "Decision must be 'approve' or 'reject'" });
      }

      const updated = store.reviewRule(ruleId, decision, reviewer, notes);
      return sendJSON(res, 200, {
        message: `Rule ${ruleId} reviewed successfully: ${decision}`,
        rule: updated,
      });
    }

    // 6. Governed Collective Defense & Sharing APIs
    if (method === "GET" && path === "/api/collective/feed") {
      const sharedRules = store.getCollectiveRules();
      const peerAdoptions = store.getPeerAdoptions();
      return sendJSON(res, 200, {
        collective_network: "Mrigmareecha Federated Defense Ring",
        participating_peers: 14,
        shared_rules_count: sharedRules.length,
        shared_rules: sharedRules,
        local_adoptions: peerAdoptions,
      });
    }

    if (method === "POST" && path === "/api/collective/adopt") {
      const body = await parseBody(req);
      const { rule_id, org, mode } = body;
      if (!rule_id) return sendJSON(res, 400, { error: "rule_id is required" });

      const adoption = store.adoptCollectiveRule(
        rule_id,
        org || "Peer Organization B (Opt-in Subscriber)",
        mode || "monitoring_only"
      );

      return sendJSON(res, 201, {
        message: "Rule adopted successfully into peer environment",
        adoption,
      });
    }

    // 7. Evidence Integrity & Tamper-Evident Ledger
    if (method === "GET" && path === "/api/evidence/audit") {
      return sendJSON(res, 200, {
        audit_trail: store.auditTrail.getAll(),
        total_records: store.auditTrail.chain.length,
      });
    }

    if (method === "GET" && path === "/api/evidence/verify") {
      const verification = store.auditTrail.verifyIntegrity();
      return sendJSON(res, 200, verification);
    }

    if (method === "GET" && path === "/api/evidence/export") {
      const eventId = query.get("event_id") || store.getAllEvents()[0]?.event_id;
      if (!eventId) {
        return sendJSON(res, 400, { error: "No events available to export" });
      }

      const event = store.getEvent(eventId);
      const analysis = store.getAnalysis(eventId);
      const rules = Array.from(store.rules.values()).filter((r) => r.origin_event_id === eventId);
      const auditRecords = store.auditTrail.chain.filter(
        (r) => r.resource_id === eventId || r.resource_id === "ledger-root"
      );

      const bundle = createEvidenceBundle({
        event,
        analysis,
        rules,
        auditRecords,
        analystId: query.get("analyst") || "analyst@mrigmareecha.sec",
        analystNotes: query.get("notes") || "Forensic export for incident triage and compliance",
      });

      return sendJSON(res, 200, bundle);
    }

    // 404 Not Found fallback
    return sendJSON(res, 404, { error: "Route not found", path, method });
  } catch (err) {
    console.error(`[API ERROR] ${method} ${url}:`, err);
    return sendJSON(res, 500, { error: "Internal server error", details: err.message });
  }
}

// ─── Server Bootstrap ─────────────────────────────────────────────────────────

const server = http.createServer(requestHandler);

server.listen(PORT, HOST, () => {
  console.log(`\n================================================================`);
  console.log(`🛡️  MRIGMAREECHA: AI-POWERED COLLECTIVE CYBER DEFENSE BACKEND`);
  console.log(`================================================================`);
  console.log(`🚀 API Server active at: http://localhost:${PORT}`);
  console.log(`📡 Ingestion Webhook:     http://localhost:${PORT}/api/events/ingest`);
  console.log(`⚡ Attack Simulator:      http://localhost:${PORT}/api/simulator/trigger`);
  console.log(`🔐 Cryptographic Ledger:  http://localhost:${PORT}/api/evidence/audit`);
  console.log(`🔍 Chain Verification:   http://localhost:${PORT}/api/evidence/verify`);
  console.log(`🌐 Collective Feed:       http://localhost:${PORT}/api/evidence/export`);
  console.log(`================================================================\n`);
});

server.on("error", (err) => {
  console.error("Server fatal error:", err.message);
  process.exit(1);
});

module.exports = server;
