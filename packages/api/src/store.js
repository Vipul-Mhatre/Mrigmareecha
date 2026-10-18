/**
 * Mrigmareecha - In-Memory State & Record Store
 *
 * Maintains the event repository, threat analysis cache, versioned rule registry,
 * collective defense distribution feed, and links to the cryptographic audit trail.
 */

const { AuditTrail } = require("./auditTrail");
const { normalizeEvent } = require("./normalizer");
const { analyzeDeterministically } = require("./analysisEngine");
const { generateCandidateRule, sanitizeRuleForCollectiveSharing } = require("./ruleEngine");

class DataStore {
  constructor() {
    this.auditTrail = new AuditTrail();
    this.events = new Map();
    this.analyses = new Map();
    this.rules = new Map();
    this.collectiveRules = new Map(); // Federated rules shared with peer organizations
    this.peerAdoptions = new Map(); // Local peer simulated adoption

    this.seedInitialData();
  }

  seedInitialData() {
    // Seed initial event corresponding to the proposal's Listing 1
    const rawSeed = {
      event_id: "evt_demo_001",
      source_type: "opencanary",
      event_type: "decoy_service_connection",
      observed_at: new Date(Date.now() - 3600000).toISOString(),
      asset_id: "lab-decoy-01",
      environment: "authorized-demo",
      source_metadata: {
        remote_address: "192.0.2.25",
        remote_port: 43210,
        destination_port: 2222,
        service: "ssh",
        username_attempted: "root",
        password_attempted: "toor",
      },
      evidence_refs: ["raw-event-demo-001"],
    };

    const norm = normalizeEvent(rawSeed);
    norm.analysis_status = "completed";
    this.events.set(norm.event_id, norm);

    this.auditTrail.recordAction("EVENT_INGESTED", "opencanary-adapter", norm.event_id, {
      source_type: norm.source_type,
      service: norm.source_metadata.service,
      remote_address: norm.source_metadata.remote_address,
    });

    // Seed analysis corresponding to Listing 2
    const analysis = analyzeDeterministically(norm);
    this.analyses.set(norm.event_id, analysis);

    this.auditTrail.recordAction("THREAT_ANALYSIS_COMPLETED", "mrigmareecha-analysis-engine", norm.event_id, {
      severity: analysis.severity,
      confidence: analysis.confidence,
      facts_count: analysis.observed_facts.length,
    });

    // Seed candidate rule corresponding to Listing 3
    const rule = generateCandidateRule(norm, analysis);
    rule.rule_id = "mr-decoy-connection-review";
    rule.description = "Review unexpected access to a monitored decoy.";
    rule.status = "candidate";
    this.rules.set(rule.rule_id, rule);

    this.auditTrail.recordAction("CANDIDATE_RULE_DRAFTED", "system://rule-synthesizer", rule.rule_id, {
      origin_event: norm.event_id,
      rule_type: rule.rule_type,
      validation_status: rule.validation.test_status,
    });

    // Seed one already approved and shared rule to showcase Collective Defense immediately
    const federatedSeedEvent = normalizeEvent({
      event_id: "evt_canary_seed_002",
      source_type: "canarytokens",
      event_type: "canary_token_activation",
      observed_at: new Date(Date.now() - 7200000).toISOString(),
      asset_id: "canary-token-aws-sec-99",
      environment: "authorized-demo",
      source_metadata: {
        remote_address: "198.51.100.88",
        service: "canary_token_callback",
        token_memo: "Planted fake AWS secret key",
        user_agent: "aws-sdk-python/1.26.115",
      },
      evidence_refs: ["raw-cloudtrail-seed"],
    });
    this.events.set(federatedSeedEvent.event_id, federatedSeedEvent);

    const fedAnalysis = analyzeDeterministically(federatedSeedEvent);
    this.analyses.set(federatedSeedEvent.event_id, fedAnalysis);

    const fedRule = generateCandidateRule(federatedSeedEvent, fedAnalysis);
    fedRule.rule_id = "mr-sigma-canary-aws-shared";
    fedRule.status = "approved";
    fedRule.reviewed_at = new Date(Date.now() - 5400000).toISOString();
    fedRule.reviewed_by = "lead-analyst@mitigata-demo.sec";
    fedRule.review_notes = "Verified decoy canary token activation. Approved for federated collective distribution.";
    this.rules.set(fedRule.rule_id, fedRule);

    const sanitized = sanitizeRuleForCollectiveSharing(fedRule);
    this.collectiveRules.set(sanitized.rule_id, sanitized);

    this.auditTrail.recordAction("RULE_APPROVED_AND_SHARED", fedRule.reviewed_by, fedRule.rule_id, {
      sharing_channel: sanitized.distribution.federation_channel,
      privacy_sanitized: true,
    });
  }

  // Events API
  addEvent(event) {
    this.events.set(event.event_id, event);
    this.auditTrail.recordAction("EVENT_INGESTED", "ingestion-api", event.event_id, {
      source_type: event.source_type,
      event_type: event.event_type,
      environment: event.environment,
      asset_id: event.asset_id,
    });
    return event;
  }

  getEvent(id) {
    return this.events.get(id);
  }

  getAllEvents() {
    return Array.from(this.events.values()).sort(
      (a, b) => new Date(b.observed_at) - new Date(a.observed_at)
    );
  }

  // Analyses API
  saveAnalysis(eventId, analysis) {
    this.analyses.set(eventId, analysis);
    const event = this.events.get(eventId);
    if (event) {
      event.analysis_status = "completed";
    }

    this.auditTrail.recordAction("THREAT_ANALYSIS_COMPLETED", analysis.analysis_provider, eventId, {
      severity: analysis.severity,
      confidence: analysis.confidence,
      provider: analysis.analysis_provider,
    });

    return analysis;
  }

  getAnalysis(eventId) {
    return this.analyses.get(eventId);
  }

  // Rules API
  saveRule(rule) {
    this.rules.set(rule.rule_id, rule);
    this.auditTrail.recordAction("CANDIDATE_RULE_DRAFTED", "system://rule-synthesizer", rule.rule_id, {
      origin_event_id: rule.origin_event_id,
      rule_type: rule.rule_type,
    });
    return rule;
  }

  getRule(id) {
    return this.rules.get(id);
  }

  getAllRules() {
    return Array.from(this.rules.values()).sort(
      (a, b) => new Date(b.created_at) - new Date(a.created_at)
    );
  }

  reviewRule(ruleId, decision, reviewer = "analyst@mrigmareecha.sec", notes = "") {
    const rule = this.rules.get(ruleId);
    if (!rule) throw new Error(`Rule ${ruleId} not found`);

    if (decision === "approve") {
      rule.status = "approved";
      rule.reviewed_at = new Date().toISOString();
      rule.reviewed_by = reviewer;
      rule.review_notes = notes || "Approved by security analyst for defensive mitigation.";

      // Automatically sanitize and publish to collective network
      const sanitized = sanitizeRuleForCollectiveSharing(rule);
      this.collectiveRules.set(sanitized.rule_id, sanitized);

      this.auditTrail.recordAction("RULE_APPROVED_AND_SHARED", reviewer, rule.rule_id, {
        decision: "approved",
        notes: rule.review_notes,
        published_to_collective: true,
      });
    } else if (decision === "reject") {
      rule.status = "rejected";
      rule.reviewed_at = new Date().toISOString();
      rule.reviewed_by = reviewer;
      rule.review_notes = notes || "Rejected by security analyst (unnecessary or out of scope).";

      this.auditTrail.recordAction("RULE_REJECTED", reviewer, rule.rule_id, {
        decision: "rejected",
        notes: rule.review_notes,
      });
    }

    return rule;
  }

  // Collective defense
  getCollectiveRules() {
    return Array.from(this.collectiveRules.values());
  }

  adoptCollectiveRule(ruleId, localOrg = "Peer Organization B (Opt-in Subscriber)", mode = "monitoring_only") {
    const collectiveRule = this.collectiveRules.get(ruleId);
    if (!collectiveRule) throw new Error("Collective rule not found");

    const adoptionRecord = {
      adoption_id: `adopt_${crypto.randomUUID().slice(0, 6)}`,
      rule_id: ruleId,
      org: localOrg,
      adopted_at: new Date().toISOString(),
      mode: mode, // monitoring_only | active_enforcement
      status: "active",
    };

    this.peerAdoptions.set(adoptionRecord.adoption_id, adoptionRecord);

    this.auditTrail.recordAction("PEER_RULE_ADOPTED", localOrg, ruleId, {
      mode,
      adoption_id: adoptionRecord.adoption_id,
    });

    return adoptionRecord;
  }

  getPeerAdoptions() {
    return Array.from(this.peerAdoptions.values());
  }
}

// Singleton store instance
const store = new DataStore();

module.exports = store;
