/**
 * Mrigmareecha - Ingestion & Normalizer Service
 *
 * Normalizes signals from OpenCanary, Canarytokens, and test deception assets
 * into the standardized Mrigmareecha event schema (Listing 1 in proposal).
 */

const crypto = require("crypto");

/**
 * Mask sensitive values (e.g. passwords captured in honeypots or authorization keys)
 * to prevent accidental leakages in logs.
 */
function maskSensitive(val) {
  if (typeof val !== "string") return val;
  if (val.length <= 4) return "****";
  return val.slice(0, 2) + "****" + val.slice(-2);
}

/**
 * Normalize an incoming raw payload into the standardized schema.
 * Supports:
 * 1. Native Mrigmareecha format
 * 2. OpenCanary syslog / HTTP webhook format
 * 3. Thinkst Canarytokens webhook format
 */
function normalizeEvent(raw) {
  if (!raw || typeof raw !== "object") {
    throw new Error("Invalid event payload: payload must be an object");
  }

  const now = new Date().toISOString();
  const event_id = raw.event_id || `evt_${crypto.randomUUID().slice(0, 8)}`;
  let source_type = "simulated_decoy";
  let event_type = "decoy_service_connection";
  let asset_id = "lab-decoy-01";
  let environment = "authorized-demo";
  let observed_at = raw.observed_at || now;
  let source_metadata = {};
  const evidence_refs = raw.evidence_refs || [`raw-${event_id}`];

  // 1. Detect OpenCanary webhook payload
  if (raw.logtype || (raw.dst_port !== undefined && raw.src_host !== undefined)) {
    source_type = "opencanary";
    asset_id = raw.node_id || raw.sensor_id || "opencanary-node-01";
    environment = raw.environment || "authorized-lab";
    observed_at = raw.utc_time || raw.local_time || now;

    const logtype = parseInt(raw.logtype, 10);
    const serviceMap = {
      2000: "ssh",
      3000: "http",
      4000: "ftp",
      5000: "telnet",
      6000: "portscan",
      7000: "mysql",
      8000: "redis",
      9000: "git",
    };
    const detectedService = serviceMap[logtype] || raw.service || "unknown_service";

    event_type = logtype === 6000 ? "port_scan" : "decoy_service_connection";

    source_metadata = {
      remote_address: raw.src_host || "192.0.2.1",
      remote_port: raw.src_port || null,
      destination_port: raw.dst_port || 22,
      service: detectedService,
      logtype: logtype,
      payload_sample: raw.logdata ? JSON.stringify(raw.logdata) : null,
      username_attempted: raw.logdata?.USERNAME || raw.logdata?.user || null,
      password_attempted: raw.logdata?.PASSWORD ? maskSensitive(raw.logdata.PASSWORD) : null,
    };
  }
  // 2. Detect Canarytokens webhook payload
  else if (raw.canarydrop || raw.manage_url || raw.memo) {
    source_type = "canarytokens";
    asset_id = raw.canarydrop || "canarytoken-artifact";
    environment = raw.environment || "authorized-demo";
    event_type = "canary_token_activation";
    observed_at = raw.time || now;

    source_metadata = {
      remote_address: raw.src_ip || raw.source_ip || "198.51.100.12",
      user_agent: raw.useragent || raw.user_agent || "Automated Token Probe",
      token_memo: raw.memo || "Decoy AWS/Database credentials planted in sensitive path",
      service: "canary_token_callback",
      channel: raw.channel || "http_callback",
    };
  }
  // 3. Native Mrigmareecha schema
  else {
    source_type = raw.source_type || "simulated_decoy";
    event_type = raw.event_type || "decoy_service_connection";
    asset_id = raw.asset_id || "lab-decoy-01";
    environment = raw.environment || "authorized-demo";
    source_metadata = {
      remote_address: raw.source_metadata?.remote_address || raw.remote_address || "192.0.2.25",
      service: raw.source_metadata?.service || raw.service || "ssh",
      destination_port: raw.source_metadata?.destination_port || raw.port || 2222,
      notes: raw.source_metadata?.notes || raw.notes || "Controlled lab observation",
      ...raw.source_metadata,
    };
  }

  // Final validated canonical normalized event (Section 5.2 Listing 1)
  return {
    event_id,
    source_type,
    event_type,
    observed_at,
    asset_id,
    environment,
    source_metadata,
    evidence_refs,
    analysis_status: "pending",
    sharing_consent: false,
    raw_payload_checksum: crypto
      .createHash("sha256")
      .update(JSON.stringify(raw), "utf8")
      .digest("hex")
      .slice(0, 16),
  };
}

module.exports = {
  normalizeEvent,
  maskSensitive,
};
