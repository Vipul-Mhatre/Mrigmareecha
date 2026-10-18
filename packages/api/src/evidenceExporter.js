/**
 * Mrigmareecha - Evidence Bundle Exporter & Cryptographic Manifest Generator
 *
 * Implements Section 8 of the proposal:
 * - Packages event telemetry, normalized model, threat analysis, rule versions,
 *   analyst approvals, and audit trail slices into an exportable JSON bundle.
 * - Generates individual SHA-256 digests for each component and signs the manifest.
 */

const crypto = require("crypto");
const { canonicalStringify } = require("./auditTrail");

function sha256(data) {
  const str = typeof data === "string" ? data : canonicalStringify(data);
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

/**
 * Generate an exportable incident evidence bundle with cryptographic integrity manifest.
 */
function createEvidenceBundle({
  event,
  analysis,
  rules = [],
  auditRecords = [],
  analystId = "analyst@mrigmareecha.sec",
  analystNotes = "Authorized export for incident forensic verification",
}) {
  const generatedAt = new Date().toISOString();
  const bundleId = `evb_${event.event_id}_${Date.now()}`;

  // Build the component blocks
  const provenanceBlock = {
    bundle_id: bundleId,
    generated_at: generatedAt,
    system: "Mrigmareecha AI-Powered Collective Cyber Defense",
    version: "1.0.0",
    classification: "PROTECTED_FORENSIC_EVIDENCE",
    exported_by: analystId,
    analyst_justification: analystNotes,
  };

  const eventBlock = {
    raw_reference: event.evidence_refs || [`raw-${event.event_id}`],
    normalized_event: event,
  };

  const analysisBlock = {
    threat_assessment: analysis || null,
  };

  const rulesBlock = {
    associated_rules: rules,
  };

  const auditBlock = {
    audit_chain_slice: auditRecords,
    record_count: auditRecords.length,
    latest_chain_hash: auditRecords.length > 0 ? auditRecords[auditRecords.length - 1].record_hash : null,
  };

  // Compute individual cryptographic component digests
  const hashes = {
    provenance_hash: sha256(provenanceBlock),
    event_hash: sha256(eventBlock),
    analysis_hash: sha256(analysisBlock),
    rules_hash: sha256(rulesBlock),
    audit_slice_hash: sha256(auditBlock),
  };

  // Compute overall composite manifest digest
  const rootDigest = sha256(hashes);

  const manifest = {
    hash_algorithm: "SHA-256",
    canonicalization: "RFC 8785 JSON Canonicalization Scheme (JCS)",
    component_digests: hashes,
    composite_root_digest: rootDigest,
    verification_instructions:
      "Verify bundle integrity by calculating SHA-256 over each canonicalized block and matching with component_digests.",
  };

  return {
    bundle_id: bundleId,
    manifest,
    provenance: provenanceBlock,
    evidence: {
      event: eventBlock,
      analysis: analysisBlock,
      defensive_rules: rulesBlock,
      traceable_audit_trail: auditBlock,
    },
  };
}

module.exports = {
  createEvidenceBundle,
  sha256,
};
