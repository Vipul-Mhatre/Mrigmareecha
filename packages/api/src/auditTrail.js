/**
 * Mrigmareecha - Tamper-Evident Audit Trail
 *
 * Implements a cryptographic SHA-256 hash-chain audit ledger.
 * Each entry canonicalizes its content and links to the previous entry's SHA-256 hash.
 * Verifiable mathematically to prove that no log was altered, reordered, or deleted.
 */

const crypto = require("crypto");

/**
 * Deterministically serialize an object to JSON (canonical JSON representation)
 * to ensure consistent SHA-256 digests.
 */
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalStringify).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalStringify(obj[k])).join(",") + "}";
}

class AuditTrail {
  constructor() {
    this.chain = [];
    // Initialize genesis block
    this.createGenesisBlock();
  }

  createGenesisBlock() {
    const genesisData = {
      index: 0,
      timestamp: "2026-10-18T00:00:00.000Z",
      action: "GENESIS_LEDGER_INITIALIZED",
      actor: "system://mrigmareecha-core",
      resource_id: "ledger-root",
      details: {
        system: "Mrigmareecha Cyber Defense Platform",
        version: "1.0.0",
        message: "Tamper-evident audit ledger established for authorized controlled deception.",
      },
      prev_hash: "0000000000000000000000000000000000000000000000000000000000000000",
    };

    const hash = this.calculateHash(genesisData);
    genesisData.record_hash = hash;
    this.chain.push(genesisData);
  }

  calculateHash(entry) {
    const payload = {
      index: entry.index,
      timestamp: entry.timestamp,
      action: entry.action,
      actor: entry.actor,
      resource_id: entry.resource_id,
      details: entry.details,
      prev_hash: entry.prev_hash,
    };
    const canonicalStr = canonicalStringify(payload);
    return crypto.createHash("sha256").update(canonicalStr, "utf8").digest("hex");
  }

  /**
   * Append an immutable record to the audit chain
   */
  recordAction(action, actor, resource_id, details = {}) {
    const previousRecord = this.chain[this.chain.length - 1];
    const newRecord = {
      index: this.chain.length,
      timestamp: new Date().toISOString(),
      action,
      actor: actor || "system",
      resource_id: resource_id || "global",
      details,
      prev_hash: previousRecord.record_hash,
    };

    newRecord.record_hash = this.calculateHash(newRecord);
    this.chain.push(newRecord);
    return newRecord;
  }

  /**
   * Verify the integrity of the entire cryptographic chain
   */
  verifyIntegrity() {
    for (let i = 0; i < this.chain.length; i++) {
      const current = this.chain[i];

      // Check linkage
      if (i > 0) {
        const previous = this.chain[i - 1];
        if (current.prev_hash !== previous.record_hash) {
          return {
            valid: false,
            error: `Linkage broken at index ${i}: prev_hash does not match previous record_hash`,
            broken_index: i,
            total_records: this.chain.length,
          };
        }
      }

      // Check cryptographic digest
      const recalculated = this.calculateHash(current);
      if (recalculated !== current.record_hash) {
        return {
          valid: false,
          error: `Digest mismatch at index ${i}: record was modified after hashing`,
          tampered_index: i,
          expected_hash: recalculated,
          recorded_hash: current.record_hash,
          total_records: this.chain.length,
        };
      }
    }

    return {
      valid: true,
      message: "Cryptographic SHA-256 chain verified. Zero tampering detected.",
      chain_length: this.chain.length,
      latest_hash: this.chain[this.chain.length - 1].record_hash,
      root_hash: this.chain[0].record_hash,
      verified_at: new Date().toISOString(),
    };
  }

  getAll() {
    return [...this.chain].reverse();
  }

  getByResource(resource_id) {
    return this.chain.filter((item) => item.resource_id === resource_id);
  }
}

module.exports = {
  AuditTrail,
  canonicalStringify,
};
