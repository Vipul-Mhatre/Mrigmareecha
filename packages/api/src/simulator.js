/**
 * Mrigmareecha - Honeypot & Deception Attack Simulator
 *
 * Provides realistic test scenarios to simulate OpenCanary honeypots,
 * Canarytoken activations, and network probes in a controlled authorized lab.
 */

const crypto = require("crypto");

const SIMULATION_SCENARIOS = {
  ssh_brute_force: {
    id: "ssh_brute_force",
    title: "OpenCanary SSH Decoy Probe",
    description: "Simulates an external scanning tool targeting a deliberately exposed SSH honeypot port (2222).",
    generator: () => ({
      source_type: "opencanary",
      event_type: "decoy_service_connection",
      asset_id: "lab-ssh-honeypot-01",
      environment: "authorized-demo-lab",
      observed_at: new Date().toISOString(),
      source_metadata: {
        remote_address: `198.51.100.${Math.floor(Math.random() * 200) + 10}`,
        remote_port: Math.floor(Math.random() * 40000) + 10000,
        destination_port: 2222,
        service: "ssh",
        logtype: 2000,
        username_attempted: ["root", "admin", "ubuntu", "support"][Math.floor(Math.random() * 4)],
        password_attempted: "P@ssw0rd2026!",
        connection_attempts_last_minute: 8,
      },
      evidence_refs: [`raw-pcap-ssh-${crypto.randomUUID().slice(0, 6)}`],
    }),
  },

  canary_token_leak: {
    id: "canary_token_leak",
    title: "AWS Canarytoken Credential Activation",
    description: "Simulates activation of a seeded canary credential leaked from a decoy repository or dummy .env.",
    generator: () => ({
      source_type: "canarytokens",
      event_type: "canary_token_activation",
      asset_id: "canary-token-aws-sec-99",
      environment: "authorized-demo-lab",
      observed_at: new Date().toISOString(),
      source_metadata: {
        remote_address: `203.0.113.${Math.floor(Math.random() * 200) + 10}`,
        service: "canary_token_callback",
        channel: "aws_api_callback",
        user_agent: "aws-sdk-go/v1.44.200 (go1.21; linux; amd64)",
        token_memo: "Planted fake AWS root credential in public staging .env file",
        canarydrop: "canarydrop_aws_sec_99",
        triggered_api: "sts:GetCallerIdentity",
      },
      evidence_refs: [`raw-cloudtrail-canary-${crypto.randomUUID().slice(0, 6)}`],
    }),
  },

  redis_unauth_probe: {
    id: "redis_unauth_probe",
    title: "Decoy Redis Database Exploit Sweep",
    description: "Simulates an unauthenticated crawler attempting memory dump and remote shell execution against decoy Redis.",
    generator: () => ({
      source_type: "opencanary",
      event_type: "decoy_service_connection",
      asset_id: "lab-redis-decoy-02",
      environment: "authorized-demo-lab",
      observed_at: new Date().toISOString(),
      source_metadata: {
        remote_address: `192.0.2.${Math.floor(Math.random() * 200) + 10}`,
        remote_port: 52144,
        destination_port: 6379,
        service: "redis",
        logtype: 8000,
        command_sample: "CONFIG GET dir ; SLAVEOF 198.51.100.99 6379",
        notes: "Automated Redis exploitation script detected targeting decoy port",
      },
      evidence_refs: [`raw-redis-sock-${crypto.randomUUID().slice(0, 6)}`],
    }),
  },

  web_path_traversal: {
    id: "web_path_traversal",
    title: "Web Decoy Traversal & Config Probing",
    description: "Simulates scanner attempting path traversal on decoy web endpoints (/.env, /wp-admin, /.git/config).",
    generator: () => ({
      source_type: "opencanary",
      event_type: "decoy_service_connection",
      asset_id: "lab-web-decoy-http",
      environment: "authorized-demo-lab",
      observed_at: new Date().toISOString(),
      source_metadata: {
        remote_address: `198.51.100.${Math.floor(Math.random() * 200) + 10}`,
        remote_port: 44321,
        destination_port: 8080,
        service: "http",
        logtype: 3000,
        request_path: ["/.env", "/wp-admin/setup-config.php", "/.git/config", "/api/v1/debug"][
          Math.floor(Math.random() * 4)
        ],
        user_agent: "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
      },
      evidence_refs: [`raw-http-req-${crypto.randomUUID().slice(0, 6)}`],
    }),
  },
};

function getAvailableScenarios() {
  return Object.values(SIMULATION_SCENARIOS).map((s) => ({
    id: s.id,
    title: s.title,
    description: s.description,
  }));
}

function generateScenarioEvent(scenarioId) {
  const scenario = SIMULATION_SCENARIOS[scenarioId] || SIMULATION_SCENARIOS.ssh_brute_force;
  return scenario.generator();
}

module.exports = {
  SIMULATION_SCENARIOS,
  getAvailableScenarios,
  generateScenarioEvent,
};
