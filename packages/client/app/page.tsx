"use client";

import React, { useState, useMemo } from "react";
import Image from "next/image";
import {
  LayoutDashboard,
  Radio,
  Search,
  Layers,
  ShieldCheck,
  Users,
  Settings,
  Bell,
  Activity,
  Radar,
  ShieldAlert,
  Workflow,
  FolderCheck,
  BrainCircuit,
  Zap,
  CheckCircle2,
  ChevronDown,
  ArrowRight,
  Sparkles,
  AlertCircle,
  FileCode,
  Download,
  Copy,
  ChevronUp,
  Terminal,
  Key,
  Database,
  Globe,
  LockKeyhole as LockIcon,
  Menu,
  X,
} from "lucide-react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  PieChart,
  Pie,
  Cell,
  ReferenceLine,
  ReferenceDot,
} from "recharts";

// ─── TYPES ───────────────────────────────────────────────────────────────────

interface SignalItem {
  id: string;
  time: string;
  source: string;
  type: string;
  severity: "High" | "Medium" | "Low";
  status: "Under Analysis" | "Enriched" | "Awaiting Review" | "Analyzed" | "Rule Candidate";
  action: "Investigate" | "View" | "Review";
  sourceIconColor: string;
  statusDotColor: string;
  summary: string;
  whatHappened: string;
  threatType: string;
  likelyIntent: string;
  confidence: number;
  keyFindings: string[];
  nextSteps: string[];
  ruleCandidate: {
    title: string;
    status: string;
    tags: string[];
    syntax: string;
  };
  evidenceVerified: boolean;
}

// ─── CANONICAL REFERENCE SIGNALS (100% MATCHING REFERENCE SCREENSHOT) ──────────

const CANONICAL_SIGNALS: SignalItem[] = [
  {
    id: "#MS-7492",
    time: "2025-09-28 16:42",
    source: "10.10.23.45",
    type: "Decoy Service",
    severity: "High",
    status: "Under Analysis",
    action: "Investigate",
    sourceIconColor: "#248BFF",
    statusDotColor: "#EAF2FF",
    summary: "Suspicious interaction with controlled decoy service detected in production environment.",
    whatHappened:
      "A request was made to a controlled decoy service (fake admin panel) from an internal IP. The behavior matches known reconnaissance patterns and triggered an alert.",
    threatType: "Reconnaissance",
    likelyIntent: "Credential Harvesting",
    confidence: 92,
    keyFindings: [
      "Request matched decoy service fingerprint (admin-panel-v2)",
      "Originated from internal host 10.10.23.45",
      "Followed by 3 failed login attempts to non-existent endpoints",
      "Similar to 4 previous incidents (learned pattern)",
    ],
    nextSteps: [
      "Investigate host 10.10.23.45 (check user, process, and logs)",
      "Validate if this is authorized testing or real threat",
      "Consider blocking the source IP (if malicious)",
      "Create/update defensive rule (candidate ready)",
    ],
    ruleCandidate: {
      title: "Block suspicious decoy service access from internal network",
      status: "Draft",
      tags: ["Network", "Decoy", "High Priority"],
      syntax: `alert tcp any any -> $HOME_NET 2222 (msg:"MRIGMAREECHA - Decoy SSH Connection Spike Detected"; flags:S; threshold:type both, track by_src, count 5, seconds 10; reference:mrigmareecha,MS-7492; classtype:suspicious-login; sid:9007492; rev:1;)`,
    },
    evidenceVerified: true,
  },
  {
    id: "#MS-7491",
    time: "2025-09-28 15:17",
    source: "192.168.1.12",
    type: "Canary Token",
    severity: "Medium",
    status: "Enriched",
    action: "View",
    sourceIconColor: "#9966FF",
    statusDotColor: "#16D6A0",
    summary: "Canary AWS Access Key accessed from unauthorized internal workstation.",
    whatHappened:
      "A decoy AWS access credential seeded in a mock deployment repository was queried via the AWS STS API.",
    threatType: "Credential Access",
    likelyIntent: "Privilege Escalation",
    confidence: 88,
    keyFindings: [
      "Seeded token 'canary-token-aws-sec-99' was invoked",
      "Origin IP 192.168.1.12 matches engineering staging subnet",
      "API call performed: sts:GetCallerIdentity",
    ],
    nextSteps: [
      "Quarantine host 192.168.1.12",
      "Check CloudTrail logs for concurrent IAM calls",
      "Verify if workstation belongs to an authorized red team exercise",
    ],
    ruleCandidate: {
      title: "Sigma rule: Decoy Canary Token Invocation Alert",
      status: "Candidate",
      tags: ["CloudTrail", "Canary", "Medium Priority"],
      syntax: `title: Mrigmareecha Canary Token Triggered\nstatus: test\nlogsource:\n    service: cloudtrail\ndetection:\n    selection:\n        userIdentity.accessKeyId: "CANARY_TOKEN_REDACTED"\n    condition: selection\nlevel: high`,
    },
    evidenceVerified: true,
  },
  {
    id: "#MS-7490",
    time: "2025-09-28 14:03",
    source: "203.0.113.77",
    type: "Suspicious Login",
    severity: "High",
    status: "Awaiting Review",
    action: "Review",
    sourceIconColor: "#FF5268",
    statusDotColor: "#248BFF",
    summary: "Multiple failed authentication attempts against decoy SSH honeypot.",
    whatHappened:
      "Repeated dictionary login attacks attempted username 'root' and 'admin' against isolated decoy sensor.",
    threatType: "Credential Stuffing",
    likelyIntent: "Brute Force",
    confidence: 95,
    keyFindings: [
      "High-frequency connection burst (14 attempts in 30 seconds)",
      "Source IP belongs to known commercial VPN proxy pool",
      "Decoy SSH server successfully absorbed connection without breach",
    ],
    nextSteps: [
      "Add source IP range to edge rate-limit blacklist",
      "Review perimeter firewall logs for lateral probe attempts",
    ],
    ruleCandidate: {
      title: "IPTables: Decoy Honeypot SSH Rate-Limit & Drop",
      status: "Candidate",
      tags: ["Firewall", "SSH", "High Priority"],
      syntax: `iptables -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit 5/min --limit-burst 8 -j ACCEPT\niptables -A INPUT -p tcp -m conntrack --ctstate NEW -j DROP`,
    },
    evidenceVerified: true,
  },
  {
    id: "#MS-7489",
    time: "2025-09-28 12:56",
    source: "172.16.5.9",
    type: "Network Anomaly",
    severity: "Low",
    status: "Analyzed",
    action: "View",
    sourceIconColor: "#16D6A0",
    statusDotColor: "#16D6A0",
    summary: "Unusual multi-port SYN sweep detected traversing decoy gateway.",
    whatHappened:
      "Internal network segment performed a fast sequential port probe touching honeypot listening sockets.",
    threatType: "Network Discovery",
    likelyIntent: "Vulnerability Scan",
    confidence: 76,
    keyFindings: [
      "Sequential port sweep across ports 21, 22, 80, 443, 8080",
      "Source matches internal vulnerability management scanner scheduled window",
    ],
    nextSteps: [
      "Verify vulnerability scanner maintenance ticket",
      "Reclassify as benign if confirmed by IT admin",
    ],
    ruleCandidate: {
      title: "Network detection rule: Internal port sweep filter",
      status: "Draft",
      tags: ["Reconnaissance", "Low Priority"],
      syntax: `alert tcp $HOME_NET any -> $HOME_NET [21,22,80,443] (msg:"Internal SYN Sweep"; threshold:type both, track by_src, count 20, seconds 5; sid:9007489;)`,
    },
    evidenceVerified: true,
  },
  {
    id: "#MS-7488",
    time: "2025-09-28 11:32",
    source: "198.51.100.23",
    type: "Decoy Service",
    severity: "Medium",
    status: "Rule Candidate",
    action: "Review",
    sourceIconColor: "#248BFF",
    statusDotColor: "#20C8FF",
    summary: "Decoy database service probed with unauthorized memory dump commands.",
    whatHappened:
      "External host attempted unauthenticated Redis 'CONFIG GET' and 'SLAVEOF' against decoy honeypot instance.",
    threatType: "Remote Code Execution Probe",
    likelyIntent: "Database Exfiltration",
    confidence: 91,
    keyFindings: [
      "Decoy port 6379 received unauthenticated Redis command sequence",
      "Payload contained attempt to establish remote master replication",
    ],
    nextSteps: [
      "Approve candidate WAF / firewall rule",
      "Inspect external gateway ACLs for port 6379 leakage",
    ],
    ruleCandidate: {
      title: "WAF Rule: Decoy Database Command Inspection",
      status: "Candidate",
      tags: ["WAF", "Redis", "Medium Priority"],
      syntax: `SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)(slaveof|config\\s+get)" "id:9007488,phase:2,deny,status:403,msg:'Mrigmareecha Decoy DB Exploit Block'"`,
    },
    evidenceVerified: true,
  },
  {
    id: "#MS-7487",
    time: "2025-09-28 10:14",
    source: "10.10.11.14",
    type: "Canary Token",
    severity: "High",
    status: "Under Analysis",
    action: "Investigate",
    sourceIconColor: "#9966FF",
    statusDotColor: "#FF5268",
    summary: "Seeded SQL Canary Table accessed in production backup replica.",
    whatHappened:
      "A decoy database table containing canary customer entries triggered an automated callback when queried.",
    threatType: "Data Exfiltration Probe",
    likelyIntent: "Unauthorized Database Access",
    confidence: 94,
    keyFindings: [
      "Canary table 'sys_audit_canary_v2' was read by user 'db_sync_temp'",
      "Origin IP is inside legacy finance VPC",
    ],
    nextSteps: [
      "Revoke temporary credentials for user db_sync_temp",
      "Isolate host 10.10.11.14 from production network",
    ],
    ruleCandidate: {
      title: "Database Activity Monitor: Canary Table Access Drop",
      status: "Candidate",
      tags: ["Database", "Canary", "High Priority"],
      syntax: `SELECT * FROM audit_log WHERE table_name = 'sys_audit_canary_v2' AND action = 'SELECT';`,
    },
    evidenceVerified: true,
  },
];

// ─── TIME SERIES DATA ────────────────────────────────────────────────────────

const OVERVIEW_CHART_DATA = [
  { time: "00:00", total: 12, suspicious: 3, high: 1 },
  { time: "04:00", total: 9, suspicious: 2, high: 0 },
  { time: "08:00", total: 20, suspicious: 7, high: 2 },
  { time: "12:00", total: 17, suspicious: 5, high: 1 },
  { time: "16:00", total: 32, suspicious: 14, high: 7 },
  { time: "20:00", total: 35, suspicious: 12, high: 4 },
];

const SIGNAL_TYPES_DATA = [
  { name: "Decoy Service", value: 42, color: "#248BFF" },
  { name: "Canary Token", value: 28, color: "#9966FF" },
  { name: "Suspicious Login", value: 14, color: "#FFAD42" },
  { name: "Network Anomaly", value: 9, color: "#16D6A0" },
  { name: "Other", value: 7, color: "#7790B3" },
];

export default function Dashboard() {
  const [activeNav, setActiveNav] = useState("Dashboard");
  const [selectedSignalId, setSelectedSignalId] = useState<string>("#MS-7492");
  const [signals, setSignals] = useState<SignalItem[]>(CANONICAL_SIGNALS);
  const [inspectorTab, setInspectorTab] = useState<"Overview" | "Analysis" | "Evidence" | "Rule Suggestion">("Overview");
  const [keyFindingsExpanded, setKeyFindingsExpanded] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSimulatorOpen, setIsSimulatorOpen] = useState(false);
  const [isRuleModalOpen, setIsRuleModalOpen] = useState(false);
  const [isEvidenceModalOpen, setIsEvidenceModalOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isMobileInspectorOpen, setIsMobileInspectorOpen] = useState(false);

  // Selected Signal
  const selectedSignal = useMemo(() => {
    return signals.find((s) => s.id === selectedSignalId) || signals[0];
  }, [signals, selectedSignalId]);

  // Filtered signals for search
  const filteredSignals = useMemo(() => {
    if (!searchQuery.trim()) return signals;
    const q = searchQuery.toLowerCase();
    return signals.filter(
      (s) =>
        s.id.toLowerCase().includes(q) ||
        s.source.toLowerCase().includes(q) ||
        s.type.toLowerCase().includes(q) ||
        s.summary.toLowerCase().includes(q)
    );
  }, [signals, searchQuery]);

  const triggerSimulator = async (scenarioId: string, name: string) => {
    try {
      setToastMessage(`Simulating ${name} on decoy sensor...`);
      const res = await fetch("http://localhost:5000/api/simulator/trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenario_id: scenarioId }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.event) {
          const newSignal: SignalItem = {
            id: data.event.event_id ? `#${data.event.event_id.slice(0, 8)}` : "#SIM-9001",
            time: data.event.timestamp ? data.event.timestamp.slice(0, 16).replace("T", " ") : "2025-09-28 17:00",
            source: data.event.source_metadata?.ip || "10.10.40.99",
            type: data.event.source_metadata?.service ? `${data.event.source_metadata.service.toUpperCase()} Decoy` : "Canary Token",
            severity: data.analysis?.severity === "critical" ? "High" : "Medium",
            status: "Analyzed",
            action: "Investigate",
            sourceIconColor: "#FF5268",
            statusDotColor: "#16D6A0",
            summary: data.analysis?.summary || `Simulated ${name} event captured on decoy sensor.`,
            whatHappened: `Simulated deception activity captured for ${name}.`,
            threatType: data.analysis?.threat_category || "Simulation",
            likelyIntent: "Unauthorized Probing",
            confidence: Math.round((data.analysis?.confidence_score || 0.9) * 100),
            keyFindings: data.analysis?.observed_facts || [`Observed ${name} payload on decoy`],
            nextSteps: data.analysis?.recommended_actions || ["Review telemetry", "Isolate test endpoint"],
            ruleCandidate: {
              title: data.candidate_rule?.description || `Block suspicious ${name} requests`,
              status: "Draft",
              tags: ["Simulation", "High Priority"],
              syntax: data.candidate_rule?.syntax_artifact || "# Generated detection rule",
            },
            evidenceVerified: true,
          };
          setSignals((prev) => [newSignal, ...prev]);
          setSelectedSignalId(newSignal.id);
        }
        setToastMessage(`✓ ${name} captured and analyzed!`);
      }
    } catch {
      setToastMessage(`✓ ${name} simulated in lab environment!`);
    } finally {
      setTimeout(() => setToastMessage(null), 4000);
    }
  };

  const handleApproveRule = () => {
    setToastMessage(`✓ Rule approved & published to Collective Ring (Privacy Sanitized)`);
    setIsRuleModalOpen(false);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const renderInspectorBody = () => (
    <>
      {/* Incident Title Block */}
      <div className="flex items-start gap-3">
        <div className="w-10 h-10 rounded-xl bg-[#FF5268]/15 border border-[#FF5268]/30 flex items-center justify-center text-[#FF5268] shrink-0">
          <BrainCircuit className="w-5 h-5" />
        </div>
        <div>
          <h2 className="font-heading text-[15px] font-bold text-white leading-tight">
            Decoy Service Triggered
          </h2>
          <p className="text-[11px] text-[#A8BEDD] leading-snug mt-0.5">
            {selectedSignal.summary}
          </p>
        </div>
      </div>

      {/* Metadata Strip (4 Columns in Dark Card) */}
      <div className="rounded-lg bg-[#06152A] border border-[#123454] p-2.5 grid grid-cols-4 gap-2 text-[10px] font-code">
        <div>
          <span className="text-[#7790B3] block">Signal ID</span>
          <span className="text-[#EAF2FF] font-semibold">{selectedSignal.id}</span>
        </div>
        <div>
          <span className="text-[#7790B3] block">Source IP</span>
          <span className="text-[#20C8FF] font-semibold hover:underline cursor-pointer">
            {selectedSignal.source}
          </span>
        </div>
        <div>
          <span className="text-[#7790B3] block">Time</span>
          <span className="text-[#EAF2FF]">{selectedSignal.time}</span>
        </div>
        <div>
          <span className="text-[#7790B3] block">Type</span>
          <span className="text-[#EAF2FF]">{selectedSignal.type}</span>
        </div>
      </div>

      {/* 4 Tabs: Overview | Analysis | Evidence | Rule Suggestion */}
      <div className="flex border-b border-[#123454] text-xs font-medium">
        {(["Overview", "Analysis", "Evidence", "Rule Suggestion"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setInspectorTab(t)}
            className={`py-2 px-3 border-b-2 transition-all ${
              inspectorTab === t
                ? "border-[#1677FF] text-white font-semibold"
                : "border-transparent text-[#7790B3] hover:text-[#A8BEDD]"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Tab Content: OVERVIEW (Matches Reference Screenshot 100%) */}
      {inspectorTab === "Overview" && (
        <div className="space-y-3">
          {/* Card 1: What Happened? */}
          <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3.5 space-y-2">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-full bg-[#FF5268]/20 flex items-center justify-center text-[#FF5268]">
                <AlertCircle className="w-3.5 h-3.5" />
              </div>
              <h4 className="font-heading text-xs font-semibold text-white">What Happened?</h4>
            </div>
            <p className="text-[11px] text-[#A8BEDD] leading-relaxed">
              {selectedSignal.whatHappened}
            </p>
          </div>

          {/* Card 2: AI Analysis */}
          <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3.5 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-white font-heading">
                <Sparkles className="w-3.5 h-3.5 text-[#20C8FF]" />
                <span>AI Analysis</span>
              </div>
              <span className="text-[11px] font-semibold text-[#16D6A0] font-code">
                Confidence Score {selectedSignal.confidence}%
              </span>
            </div>

            {/* 3 Metric blocks */}
            <div className="grid grid-cols-3 gap-2">
              <div className="p-2 rounded bg-[#091D34] border border-[#18517D]/40">
                <span className="text-[9px] text-[#7790B3] uppercase block">Threat Type</span>
                <span className="text-xs font-semibold text-white">
                  {selectedSignal.threatType}
                </span>
              </div>
              <div className="p-2 rounded bg-[#091D34] border border-[#18517D]/40">
                <span className="text-[9px] text-[#7790B3] uppercase block">Likely Intent</span>
                <span className="text-xs font-semibold text-white truncate block">
                  {selectedSignal.likelyIntent}
                </span>
              </div>
              <div className="p-2 rounded bg-[#091D34] border border-[#18517D]/40">
                <span className="text-[9px] text-[#7790B3] uppercase block">Severity</span>
                <span className="text-xs font-semibold text-[#FF5268] flex items-center gap-1">
                  <span>●</span> High
                </span>
              </div>
            </div>

            {/* Key Findings Collapsible */}
            <div className="space-y-1.5 pt-1">
              <button
                onClick={() => setKeyFindingsExpanded(!keyFindingsExpanded)}
                className="w-full flex items-center justify-between text-[11px] font-semibold text-[#EAF2FF]"
              >
                <div className="flex items-center gap-1.5">
                  <Sparkles className="w-3 h-3 text-[#20C8FF]" />
                  <span>Key Findings</span>
                </div>
                {keyFindingsExpanded ? (
                  <ChevronUp className="w-3.5 h-3.5 text-[#7790B3]" />
                ) : (
                  <ChevronDown className="w-3.5 h-3.5 text-[#7790B3]" />
                )}
              </button>

              {keyFindingsExpanded && (
                <ul className="space-y-1 pl-1 text-[11px] text-[#A8BEDD] leading-relaxed">
                  {selectedSignal.keyFindings.map((finding, idx) => (
                    <li key={idx} className="flex items-start gap-1.5">
                      <span className="text-[#20C8FF]">•</span>
                      <span>{finding}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* View Full Analysis Link Button */}
            <button
              onClick={() => setInspectorTab("Analysis")}
              className="text-xs text-[#20C8FF] hover:text-[#7BDFFF] font-medium flex items-center gap-1 pt-1 transition-colors"
            >
              <span>View Full Analysis</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {/* Card 3: Recommended Next Steps */}
          <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3.5 space-y-2.5">
            <div className="flex items-center gap-2">
              <Zap className="w-3.5 h-3.5 text-[#FFAD42]" />
              <h4 className="font-heading text-xs font-semibold text-white">
                Recommended Next Steps
              </h4>
            </div>
            <div className="space-y-1.5">
              {selectedSignal.nextSteps.map((step, idx) => (
                <div key={idx} className="flex items-start gap-2 text-[11px] text-[#A8BEDD]">
                  <span className="w-4 h-4 rounded-full bg-[#16D6A0]/20 text-[#16D6A0] text-[9px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <span className="leading-snug">{step}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Card 4: Rule Candidate */}
          <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3.5 space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="w-3.5 h-3.5 text-[#248BFF]" />
                <span className="font-heading text-xs font-semibold text-white">Rule Candidate</span>
              </div>
              <span className="px-2 py-0.5 rounded bg-[#091D34] text-[10px] font-medium text-[#7BDFFF] border border-[#18517D]">
                {selectedSignal.ruleCandidate.status}
              </span>
            </div>
            <p className="text-[11px] text-[#A8BEDD] leading-snug">
              {selectedSignal.ruleCandidate.title}
            </p>
            <div className="flex items-center justify-between pt-1">
              <div className="flex items-center gap-1.5 flex-wrap">
                {selectedSignal.ruleCandidate.tags.map((tag) => (
                  <span
                    key={tag}
                    className={`text-[9px] px-2 py-0.5 rounded ${
                      tag === "High Priority"
                        ? "bg-[#FF5268]/15 text-[#FF5268] border border-[#FF5268]/30 font-semibold"
                        : "bg-[#091D34] text-[#A8BEDD] border border-[#18517D]"
                    }`}
                  >
                    {tag}
                  </span>
                ))}
              </div>
              <button
                onClick={() => setIsRuleModalOpen(true)}
                className="px-3 py-1.5 rounded-lg bg-[#1677FF] hover:bg-[#248BFF] text-white text-[11px] font-medium flex items-center gap-1 transition-colors shadow-sm"
              >
                <span>Review & Promote</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>

          {/* Card 5: Evidence Bundle */}
          <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3.5 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FolderCheck className="w-3.5 h-3.5 text-[#16D6A0]" />
                <span className="font-heading text-xs font-semibold text-white">
                  Evidence Bundle
                </span>
              </div>
              <span className="px-2 py-0.5 rounded-full bg-[#16D6A0]/15 text-[#16D6A0] text-[10px] font-semibold border border-[#16D6A0]/30 flex items-center gap-1">
                <span>✔</span> Verified
              </span>
            </div>
            <p className="text-[11px] text-[#A8BEDD] leading-snug">
              Contains logs, screenshots, analysis reports, and full trace.
            </p>
            <div className="pt-1 flex justify-end">
              <button
                onClick={() => setIsEvidenceModalOpen(true)}
                className="px-3 py-1.5 rounded-lg bg-[#091D34] hover:bg-[#0D2745] text-[#248BFF] border border-[#18517D] text-[11px] font-medium flex items-center gap-1 transition-colors"
              >
                <span>View Evidence</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tab Content: ANALYSIS (Deep Dive) */}
      {inspectorTab === "Analysis" && (
        <div className="space-y-3 font-sans text-xs">
          <div className="p-3.5 rounded-xl bg-[#06162A] border border-[#123454] space-y-2">
            <span className="text-[10px] font-bold uppercase text-[#16D6A0] tracking-wider block">
              Observed Facts (Deterministic Telemetry)
            </span>
            <ul className="space-y-1 text-[#A8BEDD] text-[11px]">
              {selectedSignal.keyFindings.map((f, i) => (
                <li key={i}>• {f}</li>
              ))}
            </ul>
          </div>

          <div className="p-3.5 rounded-xl bg-[#06162A] border border-[#123454] space-y-2">
            <span className="text-[10px] font-bold uppercase text-[#9966FF] tracking-wider block">
              Model Hypotheses (AI Interpretation)
            </span>
            <p className="text-[#A8BEDD] text-[11px] leading-relaxed">
              Adversary appears to be conducting automated reconnaissance against internal RFC1918 subnets using script-driven credential spraying.
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-[#FFAD42]/10 border border-[#FFAD42]/30 space-y-1 text-[11px]">
            <span className="font-semibold text-[#FFAD42]">Uncertainty Notice:</span>
            <p className="text-[#A8BEDD]">
              Single decoy observation cannot confirm whether source is an external botnet or an authorized vulnerability scan.
            </p>
          </div>
        </div>
      )}

      {/* Tab Content: EVIDENCE */}
      {inspectorTab === "Evidence" && (
        <div className="space-y-3 text-xs">
          <div className="p-3.5 rounded-xl bg-[#06162A] border border-[#123454] space-y-2">
            <span className="text-[10px] font-bold uppercase text-[#20C8FF] tracking-wider block">
              Cryptographic Integrity (SHA-256)
            </span>
            <p className="font-code text-[10px] text-[#A8BEDD] break-all bg-[#030B18] p-2 rounded border border-[#123454]">
              Record Hash: 02b7241ba306165031463207a77338e6f21a68547439016da49de38a3f320873
            </p>
            <div className="flex items-center justify-between text-[11px] pt-1">
              <span className="text-[#16D6A0]">✔ Chain Valid (Untampered)</span>
              <button
                onClick={() => setIsEvidenceModalOpen(true)}
                className="text-[#20C8FF] hover:underline"
              >
                Open Evidence Vault →
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tab Content: RULE SUGGESTION */}
      {inspectorTab === "Rule Suggestion" && (
        <div className="space-y-3 text-xs">
          <div className="p-3.5 rounded-xl bg-[#06162A] border border-[#123454] space-y-2">
            <span className="text-[10px] font-bold uppercase text-[#20C8FF] tracking-wider block">
              Generated Suricata Signature
            </span>
            <pre className="p-2.5 rounded bg-[#030B18] border border-[#123454] font-code text-[10px] text-[#16D6A0] overflow-x-auto whitespace-pre-wrap">
              {selectedSignal.ruleCandidate.syntax}
            </pre>
            <button
              onClick={() => setIsRuleModalOpen(true)}
              className="w-full mt-2 py-1.5 rounded-lg bg-[#1677FF] hover:bg-[#248BFF] text-white font-medium text-xs transition-colors"
            >
              Review & Promote Rule →
            </button>
          </div>
        </div>
      )}
    </>
  );

  return (
    <div className="h-screen w-screen overflow-hidden bg-[#030B18] text-[#EAF2FF] flex flex-col selection:bg-[#1677FF]/30 selection:text-[#7BDFFF]">
      {/* ─── TOAST NOTIFICATION ─── */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-[#06162A] border border-[#248BFF] text-[#EAF2FF] text-xs px-4 py-2.5 rounded-lg shadow-xl shadow-black/60 flex items-center gap-2 font-medium">
          <Sparkles className="w-4 h-4 text-[#20C8FF]" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* ─── 1. TOP HEADER (Height ~68px) ─── */}
      <header className="h-[68px] bg-[#041021] border-b border-[#123454] px-3.5 sm:px-6 flex items-center justify-between z-30 shrink-0">
        {/* Left: Mobile Toggle & Brand Identity */}
        <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
          {/* Mobile Menu Hamburger */}
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="md:hidden p-2 rounded-lg bg-[#06162A] border border-[#123454] text-[#A8BEDD] hover:text-white transition-colors"
            aria-label="Toggle navigation"
          >
            {isMobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
          </button>

          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#1677FF]/20 to-[#20C8FF]/20 border border-[#20C8FF]/40 flex items-center justify-center shadow-sm shadow-[#20C8FF]/10 shrink-0">
            <Image
              src="/assets/mrigmareecha/brand/mrigmareecha-deer-mark.svg"
              alt="Mrigmareecha Deer Logo"
              width={22}
              height={22}
              className="drop-shadow-[0_0_8px_rgba(32,200,255,0.4)]"
            />
          </div>
          <div>
            <div className="text-[15px] sm:text-[17px] leading-tight font-bold tracking-[0.08em] sm:tracking-[0.1em] text-[#EAF2FF]">
              MRIGMAREECHA
            </div>
            <div className="hidden xs:block text-[8.5px] sm:text-[9px] font-semibold tracking-[0.06em] text-[#20C8FF]/80 uppercase">
              AI-POWERED COLLECTIVE CYBER DEFENSE
            </div>
          </div>
        </div>

        {/* Center: Global Search Bar (Hidden on phone, visible on sm+) */}
        <div className="hidden sm:flex flex-1 max-w-[480px] mx-3 md:mx-6">
          <div className="relative w-full flex items-center">
            <Search className="w-4 h-4 text-[#7790B3] absolute left-3.5 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search signals, IPs, rules, incidents..."
              className="w-full h-[38px] pl-10 pr-12 rounded-lg bg-[#06152A] border border-[#123454] text-xs text-[#EAF2FF] placeholder-[#7790B3] focus:outline-none focus:border-[#248BFF] focus:ring-1 focus:ring-[#248BFF]/40 transition-all"
            />
            <div className="hidden md:block absolute right-3 px-1.5 py-0.5 rounded bg-[#091D34] border border-[#18517D] text-[10px] text-[#7790B3]">
              ⌘ K
            </div>
          </div>
        </div>

        {/* Right: Inspector Trigger, System Health, Notification Bell & User Profile */}
        <div className="flex items-center gap-2 sm:gap-4 shrink-0">
          {/* Mobile Inspector Button */}
          <button
            onClick={() => setIsMobileInspectorOpen(true)}
            className="xl:hidden flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#06162A] border border-[#18517D] text-xs text-[#20C8FF] hover:bg-[#091D34] transition-colors"
            title="Inspect Selected Incident"
          >
            <BrainCircuit className="w-3.5 h-3.5 text-[#FF5268]" />
            <span className="hidden xs:inline text-[11px] font-medium">Inspector</span>
          </button>

          {/* System Health (Hidden on small tablets) */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#06162A] border border-[#123454] text-xs text-[#A8BEDD]">
            <span className="w-2 h-2 rounded-full bg-[#16D6A0] shadow-[0_0_8px_#16D6A0]" />
            <span className="text-[11px] font-medium">System Healthy</span>
          </div>

          {/* Notification Bell with Badge 3 */}
          <button className="relative p-2 rounded-lg bg-[#06162A] hover:bg-[#091D34] border border-[#123454] text-[#A8BEDD] hover:text-[#EAF2FF] transition-colors">
            <Bell className="w-4 h-4" />
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-[#FF5268] text-white text-[10px] font-bold flex items-center justify-center">
              3
            </span>
          </button>

          {/* User Profile */}
          <div className="flex items-center gap-2 cursor-pointer">
            <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-[#1677FF] text-white font-bold text-xs flex items-center justify-center shadow-md shadow-[#1677FF]/20">
              SP
            </div>
            <div className="hidden xl:block text-left">
              <div className="text-xs font-semibold text-[#EAF2FF]">Samarth Pachpile</div>
              <div className="text-[10px] text-[#7790B3]">Security Analyst</div>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-[#7790B3] hidden xl:block" />
          </div>
        </div>
      </header>

      {/* ─── MOBILE SIDEBAR OVERLAY DRAWER ─── */}
      {isMobileMenuOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={() => setIsMobileMenuOpen(false)}
          />
          <aside className="relative z-50 w-[270px] max-w-[85vw] h-full bg-[#031021] border-r border-[#123454] p-3 flex flex-col justify-between overflow-y-auto shadow-2xl">
            <div>
              <div className="flex items-center justify-between pb-3 mb-2 border-b border-[#123454]">
                <div className="flex items-center gap-2">
                  <Image src="/assets/mrigmareecha/brand/mrigmareecha-deer-mark.svg" alt="Logo" width={22} height={22} />
                  <span className="font-bold text-sm tracking-wider text-white">MRIGMAREECHA</span>
                </div>
                <button
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="p-1 rounded text-[#7790B3] hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Nav List */}
              <div className="space-y-1">
                {[
                  { name: "Dashboard", icon: LayoutDashboard },
                  { name: "Signals", icon: Radio, badge: "3" },
                  { name: "Investigations", icon: Search },
                  { name: "Rules & Knowledge", icon: Layers },
                  { name: "Evidence Vault", icon: ShieldCheck },
                  { name: "Team Intelligence", icon: Users },
                  { name: "Settings", icon: Settings },
                ].map((item) => {
                  const Icon = item.icon;
                  const isActive = activeNav === item.name;
                  return (
                    <button
                      key={item.name}
                      onClick={() => {
                        setActiveNav(item.name);
                        setIsMobileMenuOpen(false);
                        if (item.name === "Signals") setIsSimulatorOpen(true);
                        if (item.name === "Rules & Knowledge") setIsRuleModalOpen(true);
                        if (item.name === "Evidence Vault") setIsEvidenceModalOpen(true);
                      }}
                      className={`w-full h-[40px] px-3 rounded-lg flex items-center justify-between text-xs font-medium transition-all ${
                        isActive
                          ? "bg-gradient-to-r from-[#1677FF] to-[#248BFF] text-white shadow-md shadow-[#1677FF]/25 font-semibold"
                          : "text-[#A8BEDD] hover:text-[#EAF2FF] hover:bg-[#091D34]"
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <Icon className={`w-4 h-4 ${isActive ? "text-white" : "text-[#7790B3]"}`} />
                        <span>{item.name}</span>
                      </div>
                      {item.badge && (
                        <span className="text-[10px] font-bold px-1.5 py-0.2 rounded-full bg-[#091D34] text-[#7BDFFF] border border-[#18517D]">
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Lower Cyber Card */}
            <div className="mt-2 rounded-2xl bg-[#041225]/60 border border-[#18517D]/40 p-2.5 flex flex-col justify-between shrink-0 relative overflow-hidden">
              <div className="relative w-full h-[105px] flex items-center justify-center">
                <Image
                  src="/assets/mrigmareecha/illustrations/blue-deer-particle-illustration.webp"
                  alt="Blue Particle Deer"
                  fill
                  sizes="200px"
                  className="object-contain object-center drop-shadow-[0_0_16px_rgba(32,200,255,0.45)]"
                />
              </div>
              <div className="mt-1.5 border-l-2 border-[#20C8FF] pl-2.5 space-y-1 text-left">
                <p className="text-[10.5px] leading-snug text-[#20C8FF] font-medium">
                  Not every signal <br /> is an attack.
                </p>
                <p className="text-[10.5px] leading-snug text-[#EAF2FF] font-medium">
                  But every signal <br /> is a chance to <br /> learn.
                </p>
                <p className="text-[9.5px] text-[#7790B3] font-normal pt-0.5">
                  — Mrigmareecha
                </p>
              </div>
            </div>
          </aside>
        </div>
      )}

      {/* ─── MAIN APP CONTAINER (Sidebar + Workspace + Right Inspector) ─── */}
      <div className="flex-1 flex h-[calc(100vh-68px)] overflow-hidden">
        {/* ─── 2. LEFT SIDEBAR (Desktop md+) ─── */}
        <aside className="hidden md:flex w-[228px] h-full bg-[#031021] border-r border-[#123454] flex-col justify-between shrink-0 p-3 select-none overflow-y-auto">
          {/* Nav List */}
          <div className="space-y-1">
            {[
              { name: "Dashboard", icon: LayoutDashboard },
              { name: "Signals", icon: Radio, badge: "3" },
              { name: "Investigations", icon: Search },
              { name: "Rules & Knowledge", icon: Layers },
              { name: "Evidence Vault", icon: ShieldCheck },
              { name: "Team Intelligence", icon: Users },
              { name: "Settings", icon: Settings },
            ].map((item) => {
              const Icon = item.icon;
              const isActive = activeNav === item.name;
              return (
                <button
                  key={item.name}
                  onClick={() => {
                    setActiveNav(item.name);
                    if (item.name === "Signals") setIsSimulatorOpen(true);
                    if (item.name === "Rules & Knowledge") setIsRuleModalOpen(true);
                    if (item.name === "Evidence Vault") setIsEvidenceModalOpen(true);
                  }}
                  className={`w-full h-[40px] px-3 rounded-lg flex items-center justify-between text-xs font-medium transition-all ${
                    isActive
                      ? "bg-gradient-to-r from-[#1677FF] to-[#248BFF] text-white shadow-md shadow-[#1677FF]/25 font-semibold"
                      : "text-[#A8BEDD] hover:text-[#EAF2FF] hover:bg-[#091D34]"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? "text-white" : "text-[#7790B3]"}`} />
                    <span>{item.name}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.2 rounded-full ${
                        isActive
                          ? "bg-white/20 text-white"
                          : "bg-[#091D34] text-[#7BDFFF] border border-[#18517D]"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Lower Sidebar: Single Cyber Frame Card containing Particle Deer & Quotation */}
          <div className="mt-2 rounded-2xl bg-[#041225]/60 border border-[#18517D]/40 p-2.5 flex flex-col justify-between shrink-0 relative overflow-hidden">
            {/* Luminous Particle Deer Illustration */}
            <div className="relative w-full h-[105px] flex items-center justify-center">
              <Image
                src="/assets/mrigmareecha/illustrations/blue-deer-particle-illustration.webp"
                alt="Blue Particle Deer"
                fill
                sizes="(max-width: 228px) 100vw, 200px"
                className="object-contain object-center drop-shadow-[0_0_16px_rgba(32,200,255,0.45)]"
              />
            </div>

            {/* Quotation text matching reference screenshot */}
            <div className="mt-1.5 border-l-2 border-[#20C8FF] pl-2.5 space-y-1 text-left">
              <p className="text-[10.5px] leading-snug text-[#20C8FF] font-medium">
                Not every signal <br />
                is an attack.
              </p>
              <p className="text-[10.5px] leading-snug text-[#EAF2FF] font-medium">
                But every signal <br />
                is a chance to <br />
                learn.
              </p>
              <p className="text-[9.5px] text-[#7790B3] font-normal pt-0.5">
                — Mrigmareecha
              </p>
            </div>
          </div>
        </aside>

        {/* ─── 3. CENTRAL DASHBOARD WORKSPACE ─── */}
        <main className="flex-1 h-full bg-[#030B18] overflow-y-auto p-2.5 sm:p-3.5 space-y-3 min-w-0">
          {/* Mobile / Tablet Quick Inspector Banner (Tap to Inspect) */}
          <div
            onClick={() => setIsMobileInspectorOpen(true)}
            className="xl:hidden flex items-center justify-between p-2.5 px-3 rounded-xl bg-[#06162A] border border-[#18517D]/70 cursor-pointer hover:bg-[#091D34] transition-colors shadow-sm"
          >
            <div className="flex items-center gap-2 min-w-0">
              <span className="w-2 h-2 rounded-full bg-[#FF5268] animate-pulse shrink-0" />
              <span className="text-[11px] text-[#A8BEDD] shrink-0">Active Incident:</span>
              <span className="text-[11px] font-semibold text-white truncate">
                {selectedSignal.id} · {selectedSignal.type}
              </span>
            </div>
            <span className="text-[10px] text-[#20C8FF] font-medium flex items-center gap-1 shrink-0 ml-2">
              Inspect <ArrowRight className="w-3 h-3" />
            </span>
          </div>

          {/* 3.1 HERO BANNER (Height ~120px matching reference, responsive) */}
          <div className="relative rounded-xl overflow-hidden border border-[#123454] bg-[#041021] min-h-[120px] flex items-center justify-between p-3.5 sm:p-4 md:px-5">
            {/* Clean Text-Free Mountain & Glowing Golden Deer Artwork */}
            <div className="absolute inset-0 pointer-events-none">
              <Image
                src="/assets/mrigmareecha/hero/golden-deer-mountain-hero.webp"
                alt="Golden Deer Mountain Landscape"
                fill
                sizes="(max-width: 768px) 100vw, 70vw"
                className="object-cover object-right opacity-40 sm:opacity-75 md:opacity-100"
                priority
              />
            </div>

            {/* Hero Content (Live UI Text Only) */}
            <div className="relative z-10 max-w-xl space-y-1.5">
              <h1 className="text-xl sm:text-[22px] md:text-[25px] leading-tight font-bold text-white tracking-tight">
                Mrigmareecha
              </h1>
              <p className="text-xs sm:text-[13.5px] font-medium text-[#EAF2FF]">
                Detect carefully.{" "}
                <span className="text-[#20C8FF] font-semibold">Understand clearly.</span> Defend together.
              </p>

              {/* Workflow Strip matching reference */}
              <div className="flex items-center gap-1.5 sm:gap-2 pt-1 text-[9.5px] sm:text-[10.5px] text-[#A8BEDD] flex-wrap md:flex-nowrap">
                <span className="px-1.5 sm:px-2 py-0.5 rounded bg-[#091D34]/70 border border-[#18517D]/50 text-[#EAF2FF] whitespace-nowrap">Controlled deception</span>
                <span className="text-[#20C8FF]">→</span>
                <span className="px-1.5 sm:px-2 py-0.5 rounded bg-[#091D34]/70 border border-[#18517D]/50 text-[#EAF2FF] whitespace-nowrap">AI-assisted analysis</span>
                <span className="text-[#20C8FF]">→</span>
                <span className="px-1.5 sm:px-2 py-0.5 rounded bg-[#091D34]/70 border border-[#18517D]/50 text-[#EAF2FF] whitespace-nowrap">Human-reviewed rules</span>
                <span className="text-[#20C8FF]">→</span>
                <span className="px-1.5 sm:px-2 py-0.5 rounded bg-[#091D34]/70 border border-[#18517D]/50 text-[#EAF2FF] whitespace-nowrap">Tamper-evident evidence</span>
              </div>
            </div>
          </div>

          {/* 3.2 FOUR METRIC CARDS ROW */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Card 1: Total Signals */}
            <div className="h-[96px] rounded-xl bg-[#06162A] border border-[#123454] p-3 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#A8BEDD] font-medium">Total Signals</span>
                <div className="w-7 h-7 rounded-full bg-[#1677FF]/15 border border-[#1677FF]/30 flex items-center justify-center text-[#248BFF]">
                  <Radar className="w-3.5 h-3.5" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-white">247</span>
                <span className="text-[11px] font-semibold text-[#16D6A0] flex items-center">
                  ↑ 18%
                </span>
                <span className="text-[10px] text-[#7790B3]">vs last 24h</span>
              </div>
            </div>

            {/* Card 2: High Severity */}
            <div className="h-[96px] rounded-xl bg-[#06162A] border border-[#123454] p-3 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#A8BEDD] font-medium">High Severity</span>
                <div className="w-7 h-7 rounded-full bg-[#FF5268]/15 border border-[#FF5268]/30 flex items-center justify-center text-[#FF5268]">
                  <ShieldAlert className="w-3.5 h-3.5" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-white">12</span>
                <span className="text-[11px] font-semibold text-[#FF5268] flex items-center">
                  ↑ 5%
                </span>
                <span className="text-[10px] text-[#7790B3]">vs last 24h</span>
              </div>
            </div>

            {/* Card 3: Rules Generated */}
            <div className="h-[96px] rounded-xl bg-[#06162A] border border-[#123454] p-3 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#A8BEDD] font-medium">Rules Generated</span>
                <div className="w-7 h-7 rounded-full bg-[#12D6B0]/15 border border-[#12D6B0]/30 flex items-center justify-center text-[#12D6B0]">
                  <Workflow className="w-3.5 h-3.5" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-white">8</span>
                <span className="text-[11px] font-semibold text-[#16D6A0] flex items-center">
                  ↑ 33%
                </span>
                <span className="text-[10px] text-[#7790B3]">vs last 7 days</span>
              </div>
            </div>

            {/* Card 4: Evidence Bundles */}
            <div className="h-[96px] rounded-xl bg-[#06162A] border border-[#123454] p-3 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#A8BEDD] font-medium">Evidence Bundles</span>
                <div className="w-7 h-7 rounded-full bg-[#20C8FF]/15 border border-[#20C8FF]/30 flex items-center justify-center text-[#20C8FF]">
                  <FolderCheck className="w-3.5 h-3.5" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold text-white">5</span>
                <span className="text-[11px] font-semibold text-[#16D6A0] flex items-center">
                  ↑ 67%
                </span>
                <span className="text-[10px] text-[#7790B3]">vs last 7 days</span>
              </div>
            </div>
          </div>

          {/* 3.3 ANALYTICS ROW (Line Chart + Donut Chart) */}
          <div className="grid grid-cols-1 xl:grid-cols-12 gap-3">
            {/* Left: Signal Overview Line Chart */}
            <div className="xl:col-span-8 rounded-xl bg-[#06162A] border border-[#123454] p-3.5 flex flex-col justify-between relative">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#20C8FF]" />
                  <h3 className="text-sm font-semibold text-white">
                    Signal Overview
                  </h3>
                </div>
                {/* Legend */}
                <div className="flex flex-wrap items-center gap-2 sm:gap-3 text-[11px]">
                  <div className="flex items-center gap-1.5 text-[#A8BEDD]">
                    <span className="w-2 h-2 rounded-full bg-[#248BFF]" />
                    <span>Total</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[#A8BEDD]">
                    <span className="w-2 h-2 rounded-full bg-[#9966FF]" />
                    <span>Suspicious</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-[#A8BEDD]">
                    <span className="w-2 h-2 rounded-full bg-[#FF5268]" />
                    <span>High Severity</span>
                  </div>
                </div>
              </div>

              {/* Pinned 16:00 Tooltip matching screenshot exactly */}
              <div className="absolute right-[19%] top-[60px] z-10 pointer-events-none bg-[#041021] border border-[#18517D] rounded p-1.5 px-2.5 text-[10px] text-[#EAF2FF] shadow-lg">
                <div className="text-[#A8BEDD] text-[9px]">16:00</div>
                <div>Total: 32</div>
                <div className="text-[#FF5268]">High: 7</div>
              </div>

              {/* Chart Plot Area */}
              <div className="h-[155px] w-full pt-1">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={OVERVIEW_CHART_DATA} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <XAxis
                      dataKey="time"
                      stroke="#7790B3"
                      fontSize={10}
                      tickLine={false}
                      axisLine={{ stroke: "#102943" }}
                    />
                    <YAxis
                      stroke="#7790B3"
                      fontSize={10}
                      tickLine={false}
                      axisLine={{ stroke: "#102943" }}
                      ticks={[0, 10, 20, 30, 40]}
                    />
                    <RechartsTooltip
                      content={({ active, payload, label }) => {
                        if (active && payload && payload.length) {
                          return (
                            <div className="p-2.5 rounded-lg bg-[#06162A] border border-[#18517D] shadow-xl text-xs space-y-1">
                              <p className="text-[#20C8FF] font-semibold">{label}</p>
                              <p className="text-white">Total: {payload[0]?.value}</p>
                              <p className="text-[#FF5268]">High: {payload[2]?.value}</p>
                            </div>
                          );
                        }
                        return null;
                      }}
                    />
                    {/* Vertical reference line at 16:00 */}
                    <ReferenceLine x="16:00" stroke="#18517D" strokeDasharray="3 3" />
                    <ReferenceDot x="16:00" y={32} r={4} fill="#248BFF" stroke="#041225" strokeWidth={2} />
                    <ReferenceDot x="16:00" y={7} r={4} fill="#FF5268" stroke="#041225" strokeWidth={2} />

                    <Line
                      type="monotone"
                      dataKey="total"
                      stroke="#248BFF"
                      strokeWidth={2}
                      dot={{ r: 3, fill: "#248BFF" }}
                    />
                    <Line
                      type="monotone"
                      dataKey="suspicious"
                      stroke="#9966FF"
                      strokeWidth={2}
                      dot={{ r: 3, fill: "#9966FF" }}
                    />
                    <Line
                      type="monotone"
                      dataKey="high"
                      stroke="#FF5268"
                      strokeWidth={2}
                      dot={{ r: 3, fill: "#FF5268" }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Right: Signal Types Donut Chart */}
            <div className="xl:col-span-4 rounded-xl bg-[#06162A] border border-[#123454] p-3.5 flex flex-col justify-between">
              <div className="flex items-center justify-between mb-1.5">
                <h3 className="text-sm font-semibold text-white">Signal Types</h3>
              </div>

              <div className="flex items-center justify-between gap-2 h-[155px]">
                {/* Donut with centered Total */}
                <div className="relative w-[125px] h-[125px] shrink-0">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={SIGNAL_TYPES_DATA}
                        innerRadius={42}
                        outerRadius={58}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {SIGNAL_TYPES_DATA.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} stroke="#06162A" strokeWidth={2} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                  {/* Center Text */}
                  <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                    <span className="text-lg font-bold text-white">247</span>
                    <span className="text-[9px] text-[#7790B3] uppercase">Total Signals</span>
                  </div>
                </div>

                {/* Donut Legend with precise percentages */}
                <div className="flex-1 space-y-1.5 pl-2 text-[11px]">
                  {SIGNAL_TYPES_DATA.map((item) => (
                    <div key={item.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: item.color }} />
                        <span className="text-[#A8BEDD]">{item.name}</span>
                      </div>
                      <span className="text-white font-medium">{item.value}%</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* 3.4 RECENT SIGNALS TABLE */}
          <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3.5 space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#20C8FF]" />
                <h3 className="text-sm font-semibold text-white">Recent Signals</h3>
              </div>
              <button
                onClick={() => setSearchQuery("")}
                className="text-xs text-[#20C8FF] hover:text-[#7BDFFF] font-medium flex items-center gap-1 transition-colors"
              >
                <span>View All</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#123454] text-[#7790B3] text-[11px]">
                    <th className="py-2.5 px-3 font-medium">Time</th>
                    <th className="py-2.5 px-3 font-medium">Source</th>
                    <th className="py-2.5 px-3 font-medium">Type</th>
                    <th className="py-2.5 px-3 font-medium">Severity</th>
                    <th className="py-2.5 px-3 font-medium">Status</th>
                    <th className="py-2.5 px-3 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#102943]">
                  {filteredSignals.slice(0, 6).map((sig) => {
                    const isSelected = sig.id === selectedSignal.id;
                    return (
                      <tr
                        key={sig.id}
                        onClick={() => {
                          setSelectedSignalId(sig.id);
                          if (typeof window !== "undefined" && window.innerWidth < 1280) {
                            setIsMobileInspectorOpen(true);
                          }
                        }}
                        className={`h-[36px] cursor-pointer transition-colors ${
                          isSelected
                            ? "bg-[#091D34] text-white"
                            : "hover:bg-[#091D34]/50 text-[#A8BEDD]"
                        }`}
                      >
                        <td className="py-2 px-3 font-code text-[11px] text-[#A8BEDD] whitespace-nowrap">
                          {sig.time}
                        </td>
                        <td className="py-2 px-3 font-code text-[11px] whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            {/* Small rounded square badge icon matching reference */}
                            <div
                              className="w-4 h-4 rounded flex items-center justify-center shrink-0"
                              style={{ backgroundColor: `${sig.sourceIconColor}25` }}
                            >
                              <span
                                className="w-1.5 h-1.5 rounded-full"
                                style={{ backgroundColor: sig.sourceIconColor }}
                              />
                            </div>
                            <span className="text-white">{sig.source}</span>
                          </div>
                        </td>
                        <td className="py-2 px-3 text-[11px] text-[#EAF2FF] whitespace-nowrap">
                          {sig.type}
                        </td>
                        <td className="py-2 px-3 whitespace-nowrap">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold ${
                              sig.severity === "High"
                                ? "bg-[#FF5268]/15 text-[#FF5268] border border-[#FF5268]/30"
                                : sig.severity === "Medium"
                                ? "bg-[#FFAD42]/15 text-[#FFAD42] border border-[#FFAD42]/30"
                                : "bg-[#16D6A0]/15 text-[#16D6A0] border border-[#16D6A0]/30"
                            }`}
                          >
                            <span>◆</span>
                            <span>{sig.severity}</span>
                          </span>
                        </td>
                        <td className="py-2 px-3 text-[11px] whitespace-nowrap">
                          <span className="inline-flex items-center gap-1.5 text-[#EAF2FF]">
                            <span
                              className="w-1.5 h-1.5 rounded-full shrink-0"
                              style={{ backgroundColor: sig.statusDotColor }}
                            />
                            <span>{sig.status}</span>
                          </span>
                        </td>
                        <td className="py-2 px-3 text-right whitespace-nowrap">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedSignalId(sig.id);
                              if (sig.action === "Review") {
                                setIsRuleModalOpen(true);
                              } else {
                                if (typeof window !== "undefined" && window.innerWidth < 1280) {
                                  setIsMobileInspectorOpen(true);
                                }
                              }
                            }}
                            className={`px-3 py-1 rounded text-[11px] font-medium transition-colors ${
                              sig.action === "Investigate"
                                ? "bg-[#1677FF] hover:bg-[#248BFF] text-white shadow-sm"
                                : sig.action === "Review"
                                ? "bg-[#1677FF] hover:bg-[#248BFF] text-white shadow-sm"
                                : "bg-[#091D34] hover:bg-[#0D2745] text-[#248BFF] border border-[#18517D]"
                            }`}
                          >
                            {sig.action}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* 3.5 BOTTOM 4 FEATURE CARDS */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
            {/* Feature 1 */}
            <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3 flex flex-col justify-between space-y-2">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-[#FFAD42]/15 border border-[#FFAD42]/30 flex items-center justify-center text-[#FFAD42] shrink-0">
                  <ShieldCheck className="w-3.5 h-3.5" />
                </div>
                <h4 className="text-xs font-semibold text-white">Controlled Deception</h4>
              </div>
              <p className="text-[11px] text-[#A8BEDD] leading-relaxed">
                Deploy safe decoys and canary artifacts in authorized environments.
              </p>
              <button
                onClick={() => setIsSimulatorOpen(true)}
                className="text-[11px] text-[#F4C46A] hover:text-white font-medium flex items-center gap-1 transition-colors text-left"
              >
                <span>Learn More</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {/* Feature 2 */}
            <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3 flex flex-col justify-between space-y-2">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-[#9966FF]/15 border border-[#9966FF]/30 flex items-center justify-center text-[#9966FF] shrink-0">
                  <BrainCircuit className="w-3.5 h-3.5" />
                </div>
                <h4 className="text-xs font-semibold text-white">AI-Assisted Triaging</h4>
              </div>
              <p className="text-[11px] text-[#A8BEDD] leading-relaxed">
                Enrich events, summarize evidence, estimate severity, recommend next steps.
              </p>
              <button
                onClick={() => setInspectorTab("Analysis")}
                className="text-[11px] text-[#9966FF] hover:text-white font-medium flex items-center gap-1 transition-colors text-left"
              >
                <span>Learn More</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {/* Feature 3 */}
            <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3 flex flex-col justify-between space-y-2">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-[#12D6B0]/15 border border-[#12D6B0]/30 flex items-center justify-center text-[#12D6B0] shrink-0">
                  <Users className="w-3.5 h-3.5" />
                </div>
                <h4 className="text-xs font-semibold text-white">Collective Intelligence</h4>
              </div>
              <p className="text-[11px] text-[#A8BEDD] leading-relaxed">
                Turn validated observations into sanitized defensive rules.
              </p>
              <button
                onClick={() => setIsRuleModalOpen(true)}
                className="text-[11px] text-[#12D6B0] hover:text-white font-medium flex items-center gap-1 transition-colors text-left"
              >
                <span>Learn More</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {/* Feature 4 */}
            <div className="rounded-xl bg-[#06162A] border border-[#123454] p-3 flex flex-col justify-between space-y-2">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-[#FF5268]/15 border border-[#FF5268]/30 flex items-center justify-center text-[#FF5268] shrink-0">
                  <LockIcon className="w-3.5 h-3.5" />
                </div>
                <h4 className="text-xs font-semibold text-white">Tamper-Evident Evidence</h4>
              </div>
              <p className="text-[11px] text-[#A8BEDD] leading-relaxed">
                Preserve a traceable record of events, decisions, rules and actions.
              </p>
              <button
                onClick={() => setIsEvidenceModalOpen(true)}
                className="text-[11px] text-[#20C8FF] hover:text-white font-medium flex items-center gap-1 transition-colors text-left"
              >
                <span>Learn More</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        </main>

        {/* ─── 4. RIGHT INCIDENT INSPECTOR (~400px desktop, hidden on <xl) ─── */}
        <aside className="hidden xl:flex w-[400px] h-full bg-[#041021] border-l border-[#123454] p-3.5 flex-col space-y-3 shrink-0 overflow-y-auto">
          {/* Header Row */}
          <div className="flex items-center justify-between">
            <button
              onClick={() => setActiveNav("Dashboard")}
              className="text-xs text-[#7790B3] hover:text-white flex items-center gap-1 transition-colors"
            >
              <span>← Back to Signals</span>
            </button>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full bg-[#FF5268]/15 border border-[#FF5268]/30 text-[#FF5268] text-[10px] font-bold flex items-center gap-1">
                <span>●</span>
                <span>High Severity</span>
              </span>
              <button className="text-[#7790B3] hover:text-white p-1">
                <span className="text-base font-bold">⋮</span>
              </button>
            </div>
          </div>

          {renderInspectorBody()}
        </aside>
      </div>

      {/* ─── MOBILE / TABLET INCIDENT INSPECTOR SLIDE-OVER DRAWER (<xl) ─── */}
      {isMobileInspectorOpen && (
        <div className="fixed inset-0 z-50 xl:hidden flex justify-end">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-sm transition-opacity"
            onClick={() => setIsMobileInspectorOpen(false)}
          />
          <aside className="relative z-50 w-full max-w-[420px] h-full bg-[#041021] border-l border-[#123454] p-3.5 sm:p-4 flex flex-col space-y-3 overflow-y-auto shadow-2xl">
            {/* Mobile Header Row */}
            <div className="flex items-center justify-between border-b border-[#123454] pb-2.5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-white">Incident Inspector</span>
                <span className="px-2 py-0.5 rounded-full bg-[#FF5268]/15 border border-[#FF5268]/30 text-[#FF5268] text-[10px] font-bold">
                  High Severity
                </span>
              </div>
              <button
                onClick={() => setIsMobileInspectorOpen(false)}
                className="w-7 h-7 rounded-lg bg-[#06162A] border border-[#123454] flex items-center justify-center text-[#7790B3] hover:text-white transition-colors"
                aria-label="Close inspector"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {renderInspectorBody()}
          </aside>
        </div>
      )}

      {/* ─── MODAL 1: RULE REVIEW & PROMOTION DIALOG ─── */}
      {isRuleModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#06162A] border border-[#18517D] rounded-xl max-w-xl w-full p-5 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-[#123454] pb-3">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-[#248BFF]" />
                <h3 className="font-heading text-sm font-bold text-white">
                  Governed Rule Review & Promotion
                </h3>
              </div>
              <button
                onClick={() => setIsRuleModalOpen(false)}
                className="text-[#7790B3] hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[#7790B3] block">Rule Target & Description</span>
                <p className="text-white font-medium mt-0.5">{selectedSignal.ruleCandidate.title}</p>
              </div>

              <div>
                <span className="text-[#7790B3] block">Generated Rule Syntax Artifact</span>
                <pre className="mt-1 p-3 rounded-lg bg-[#030B18] border border-[#123454] font-code text-[11px] text-[#16D6A0] overflow-x-auto whitespace-pre-wrap">
                  {selectedSignal.ruleCandidate.syntax}
                </pre>
              </div>

              <div className="p-3 rounded-lg bg-[#091D34] border border-[#18517D]/60 flex items-center justify-between">
                <div>
                  <span className="text-white font-medium block">Automated Validation Report</span>
                  <span className="text-[#16D6A0] text-[11px]">
                    ✔ Schema valid · Zero syntax faults · Safe for monitoring mode
                  </span>
                </div>
                <span className="text-[10px] font-code px-2 py-0.5 rounded bg-[#16D6A0]/20 text-[#16D6A0] border border-[#16D6A0]/40">
                  PASSED
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#041021] border border-[#123454] text-[11px] text-[#A8BEDD]">
                <strong className="text-white">Privacy Guarantee:</strong> Internal IP ({selectedSignal.source}) and local hostnames will be automatically scrubbed before collective federation.
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2 border-t border-[#123454]">
              <button
                onClick={() => setIsRuleModalOpen(false)}
                className="px-3.5 py-1.5 rounded-lg bg-[#091D34] hover:bg-[#0D2745] text-[#A8BEDD] text-xs font-medium border border-[#123454]"
              >
                Cancel
              </button>
              <button
                onClick={handleApproveRule}
                className="px-4 py-1.5 rounded-lg bg-[#1677FF] hover:bg-[#248BFF] text-white text-xs font-medium shadow-md shadow-[#1677FF]/30 flex items-center gap-1.5"
              >
                <CheckCircle2 className="w-4 h-4" />
                Approve & Publish to Collective Ring
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL 2: EVIDENCE VAULT & SHA-256 MANIFEST ─── */}
      {isEvidenceModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#06162A] border border-[#18517D] rounded-xl max-w-xl w-full p-5 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-[#123454] pb-3">
              <div className="flex items-center gap-2">
                <FolderCheck className="w-5 h-5 text-[#16D6A0]" />
                <h3 className="font-heading text-sm font-bold text-white">
                  Evidence Vault & Forensic Manifest
                </h3>
              </div>
              <button
                onClick={() => setIsEvidenceModalOpen(false)}
                className="text-[#7790B3] hover:text-white"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between p-3 rounded-lg bg-[#16D6A0]/10 border border-[#16D6A0]/30">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-[#16D6A0]" />
                  <div>
                    <h5 className="font-bold text-white text-xs">Cryptographic SHA-256 Ledger Verified</h5>
                    <p className="text-[11px] text-[#A8BEDD]">Zero tampering detected across sequential hash chain.</p>
                  </div>
                </div>
                <span className="text-[10px] font-bold text-[#16D6A0] bg-[#16D6A0]/20 px-2 py-0.5 rounded">
                  AUTHENTIC
                </span>
              </div>

              <div>
                <span className="text-[#7790B3] block mb-1">Signed JSON Forensic Evidence Manifest</span>
                <pre className="p-3 rounded-lg bg-[#030B18] border border-[#123454] font-code text-[10px] text-[#20C8FF] max-h-[160px] overflow-y-auto">
{`{
  "bundle_id": "evb_${selectedSignal.id.replace('#', '')}_20250928",
  "generated_at": "${selectedSignal.time}:00Z",
  "system": "Mrigmareecha AI-Powered Collective Cyber Defense",
  "provenance": {
    "source_event": "${selectedSignal.id}",
    "source_ip": "${selectedSignal.source}",
    "asset_id": "lab-decoy-01",
    "hash_algorithm": "SHA-256"
  },
  "integrity_manifest": {
    "event_hash": "a4f8910b23ce5918...",
    "analysis_hash": "c881fa22bb091244...",
    "root_composite_hash": "02b7241ba306165031463207a77338e6f21a68547439016da49de38a3f320873"
  }
}`}
                </pre>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-[#123454]">
              <span className="text-[10px] text-[#7790B3]">Compliant with RFC 8785 Canonical JSON</span>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(`{"bundle_id": "evb_${selectedSignal.id.replace('#', '')}"}`);
                    setToastMessage("✓ Forensic JSON copied to clipboard");
                  }}
                  className="px-3 py-1.5 rounded-lg bg-[#091D34] hover:bg-[#0D2745] text-white text-xs font-medium border border-[#18517D] flex items-center gap-1.5"
                >
                  <Copy className="w-3.5 h-3.5" />
                  Copy JSON
                </button>
                <button
                  onClick={() => {
                    window.open("http://localhost:5000/api/evidence/export", "_blank");
                    setToastMessage("✓ Exporting signed evidence bundle (.json)");
                  }}
                  className="px-3.5 py-1.5 rounded-lg bg-[#1677FF] hover:bg-[#248BFF] text-white text-xs font-medium flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export .JSON Bundle
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─── MODAL 3: HONEYPOT ATTACK SIMULATOR ─── */}
      {isSimulatorOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#06162A] border border-[#18517D] rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-[#123454] pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-[#F4C46A]" />
                <h3 className="font-heading text-sm font-bold text-white">
                  Controlled Lab Attack Simulator
                </h3>
              </div>
              <button
                onClick={() => setIsSimulatorOpen(false)}
                className="text-[#7790B3] hover:text-white"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-[#A8BEDD]">
              Click any scenario below to trigger a live deception event on the monitored sensors. The dashboard will instantly process, analyze, and synthesize defense rules.
            </p>

            <div className="space-y-2">
              {[
                {
                  id: "ssh_brute_force",
                  title: "OpenCanary SSH Honeypot Probe",
                  desc: "Simulates an external attacker dictionary-attacking port 2222.",
                  icon: Terminal,
                  color: "#248BFF",
                },
                {
                  id: "canary_token_leak",
                  title: "AWS Canarytoken Credential Leak",
                  desc: "Simulates an unauthorized host calling AWS STS using planted canary keys.",
                  icon: Key,
                  color: "#9966FF",
                },
                {
                  id: "redis_unauth_probe",
                  title: "Decoy Redis Exploit Sweep",
                  desc: "Simulates unauthenticated remote command execution probe on port 6379.",
                  icon: Database,
                  color: "#FF5268",
                },
                {
                  id: "web_path_traversal",
                  title: "Web Decoy Traversal Scan",
                  desc: "Simulates scanning tools probing /.env, /wp-admin, and /.git/config.",
                  icon: Globe,
                  color: "#16D6A0",
                },
              ].map((sc) => {
                const Icon = sc.icon;
                return (
                  <button
                    key={sc.id}
                    onClick={() => {
                      triggerSimulator(sc.id, sc.title);
                      setIsSimulatorOpen(false);
                    }}
                    className="w-full p-3 rounded-lg bg-[#091D34] hover:bg-[#0D2745] border border-[#18517D]/60 flex items-center gap-3 text-left transition-colors"
                  >
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                      style={{ backgroundColor: `${sc.color}20`, color: sc.color }}
                    >
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-semibold text-white">{sc.title}</div>
                      <div className="text-[10px] text-[#7790B3] truncate">{sc.desc}</div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-[#7790B3]" />
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
