import { useState, useEffect, useRef, useCallback, useMemo } from "react";

// ═══════════════════════════════════════════════════════════════════
// AUTO-VIA: Automotive Vulnerability Intelligence Aggregator
// Full Platform — Search, Score, Classify, Export
// ═══════════════════════════════════════════════════════════════════

// ── CONSTANTS & DATA ──────────────────────────────────────────────

const ECU_DOMAINS = {
  braking: { label: "Electronic Braking System", asil: "ASIL_D", modifier: 1.30, color: "#DC2626", icon: "⊘" },
  steering: { label: "Electric Power Steering", asil: "ASIL_D", modifier: 1.30, color: "#B91C1C", icon: "◎" },
  powertrain: { label: "Powertrain / Engine Control", asil: "ASIL_C", modifier: 1.20, color: "#EA580C", icon: "⚙" },
  chassis: { label: "Chassis Control", asil: "ASIL_C", modifier: 1.20, color: "#D97706", icon: "▣" },
  adas: { label: "ADAS / Autonomous", asil: "ASIL_D", modifier: 1.30, color: "#7C3AED", icon: "◈" },
  gateway: { label: "Gateway ECU", asil: "ASIL_B", modifier: 1.10, color: "#2563EB", icon: "⬡" },
  telematics: { label: "Telematics Control Unit", asil: "ASIL_A", modifier: 1.05, color: "#0891B2", icon: "◇" },
  infotainment: { label: "Infotainment / IVI", asil: "QM", modifier: 1.00, color: "#059669", icon: "▷" },
  body: { label: "Body Control Module", asil: "QM", modifier: 1.00, color: "#65A30D", icon: "□" },
  diagnostics: { label: "Diagnostics Interface", asil: "QM", modifier: 1.00, color: "#6B7280", icon: "◻" },
};

const ASIL_MODIFIERS = { QM: 1.00, ASIL_A: 1.05, ASIL_B: 1.10, ASIL_C: 1.20, ASIL_D: 1.30 };

const REACHABILITY_MODIFIERS = {
  "remote_external|telematics": 1.25,
  "remote_external|wifi_bt": 1.18,
  "remote_adjacent|wifi_bt": 1.15,
  "remote_adjacent|ethernet": 1.12,
  "local|can": 1.05,
  "local|diagnostic": 1.05,
  "physical|diagnostic": 1.00,
  "physical|can": 0.95,
};

const EXPLOIT_MODIFIERS = {
  active_exploitation: 1.40,
  weaponized: 1.30,
  functional: 1.15,
  poc: 1.10,
  unknown: 0.90,
};

const PRIORITY_TIERS = {
  P0_critical: { label: "P0 CRITICAL", color: "#DC2626", bg: "#FEF2F2", sla: "Immediate (24–72h)", action: "patch" },
  P1_high: { label: "P1 HIGH", color: "#EA580C", bg: "#FFF7ED", sla: "Within 7 days", action: "patch" },
  P2_medium: { label: "P2 MEDIUM", color: "#D97706", bg: "#FFFBEB", sla: "Within 30 days", action: "mitigate" },
  P3_low: { label: "P3 LOW", color: "#2563EB", bg: "#EFF6FF", sla: "Scheduled maintenance", action: "monitor" },
};

const ATTACK_SURFACES = ["remote_external", "remote_adjacent", "local", "physical"];
const NETWORK_PATHS = ["telematics", "wifi_bt", "ethernet", "can", "diagnostic", "unknown"];
const EXPLOIT_MATURITIES = ["active_exploitation", "weaponized", "functional", "poc", "unknown"];

// ── SAMPLE CVE DATABASE ───────────────────────────────────────────
const CVE_DATABASE = [
  {
    cve_id: "CVE-2025-12345", published: "2025-11-18", modified: "2026-01-06",
    description: "Buffer overflow in ExampleTLS library allows remote code execution via malformed TLS handshake packets sent to the vehicle gateway ECU's OTA update channel.",
    cvss_v4_base_score: 8.6, cvss_v4_base_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    cwe_ids: ["CWE-120"], affected_product: "ExampleTLS 1.2.3",
    cpe_matches: ["cpe:2.3:a:example:exampletls:1.2.3:*:*:*:*:*:*:*"],
    ecu_domain: "gateway", attack_surface: "remote_external", network_path: "telematics",
    exploit_maturity: "active_exploitation", kev_listed: true,
    source_feeds: ["NVD", "MITRE", "CISA_KEV"],
    sbom_component: "ExampleTLS", sbom_version: "1.2.3", sbom_purl: "pkg:generic/exampletls@1.2.3",
    vendor_advisories: [{ vendor: "ExampleCorp", advisory_id: "EX-SA-2025-001" }],
  },
  {
    cve_id: "CVE-2025-67890", published: "2025-12-03", modified: "2026-01-15",
    description: "Integer overflow vulnerability in QNX Neutrino RTOS kernel allows local privilege escalation on ADAS perception ECU, potentially enabling unauthorized access to sensor fusion pipeline.",
    cvss_v4_base_score: 7.8, cvss_v4_base_vector: "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    cwe_ids: ["CWE-190"], affected_product: "QNX Neutrino 7.1",
    cpe_matches: ["cpe:2.3:a:blackberry:qnx:7.1:*:*:*:*:*:*:*"],
    ecu_domain: "adas", attack_surface: "local", network_path: "can",
    exploit_maturity: "poc", kev_listed: false,
    source_feeds: ["NVD", "MITRE"],
    sbom_component: "QNX Neutrino", sbom_version: "7.1", sbom_purl: "pkg:generic/qnx-neutrino@7.1",
    vendor_advisories: [{ vendor: "BlackBerry QNX", advisory_id: "QNX-SA-2025-012" }],
  },
  {
    cve_id: "CVE-2026-00123", published: "2026-01-10", modified: "2026-02-01",
    description: "Heap-based buffer overflow in WolfSSL TLS library v5.6.x allows adjacent network attacker to execute arbitrary code on Telematics Control Unit via crafted DTLS packets over Bluetooth.",
    cvss_v4_base_score: 8.1, cvss_v4_base_vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L",
    cwe_ids: ["CWE-122"], affected_product: "WolfSSL 5.6.4",
    cpe_matches: ["cpe:2.3:a:wolfssl:wolfssl:5.6.4:*:*:*:*:*:*:*"],
    ecu_domain: "telematics", attack_surface: "remote_adjacent", network_path: "wifi_bt",
    exploit_maturity: "weaponized", kev_listed: false,
    source_feeds: ["NVD", "ExploitDB"],
    sbom_component: "WolfSSL", sbom_version: "5.6.4", sbom_purl: "pkg:generic/wolfssl@5.6.4",
    vendor_advisories: [{ vendor: "wolfSSL Inc.", advisory_id: "WOLF-2026-003" }],
  },
  {
    cve_id: "CVE-2025-44556", published: "2025-09-22", modified: "2025-12-14",
    description: "Unauthenticated CAN bus message injection in AUTOSAR Classic Platform BSW allows physical attacker with OBD-II access to send arbitrary diagnostic commands to Electronic Braking System ECU.",
    cvss_v4_base_score: 9.1, cvss_v4_base_vector: "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    cwe_ids: ["CWE-306"], affected_product: "AUTOSAR Classic 4.4.0",
    cpe_matches: ["cpe:2.3:a:autosar:classic_platform:4.4.0:*:*:*:*:*:*:*"],
    ecu_domain: "braking", attack_surface: "physical", network_path: "diagnostic",
    exploit_maturity: "functional", kev_listed: false,
    source_feeds: ["NVD", "MITRE"],
    sbom_component: "AUTOSAR Classic BSW", sbom_version: "4.4.0", sbom_purl: "pkg:generic/autosar-classic@4.4.0",
    vendor_advisories: [],
  },
  {
    cve_id: "CVE-2026-01567", published: "2026-01-28", modified: "2026-02-20",
    description: "Cross-site scripting vulnerability in Android Automotive OS infotainment web browser component allows remote attacker to inject malicious scripts via crafted navigation URL, potentially accessing vehicle API endpoints.",
    cvss_v4_base_score: 5.4, cvss_v4_base_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    cwe_ids: ["CWE-79"], affected_product: "Android Automotive OS 14",
    cpe_matches: ["cpe:2.3:a:google:android:14.0:*:*:*:*:automotive:*:*"],
    ecu_domain: "infotainment", attack_surface: "remote_external", network_path: "wifi_bt",
    exploit_maturity: "poc", kev_listed: false,
    source_feeds: ["NVD"],
    sbom_component: "Android Automotive", sbom_version: "14.0", sbom_purl: "pkg:generic/android-automotive@14.0",
    vendor_advisories: [{ vendor: "Google", advisory_id: "ASB-2026-01" }],
  },
  {
    cve_id: "CVE-2025-78901", published: "2025-08-15", modified: "2025-11-30",
    description: "Use-after-free vulnerability in Linux kernel CAN subsystem (SocketCAN) allows local attacker to escalate privileges on Gateway ECU running AGL Linux distribution.",
    cvss_v4_base_score: 7.0, cvss_v4_base_vector: "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    cwe_ids: ["CWE-416"], affected_product: "Linux Kernel 6.1.x",
    cpe_matches: ["cpe:2.3:a:linux:linux_kernel:6.1:*:*:*:*:*:*:*"],
    ecu_domain: "gateway", attack_surface: "local", network_path: "can",
    exploit_maturity: "poc", kev_listed: false,
    source_feeds: ["NVD", "MITRE", "ExploitDB"],
    sbom_component: "Linux Kernel", sbom_version: "6.1.72", sbom_purl: "pkg:generic/linux-kernel@6.1.72",
    vendor_advisories: [{ vendor: "Automotive Grade Linux", advisory_id: "AGL-SA-2025-007" }],
  },
  {
    cve_id: "CVE-2026-02345", published: "2026-02-05", modified: "2026-02-28",
    description: "Improper input validation in VxWorks TCP/IP stack (IPnet) allows remote attacker to cause denial of service on Powertrain ECU via specially crafted TCP packets sent through cellular modem path.",
    cvss_v4_base_score: 8.2, cvss_v4_base_vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:H/SA:H",
    cwe_ids: ["CWE-20"], affected_product: "VxWorks 7 SR0660",
    cpe_matches: ["cpe:2.3:a:wind_river:vxworks:7:*:*:*:*:*:*:*"],
    ecu_domain: "powertrain", attack_surface: "remote_external", network_path: "telematics",
    exploit_maturity: "unknown", kev_listed: false,
    source_feeds: ["NVD"],
    sbom_component: "VxWorks", sbom_version: "7 SR0660", sbom_purl: "pkg:generic/vxworks@7.0.660",
    vendor_advisories: [{ vendor: "Wind River", advisory_id: "WR-SA-2026-002" }],
  },
  {
    cve_id: "CVE-2025-99887", published: "2025-10-01", modified: "2026-01-20",
    description: "Authentication bypass in Zephyr RTOS BLE stack allows adjacent attacker to pair with Body Control Module without proper authentication, enabling unauthorized door unlock and HVAC manipulation.",
    cvss_v4_base_score: 6.8, cvss_v4_base_vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:L/SC:N/SI:N/SA:N",
    cwe_ids: ["CWE-287"], affected_product: "Zephyr RTOS 3.5.0",
    cpe_matches: ["cpe:2.3:a:zephyrproject:zephyr:3.5.0:*:*:*:*:*:*:*"],
    ecu_domain: "body", attack_surface: "remote_adjacent", network_path: "wifi_bt",
    exploit_maturity: "functional", kev_listed: false,
    source_feeds: ["NVD", "MITRE"],
    sbom_component: "Zephyr RTOS", sbom_version: "3.5.0", sbom_purl: "pkg:generic/zephyr@3.5.0",
    vendor_advisories: [{ vendor: "Zephyr Project", advisory_id: "ZEPH-SA-2025-019" }],
  },
  {
    cve_id: "CVE-2026-03456", published: "2026-02-18", modified: "2026-03-01",
    description: "Stack-based buffer overflow in OpenSSL 3.2.x DTLS implementation allows remote attacker to execute code on vehicle Gateway ECU via crafted DTLS ClientHello during OTA update negotiation.",
    cvss_v4_base_score: 9.3, cvss_v4_base_vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    cwe_ids: ["CWE-121"], affected_product: "OpenSSL 3.2.1",
    cpe_matches: ["cpe:2.3:a:openssl:openssl:3.2.1:*:*:*:*:*:*:*"],
    ecu_domain: "gateway", attack_surface: "remote_external", network_path: "telematics",
    exploit_maturity: "weaponized", kev_listed: true,
    source_feeds: ["NVD", "MITRE", "CISA_KEV", "ExploitDB"],
    sbom_component: "OpenSSL", sbom_version: "3.2.1", sbom_purl: "pkg:generic/openssl@3.2.1",
    vendor_advisories: [{ vendor: "OpenSSL Project", advisory_id: "OSSL-SA-2026-001" }],
  },
  {
    cve_id: "CVE-2025-55678", published: "2025-07-12", modified: "2025-10-28",
    description: "Race condition in Vector CANalyzer diagnostic tool allows local attacker to inject modified calibration data during ECU flashing session via shared memory corruption.",
    cvss_v4_base_score: 4.2, cvss_v4_base_vector: "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    cwe_ids: ["CWE-362"], affected_product: "Vector CANalyzer 17.0",
    cpe_matches: ["cpe:2.3:a:vector:canalyzer:17.0:*:*:*:*:*:*:*"],
    ecu_domain: "diagnostics", attack_surface: "local", network_path: "diagnostic",
    exploit_maturity: "unknown", kev_listed: false,
    source_feeds: ["NVD"],
    sbom_component: "Vector CANalyzer", sbom_version: "17.0", sbom_purl: "pkg:generic/vector-canalyzer@17.0",
    vendor_advisories: [{ vendor: "Vector Informatik", advisory_id: "VEC-SA-2025-004" }],
  },
  {
    cve_id: "CVE-2026-04789", published: "2026-03-01", modified: "2026-03-05",
    description: "Critical firmware verification bypass in EPS (Electric Power Steering) ECU bootloader allows physical attacker with JTAG access to flash unsigned firmware, potentially disabling steering assist at speed.",
    cvss_v4_base_score: 9.8, cvss_v4_base_vector: "CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    cwe_ids: ["CWE-345"], affected_product: "SteerTech FW 2.1.0",
    cpe_matches: ["cpe:2.3:a:steertech:eps_firmware:2.1.0:*:*:*:*:*:*:*"],
    ecu_domain: "steering", attack_surface: "physical", network_path: "diagnostic",
    exploit_maturity: "poc", kev_listed: false,
    source_feeds: ["NVD", "MITRE"],
    sbom_component: "SteerTech EPS Firmware", sbom_version: "2.1.0", sbom_purl: "pkg:generic/steertech-eps@2.1.0",
    vendor_advisories: [{ vendor: "SteerTech GmbH", advisory_id: "ST-SA-2026-001" }],
  },
  {
    cve_id: "CVE-2025-33221", published: "2025-06-20", modified: "2025-09-15",
    description: "Unprotected UDS (Unified Diagnostic Services) session in Chassis Control ECU allows adjacent attacker on CAN bus to invoke safety-critical diagnostic routines without SecurityAccess authentication.",
    cvss_v4_base_score: 7.5, cvss_v4_base_vector: "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:H/SA:H",
    cwe_ids: ["CWE-862"], affected_product: "ChassisControl FW 3.2",
    cpe_matches: ["cpe:2.3:a:chassiscontrol:firmware:3.2:*:*:*:*:*:*:*"],
    ecu_domain: "chassis", attack_surface: "remote_adjacent", network_path: "ethernet",
    exploit_maturity: "functional", kev_listed: false,
    source_feeds: ["NVD", "MITRE"],
    sbom_component: "ChassisControl Firmware", sbom_version: "3.2", sbom_purl: "pkg:generic/chassiscontrol@3.2",
    vendor_advisories: [],
  },
];

// ── ARS COMPUTATION ENGINE ────────────────────────────────────────

function computeARS(vuln) {
  const base = vuln.cvss_v4_base_score;
  const ecuDomain = ECU_DOMAINS[vuln.ecu_domain];
  const asilMod = ecuDomain ? ecuDomain.modifier : 1.0;
  const reachKey = `${vuln.attack_surface}|${vuln.network_path}`;
  const reachMod = REACHABILITY_MODIFIERS[reachKey] || 1.0;
  const exploitMod = EXPLOIT_MODIFIERS[vuln.exploit_maturity] || 0.90;

  const rawScore = base * asilMod * reachMod * exploitMod;
  const ars = Math.min(10.0, parseFloat(rawScore.toFixed(2)));

  let priority_tier;
  if (vuln.kev_listed) priority_tier = "P0_critical";
  else if (ars >= 9.0) priority_tier = "P0_critical";
  else if (ars >= 7.0) priority_tier = "P1_high";
  else if (ars >= 4.0) priority_tier = "P2_medium";
  else priority_tier = "P3_low";

  const recommended_action = PRIORITY_TIERS[priority_tier].action;

  const justification_trace = [
    `Base severity: CVSS v4.0 base ${base} (${vuln.cvss_v4_base_vector})`,
    `ECU domain: ${ecuDomain?.label || vuln.ecu_domain} — ASIL modifier ×${asilMod}`,
    `Reachability: ${vuln.attack_surface}/${vuln.network_path} — modifier ×${reachMod}`,
    `Exploit maturity: ${vuln.exploit_maturity} — modifier ×${exploitMod}`,
    `Raw computation: ${base} × ${asilMod} × ${reachMod} × ${exploitMod} = ${rawScore.toFixed(3)}`,
    `ARS capped at MIN(10.0, ${rawScore.toFixed(3)}) = ${ars}`,
    vuln.kev_listed ? "KEV listing forces P0_critical priority tier override" : `Priority tier: ${priority_tier} (ARS ${ars})`,
    `Recommended action: ${recommended_action}`,
  ];

  return { ars, priority_tier, recommended_action, justification_trace, raw_score: rawScore, asil_modifier: asilMod, reachability_modifier: reachMod, exploit_modifier: exploitMod };
}

// ── ENRICHED DATA ─────────────────────────────────────────────────
const ENRICHED_DB = CVE_DATABASE.map(v => ({ ...v, ...computeARS(v) }));

// ── STYLES ────────────────────────────────────────────────────────
const fonts = `
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');
`;

// ── COMPONENTS ────────────────────────────────────────────────────

function ARSGauge({ score, size = 80 }) {
  const pct = (score / 10) * 100;
  const circumference = 2 * Math.PI * 34;
  const offset = circumference - (pct / 100) * circumference;
  let color = "#2563EB";
  if (score >= 9) color = "#DC2626";
  else if (score >= 7) color = "#EA580C";
  else if (score >= 4) color = "#D97706";

  return (
    <svg width={size} height={size} viewBox="0 0 80 80">
      <circle cx="40" cy="40" r="34" fill="none" stroke="#1E293B" strokeWidth="6" />
      <circle cx="40" cy="40" r="34" fill="none" stroke={color} strokeWidth="6"
        strokeDasharray={circumference} strokeDashoffset={offset}
        strokeLinecap="round" transform="rotate(-90 40 40)"
        style={{ transition: "stroke-dashoffset 1s ease" }} />
      <text x="40" y="36" textAnchor="middle" fill="#F1F5F9" fontSize="18" fontWeight="700" fontFamily="JetBrains Mono">{score.toFixed(1)}</text>
      <text x="40" y="50" textAnchor="middle" fill="#64748B" fontSize="8" fontWeight="500" fontFamily="DM Sans">ARS</text>
    </svg>
  );
}

function PriorityBadge({ tier }) {
  const info = PRIORITY_TIERS[tier];
  if (!info) return null;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "3px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700,
      fontFamily: "JetBrains Mono", letterSpacing: "0.05em",
      color: info.color, background: `${info.color}18`, border: `1px solid ${info.color}40`,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: info.color, display: "inline-block" }} />
      {info.label}
    </span>
  );
}

function KEVBadge() {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "3px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700,
      fontFamily: "JetBrains Mono", color: "#FEF2F2", background: "#DC2626",
    }}>⚡ KEV LISTED</span>
  );
}

function ECUBadge({ domain }) {
  const info = ECU_DOMAINS[domain];
  if (!info) return <span>{domain}</span>;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 4,
      padding: "3px 10px", borderRadius: 4, fontSize: 11, fontWeight: 600,
      fontFamily: "DM Sans", color: info.color, background: `${info.color}15`, border: `1px solid ${info.color}30`,
    }}>
      <span>{info.icon}</span> {info.label}
    </span>
  );
}

function ASILBadge({ asil }) {
  const colors = {
    ASIL_D: "#DC2626", ASIL_C: "#EA580C", ASIL_B: "#D97706", ASIL_A: "#2563EB", QM: "#6B7280",
  };
  const c = colors[asil] || "#6B7280";
  return (
    <span style={{
      padding: "2px 8px", borderRadius: 3, fontSize: 10, fontWeight: 700,
      fontFamily: "JetBrains Mono", color: c, background: `${c}15`, border: `1px solid ${c}40`,
    }}>{asil?.replace("_", "-")}</span>
  );
}

function SourceBadge({ source }) {
  const colors = { NVD: "#2563EB", MITRE: "#7C3AED", CISA_KEV: "#DC2626", ExploitDB: "#EA580C" };
  const c = colors[source] || "#6B7280";
  return (
    <span style={{
      padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600,
      fontFamily: "JetBrains Mono", color: c, background: `${c}12`, border: `1px solid ${c}25`,
    }}>{source}</span>
  );
}

// ── DETAIL PANEL ──────────────────────────────────────────────────

function VulnDetailPanel({ vuln, onClose }) {
  if (!vuln) return null;
  const ecuInfo = ECU_DOMAINS[vuln.ecu_domain];
  const tierInfo = PRIORITY_TIERS[vuln.priority_tier];

  const avrJson = {
    record_id: `avia-${vuln.cve_id.split("-")[1]}-${vuln.cve_id.split("-")[2]?.slice(0,6)}`,
    cve_id: vuln.cve_id,
    source_feeds: vuln.source_feeds,
    published_date: vuln.published,
    last_modified_date: vuln.modified,
    cvss_v4_base_score: vuln.cvss_v4_base_score,
    cvss_v4_base_vector: vuln.cvss_v4_base_vector,
    exploit_maturity: vuln.exploit_maturity,
    kev_listed: vuln.kev_listed,
    affected_product: vuln.affected_product,
    cpe_matches: vuln.cpe_matches,
    sbom_component_name: vuln.sbom_component,
    sbom_component_version: vuln.sbom_version,
    sbom_component_purl: vuln.sbom_purl,
    ecu_domain: vuln.ecu_domain,
    safety_criticality: ecuInfo?.asil || "QM",
    attack_surface: vuln.attack_surface,
    network_path: vuln.network_path,
    reachability: vuln.attack_surface?.startsWith("remote") ? "reachable" : "limited",
    contextual_risk_score: vuln.ars,
    priority_tier: vuln.priority_tier,
    recommended_action: vuln.recommended_action,
    justification_trace: vuln.justification_trace,
  };

  const [activeTab, setActiveTab] = useState("overview");
  const tabs = [
    { id: "overview", label: "Overview" },
    { id: "ars", label: "ARS Scoring" },
    { id: "avr", label: "AVR Record" },
    { id: "tara", label: "TARA Export" },
  ];

  return (
    <div style={{
      position: "fixed", top: 0, right: 0, bottom: 0, width: "min(680px, 90vw)",
      background: "#0B1120", borderLeft: "1px solid #1E293B", zIndex: 1000,
      display: "flex", flexDirection: "column", boxShadow: "-8px 0 40px rgba(0,0,0,0.5)",
      animation: "slideIn 0.3s ease",
    }}>
      <style>{`@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }`}</style>

      {/* Header */}
      <div style={{ padding: "20px 24px", borderBottom: "1px solid #1E293B", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <ARSGauge score={vuln.ars} size={56} />
          <div>
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 16, fontWeight: 700, color: "#F1F5F9" }}>{vuln.cve_id}</div>
            <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
              <PriorityBadge tier={vuln.priority_tier} />
              {vuln.kev_listed && <KEVBadge />}
            </div>
          </div>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "1px solid #334155", borderRadius: 6, color: "#94A3B8", padding: "6px 10px", cursor: "pointer", fontSize: 14 }}>✕</button>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid #1E293B", padding: "0 24px" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{
            background: "none", border: "none", padding: "10px 16px", cursor: "pointer",
            fontFamily: "DM Sans", fontSize: 13, fontWeight: 600,
            color: activeTab === t.id ? "#60A5FA" : "#64748B",
            borderBottom: activeTab === t.id ? "2px solid #60A5FA" : "2px solid transparent",
          }}>{t.label}</button>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflow: "auto", padding: 24 }}>
        {activeTab === "overview" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <Section title="Description">
              <p style={{ color: "#CBD5E1", fontSize: 13, lineHeight: 1.7, margin: 0 }}>{vuln.description}</p>
            </Section>
            <Section title="ECU Domain & Safety">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <InfoCard label="ECU Domain"><ECUBadge domain={vuln.ecu_domain} /></InfoCard>
                <InfoCard label="Safety Criticality"><ASILBadge asil={ecuInfo?.asil} /></InfoCard>
                <InfoCard label="Attack Surface"><code style={codeStyle}>{vuln.attack_surface}</code></InfoCard>
                <InfoCard label="Network Path"><code style={codeStyle}>{vuln.network_path}</code></InfoCard>
              </div>
            </Section>
            <Section title="Vulnerability Intelligence">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <InfoCard label="CVSS v4.0 Base"><span style={{ fontFamily: "JetBrains Mono", fontWeight: 700, color: "#F1F5F9" }}>{vuln.cvss_v4_base_score}</span></InfoCard>
                <InfoCard label="Exploit Maturity"><code style={codeStyle}>{vuln.exploit_maturity}</code></InfoCard>
                <InfoCard label="CWE">{vuln.cwe_ids?.map(c => <code key={c} style={codeStyle}>{c}</code>)}</InfoCard>
                <InfoCard label="KEV Listed"><span style={{ color: vuln.kev_listed ? "#DC2626" : "#64748B", fontWeight: 600 }}>{vuln.kev_listed ? "YES" : "NO"}</span></InfoCard>
              </div>
            </Section>
            <Section title="Source Feeds">
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {vuln.source_feeds.map(s => <SourceBadge key={s} source={s} />)}
              </div>
            </Section>
            <Section title="SBOM Correlation">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <InfoCard label="Component"><code style={codeStyle}>{vuln.sbom_component}</code></InfoCard>
                <InfoCard label="Version"><code style={codeStyle}>{vuln.sbom_version}</code></InfoCard>
              </div>
              <div style={{ marginTop: 8 }}>
                <InfoCard label="purl"><code style={{ ...codeStyle, fontSize: 10, wordBreak: "break-all" }}>{vuln.sbom_purl}</code></InfoCard>
              </div>
            </Section>
            {vuln.vendor_advisories?.length > 0 && (
              <Section title="Vendor Advisories">
                {vuln.vendor_advisories.map((va, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, padding: "6px 0", borderBottom: "1px solid #1E293B" }}>
                    <span style={{ color: "#94A3B8", fontSize: 12 }}>{va.vendor}</span>
                    <code style={codeStyle}>{va.advisory_id}</code>
                  </div>
                ))}
              </Section>
            )}
            <Section title="Treatment SLA">
              <div style={{ padding: 12, borderRadius: 6, background: `${tierInfo?.color}10`, border: `1px solid ${tierInfo?.color}30` }}>
                <div style={{ fontFamily: "JetBrains Mono", fontSize: 13, fontWeight: 600, color: tierInfo?.color }}>{tierInfo?.sla}</div>
                <div style={{ fontSize: 12, color: "#94A3B8", marginTop: 4 }}>Recommended: <strong style={{ color: "#F1F5F9" }}>{vuln.recommended_action?.toUpperCase()}</strong></div>
              </div>
            </Section>
          </div>
        )}

        {activeTab === "ars" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <Section title="ARS Computation Model">
              <div style={{ padding: 16, borderRadius: 8, background: "#0F172A", border: "1px solid #1E293B", fontFamily: "JetBrains Mono", fontSize: 12 }}>
                <div style={{ color: "#64748B", marginBottom: 8 }}>AUTOMOTIVE RISK SCORE (ARS) FORMULA</div>
                <div style={{ color: "#60A5FA" }}>ARS = MIN(10.0, Base × ASIL_mod × Reach_mod × Exploit_mod)</div>
              </div>
            </Section>
            <Section title="Modifier Breakdown">
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, fontFamily: "DM Sans" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #1E293B" }}>
                    <th style={thStyle}>Factor</th><th style={thStyle}>Value</th><th style={thStyle}>Modifier</th><th style={thStyle}>Running</th>
                  </tr>
                </thead>
                <tbody>
                  <tr style={trStyle}>
                    <td style={tdStyle}>CVSS v4.0 Base</td>
                    <td style={tdStyle}><code style={codeStyle}>{vuln.cvss_v4_base_score}</code></td>
                    <td style={tdStyle}>—</td>
                    <td style={tdStyle}><strong style={{ color: "#F1F5F9" }}>{vuln.cvss_v4_base_score.toFixed(2)}</strong></td>
                  </tr>
                  <tr style={trStyle}>
                    <td style={tdStyle}>ASIL Safety ({ecuInfo?.asil})</td>
                    <td style={tdStyle}>{vuln.ecu_domain}</td>
                    <td style={tdStyle}><code style={codeStyle}>×{vuln.asil_modifier}</code></td>
                    <td style={tdStyle}><strong style={{ color: "#F1F5F9" }}>{(vuln.cvss_v4_base_score * vuln.asil_modifier).toFixed(2)}</strong></td>
                  </tr>
                  <tr style={trStyle}>
                    <td style={tdStyle}>Reachability</td>
                    <td style={tdStyle}>{vuln.attack_surface}/{vuln.network_path}</td>
                    <td style={tdStyle}><code style={codeStyle}>×{vuln.reachability_modifier}</code></td>
                    <td style={tdStyle}><strong style={{ color: "#F1F5F9" }}>{(vuln.cvss_v4_base_score * vuln.asil_modifier * vuln.reachability_modifier).toFixed(2)}</strong></td>
                  </tr>
                  <tr style={trStyle}>
                    <td style={tdStyle}>Exploit Maturity</td>
                    <td style={tdStyle}>{vuln.exploit_maturity}</td>
                    <td style={tdStyle}><code style={codeStyle}>×{vuln.exploit_modifier}</code></td>
                    <td style={tdStyle}><strong style={{ color: "#F1F5F9" }}>{vuln.raw_score.toFixed(2)}</strong></td>
                  </tr>
                  <tr style={{ borderTop: "2px solid #334155" }}>
                    <td colSpan={3} style={{ ...tdStyle, fontWeight: 700, color: "#F1F5F9" }}>Final ARS (capped at 10.0)</td>
                    <td style={tdStyle}>
                      <span style={{ fontFamily: "JetBrains Mono", fontSize: 18, fontWeight: 700, color: PRIORITY_TIERS[vuln.priority_tier]?.color }}>{vuln.ars.toFixed(1)}</span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </Section>
            <Section title="Justification Trace (Audit Trail)">
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {vuln.justification_trace.map((line, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, padding: "6px 10px", borderRadius: 4, background: "#0F172A", fontSize: 11, fontFamily: "JetBrains Mono" }}>
                    <span style={{ color: "#334155", minWidth: 20 }}>{String(i + 1).padStart(2, "0")}</span>
                    <span style={{ color: "#CBD5E1" }}>{line}</span>
                  </div>
                ))}
              </div>
            </Section>
          </div>
        )}

        {activeTab === "avr" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <Section title="Auto-VIA Vulnerability Record (AVR)">
              <p style={{ color: "#64748B", fontSize: 12, margin: "0 0 12px" }}>Full normalized record per Auto-VIA Schema v3.0 — six field groups (A–F)</p>
              <pre style={{
                background: "#0F172A", border: "1px solid #1E293B", borderRadius: 8, padding: 16,
                fontSize: 11, fontFamily: "JetBrains Mono", color: "#CBD5E1", overflow: "auto",
                whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6,
              }}>
                {JSON.stringify(avrJson, null, 2)}
              </pre>
            </Section>
            <button onClick={() => {
              const blob = new Blob([JSON.stringify(avrJson, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a"); a.href = url; a.download = `${vuln.cve_id}_AVR.json`; a.click();
              URL.revokeObjectURL(url);
            }} style={exportBtnStyle}>
              ⬇ Export AVR as JSON
            </button>
          </div>
        )}

        {activeTab === "tara" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <Section title="TARA Asset Register Entry (ISO/SAE 21434 Cl.9)">
              <pre style={{
                background: "#0F172A", border: "1px solid #1E293B", borderRadius: 8, padding: 16,
                fontSize: 11, fontFamily: "JetBrains Mono", color: "#CBD5E1", overflow: "auto",
                whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6,
              }}>
                {JSON.stringify({
                  asset_id: `TARA-ASSET-${vuln.sbom_component?.replace(/\s/g, "_")}-${vuln.ecu_domain}`,
                  asset_name: `${vuln.sbom_component} ${vuln.sbom_version}`,
                  asset_type: "software_component",
                  ecu_domain: vuln.ecu_domain,
                  safety_criticality: ecuInfo?.asil || "QM",
                  affected_cve: vuln.cve_id,
                  cybersecurity_properties: {
                    confidentiality: vuln.ars >= 7 ? "high" : "medium",
                    integrity: vuln.ars >= 7 ? "high" : "medium",
                    availability: vuln.ars >= 7 ? "high" : "medium",
                  },
                  damage_scenario: `Exploitation of ${vuln.sbom_component} ${vuln.sbom_version} in ${ecuInfo?.label} domain via ${vuln.attack_surface} attack surface (${vuln.network_path} path) — ${vuln.description?.slice(0, 150)}...`,
                  ars_score: vuln.ars,
                  priority_tier: vuln.priority_tier,
                  recommended_action: vuln.recommended_action,
                  treatment_sla: tierInfo?.sla,
                  iso_21434_clause: "Cl.15 — Vulnerability Management",
                  generated_at: new Date().toISOString(),
                }, null, 2)}
              </pre>
            </Section>
            <button onClick={() => {
              const taraData = {
                asset_id: `TARA-ASSET-${vuln.sbom_component?.replace(/\s/g, "_")}-${vuln.ecu_domain}`,
                asset_name: `${vuln.sbom_component} ${vuln.sbom_version}`,
                ecu_domain: vuln.ecu_domain, safety_criticality: ecuInfo?.asil,
                affected_cve: vuln.cve_id, ars_score: vuln.ars, priority_tier: vuln.priority_tier,
              };
              const blob = new Blob([JSON.stringify(taraData, null, 2)], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a"); a.href = url; a.download = `TARA_${vuln.cve_id}.json`; a.click();
              URL.revokeObjectURL(url);
            }} style={exportBtnStyle}>
              ⬇ Export TARA Entry
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div>
      <h3 style={{ fontFamily: "DM Sans", fontSize: 13, fontWeight: 700, color: "#94A3B8", letterSpacing: "0.05em", textTransform: "uppercase", margin: "0 0 10px", paddingBottom: 6, borderBottom: "1px solid #1E293B" }}>{title}</h3>
      {children}
    </div>
  );
}

function InfoCard({ label, children }) {
  return (
    <div style={{ padding: "8px 12px", borderRadius: 6, background: "#0F172A", border: "1px solid #1E293B" }}>
      <div style={{ fontSize: 10, color: "#64748B", fontWeight: 600, marginBottom: 4, fontFamily: "DM Sans", textTransform: "uppercase", letterSpacing: "0.04em" }}>{label}</div>
      <div>{children}</div>
    </div>
  );
}

const codeStyle = { fontFamily: "JetBrains Mono", fontSize: 11, color: "#60A5FA", background: "#1E293B", padding: "2px 6px", borderRadius: 3 };
const thStyle = { textAlign: "left", padding: "8px 10px", color: "#64748B", fontWeight: 600, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.04em" };
const tdStyle = { padding: "8px 10px", color: "#94A3B8" };
const trStyle = { borderBottom: "1px solid #1E293B" };
const exportBtnStyle = {
  background: "#1E293B", border: "1px solid #334155", borderRadius: 6,
  color: "#60A5FA", padding: "10px 16px", cursor: "pointer", fontFamily: "JetBrains Mono",
  fontSize: 12, fontWeight: 600, textAlign: "center",
};

// ── CUSTOM CVE INPUT ──────────────────────────────────────────────

function CustomCVEInput({ onCompute }) {
  const [form, setForm] = useState({
    cve_id: "", description: "", cvss_v4_base_score: 7.5,
    ecu_domain: "gateway", attack_surface: "remote_external", network_path: "telematics",
    exploit_maturity: "poc", kev_listed: false, affected_product: "", sbom_component: "", sbom_version: "",
  });

  const update = (k, v) => setForm(p => ({ ...p, [k]: v }));

  const handleSubmit = () => {
    if (!form.cve_id) return;
    const vuln = {
      ...form,
      cvss_v4_base_score: parseFloat(form.cvss_v4_base_score),
      published: new Date().toISOString().split("T")[0],
      modified: new Date().toISOString().split("T")[0],
      cvss_v4_base_vector: "CVSS:4.0/Custom",
      cwe_ids: [], cpe_matches: [], source_feeds: ["Manual"],
      sbom_purl: form.sbom_component ? `pkg:generic/${form.sbom_component.toLowerCase().replace(/\s/g, "-")}@${form.sbom_version}` : "",
      vendor_advisories: [],
    };
    const enriched = { ...vuln, ...computeARS(vuln) };
    onCompute(enriched);
  };

  const inputStyle = {
    background: "#0F172A", border: "1px solid #1E293B", borderRadius: 6, padding: "8px 12px",
    color: "#F1F5F9", fontFamily: "JetBrains Mono", fontSize: 12, outline: "none", width: "100%", boxSizing: "border-box",
  };
  const selectStyle = { ...inputStyle, cursor: "pointer" };
  const labelStyle = { fontSize: 10, color: "#64748B", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4, display: "block", fontFamily: "DM Sans" };

  return (
    <div style={{ padding: 24, background: "#0B1120", borderRadius: 12, border: "1px solid #1E293B" }}>
      <h3 style={{ fontFamily: "DM Sans", fontSize: 15, fontWeight: 700, color: "#F1F5F9", margin: "0 0 16px", display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ width: 28, height: 28, borderRadius: 6, background: "#1E293B", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14 }}>+</span>
        Manual CVE Assessment
      </h3>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        <div><label style={labelStyle}>CVE ID</label><input style={inputStyle} value={form.cve_id} onChange={e => update("cve_id", e.target.value)} placeholder="CVE-2026-XXXXX" /></div>
        <div><label style={labelStyle}>Affected Product</label><input style={inputStyle} value={form.affected_product} onChange={e => update("affected_product", e.target.value)} placeholder="Product name" /></div>
        <div><label style={labelStyle}>CVSS v4.0 Base Score</label><input type="number" step="0.1" min="0" max="10" style={inputStyle} value={form.cvss_v4_base_score} onChange={e => update("cvss_v4_base_score", e.target.value)} /></div>
        <div><label style={labelStyle}>ECU Domain</label>
          <select style={selectStyle} value={form.ecu_domain} onChange={e => update("ecu_domain", e.target.value)}>
            {Object.entries(ECU_DOMAINS).map(([k, v]) => <option key={k} value={k}>{v.icon} {v.label}</option>)}
          </select>
        </div>
        <div><label style={labelStyle}>Attack Surface</label>
          <select style={selectStyle} value={form.attack_surface} onChange={e => update("attack_surface", e.target.value)}>
            {ATTACK_SURFACES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div><label style={labelStyle}>Network Path</label>
          <select style={selectStyle} value={form.network_path} onChange={e => update("network_path", e.target.value)}>
            {NETWORK_PATHS.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div><label style={labelStyle}>Exploit Maturity</label>
          <select style={selectStyle} value={form.exploit_maturity} onChange={e => update("exploit_maturity", e.target.value)}>
            {EXPLOIT_MATURITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div><label style={labelStyle}>KEV Listed</label>
          <select style={selectStyle} value={form.kev_listed} onChange={e => update("kev_listed", e.target.value === "true")}>
            <option value="false">No</option><option value="true">Yes</option>
          </select>
        </div>
        <div><label style={labelStyle}>SBOM Component</label><input style={inputStyle} value={form.sbom_component} onChange={e => update("sbom_component", e.target.value)} placeholder="Component name" /></div>
      </div>
      <div style={{ marginTop: 12 }}>
        <label style={labelStyle}>Description</label>
        <textarea style={{ ...inputStyle, height: 60, resize: "vertical" }} value={form.description} onChange={e => update("description", e.target.value)} placeholder="Vulnerability description..." />
      </div>
      <button onClick={handleSubmit} style={{
        marginTop: 16, width: "100%", padding: "10px 20px", borderRadius: 6,
        background: "linear-gradient(135deg, #2563EB, #7C3AED)", border: "none",
        color: "#fff", fontFamily: "DM Sans", fontSize: 13, fontWeight: 700, cursor: "pointer",
      }}>
        Compute ARS & Generate AVR
      </button>
    </div>
  );
}

// ── DASHBOARD STATS ───────────────────────────────────────────────

function DashboardStats({ vulns }) {
  const p0 = vulns.filter(v => v.priority_tier === "P0_critical").length;
  const p1 = vulns.filter(v => v.priority_tier === "P1_high").length;
  const p2 = vulns.filter(v => v.priority_tier === "P2_medium").length;
  const p3 = vulns.filter(v => v.priority_tier === "P3_low").length;
  const kev = vulns.filter(v => v.kev_listed).length;
  const avgArs = vulns.length ? (vulns.reduce((s, v) => s + v.ars, 0) / vulns.length).toFixed(1) : "0.0";

  const stats = [
    { label: "Total AVRs", value: vulns.length, color: "#60A5FA", icon: "⬡" },
    { label: "P0 Critical", value: p0, color: "#DC2626", icon: "⊘" },
    { label: "P1 High", value: p1, color: "#EA580C", icon: "◈" },
    { label: "P2 Medium", value: p2, color: "#D97706", icon: "▣" },
    { label: "P3 Low", value: p3, color: "#2563EB", icon: "◇" },
    { label: "KEV Listed", value: kev, color: "#DC2626", icon: "⚡" },
    { label: "Avg ARS", value: avgArs, color: "#7C3AED", icon: "◎" },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 10 }}>
      {stats.map(s => (
        <div key={s.label} style={{
          padding: "14px 12px", borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B",
          display: "flex", flexDirection: "column", alignItems: "center", gap: 4,
        }}>
          <span style={{ fontSize: 20, opacity: 0.7 }}>{s.icon}</span>
          <span style={{ fontFamily: "JetBrains Mono", fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</span>
          <span style={{ fontFamily: "DM Sans", fontSize: 10, color: "#64748B", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>{s.label}</span>
        </div>
      ))}
    </div>
  );
}

// ── ECU DOMAIN DISTRIBUTION ───────────────────────────────────────

function ECUDistribution({ vulns }) {
  const domainCounts = {};
  vulns.forEach(v => { domainCounts[v.ecu_domain] = (domainCounts[v.ecu_domain] || 0) + 1; });
  const sorted = Object.entries(domainCounts).sort((a, b) => b[1] - a[1]);
  const max = Math.max(...sorted.map(([, c]) => c), 1);

  return (
    <div style={{ padding: 20, borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B" }}>
      <h3 style={{ fontFamily: "DM Sans", fontSize: 13, fontWeight: 700, color: "#94A3B8", margin: "0 0 14px", textTransform: "uppercase", letterSpacing: "0.05em" }}>ECU Domain Distribution</h3>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {sorted.map(([domain, count]) => {
          const info = ECU_DOMAINS[domain];
          return (
            <div key={domain} style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ minWidth: 130, fontFamily: "DM Sans", fontSize: 11, color: info?.color || "#94A3B8", fontWeight: 600 }}>
                {info?.icon} {info?.label || domain}
              </span>
              <div style={{ flex: 1, height: 18, background: "#1E293B", borderRadius: 4, overflow: "hidden" }}>
                <div style={{
                  height: "100%", width: `${(count / max) * 100}%`,
                  background: `linear-gradient(90deg, ${info?.color}60, ${info?.color}20)`,
                  borderRadius: 4, transition: "width 0.8s ease",
                }} />
              </div>
              <span style={{ minWidth: 24, fontFamily: "JetBrains Mono", fontSize: 12, color: "#F1F5F9", fontWeight: 700, textAlign: "right" }}>{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────────

export default function AutoVIA() {
  const [search, setSearch] = useState("");
  const [filterDomain, setFilterDomain] = useState("all");
  const [filterPriority, setFilterPriority] = useState("all");
  const [filterKEV, setFilterKEV] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [customVulns, setCustomVulns] = useState([]);
  const [view, setView] = useState("dashboard"); // dashboard | search | assess
  const [sortBy, setSortBy] = useState("ars_desc");

  const allVulns = useMemo(() => [...ENRICHED_DB, ...customVulns], [customVulns]);

  const filtered = useMemo(() => {
    let result = allVulns;
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(v =>
        v.cve_id.toLowerCase().includes(q) ||
        v.description.toLowerCase().includes(q) ||
        v.affected_product.toLowerCase().includes(q) ||
        v.sbom_component.toLowerCase().includes(q) ||
        v.ecu_domain.toLowerCase().includes(q) ||
        v.cwe_ids?.some(c => c.toLowerCase().includes(q))
      );
    }
    if (filterDomain !== "all") result = result.filter(v => v.ecu_domain === filterDomain);
    if (filterPriority !== "all") result = result.filter(v => v.priority_tier === filterPriority);
    if (filterKEV) result = result.filter(v => v.kev_listed);

    result.sort((a, b) => {
      switch (sortBy) {
        case "ars_desc": return b.ars - a.ars;
        case "ars_asc": return a.ars - b.ars;
        case "cvss_desc": return b.cvss_v4_base_score - a.cvss_v4_base_score;
        case "date_desc": return new Date(b.published) - new Date(a.published);
        default: return b.ars - a.ars;
      }
    });
    return result;
  }, [allVulns, search, filterDomain, filterPriority, filterKEV, sortBy]);

  const handleCustomCompute = (vuln) => {
    setCustomVulns(prev => [vuln, ...prev]);
    setSelectedVuln(vuln);
    setView("search");
  };

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: "▦" },
    { id: "search", label: "Search & Triage", icon: "⌕" },
    { id: "assess", label: "Manual Assessment", icon: "+" },
  ];

  const selectStyle = {
    background: "#0F172A", border: "1px solid #1E293B", borderRadius: 6, padding: "7px 10px",
    color: "#94A3B8", fontFamily: "DM Sans", fontSize: 12, outline: "none", cursor: "pointer",
  };

  return (
    <div style={{ minHeight: "100vh", background: "#060A14", color: "#F1F5F9", fontFamily: "DM Sans" }}>
      <style>{fonts}</style>
      <style>{`
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0B1120; }
        ::-webkit-scrollbar-thumb { background: #1E293B; border-radius: 3px; }
        ::selection { background: #2563EB40; }
        input:focus, select:focus, textarea:focus { border-color: #2563EB !important; }
        option { background: #0F172A; color: #F1F5F9; }
      `}</style>

      {/* ── HEADER ── */}
      <header style={{
        padding: "0 32px", height: 64, display: "flex", alignItems: "center", justifyContent: "space-between",
        borderBottom: "1px solid #1E293B", background: "#0B1120",
        position: "sticky", top: 0, zIndex: 100, backdropFilter: "blur(12px)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center",
            background: "linear-gradient(135deg, #2563EB, #7C3AED)", fontFamily: "JetBrains Mono", fontWeight: 800, fontSize: 14, color: "#fff",
          }}>AV</div>
          <div>
            <div style={{ fontFamily: "JetBrains Mono", fontWeight: 700, fontSize: 16, color: "#F1F5F9", letterSpacing: "-0.02em" }}>Auto-VIA</div>
            <div style={{ fontFamily: "DM Sans", fontSize: 10, color: "#64748B", letterSpacing: "0.08em", textTransform: "uppercase" }}>Automotive Vulnerability Intelligence Aggregator</div>
          </div>
        </div>

        <nav style={{ display: "flex", gap: 4 }}>
          {navItems.map(item => (
            <button key={item.id} onClick={() => setView(item.id)} style={{
              background: view === item.id ? "#1E293B" : "transparent",
              border: view === item.id ? "1px solid #334155" : "1px solid transparent",
              borderRadius: 6, padding: "7px 14px", cursor: "pointer",
              fontFamily: "DM Sans", fontSize: 12, fontWeight: 600,
              color: view === item.id ? "#60A5FA" : "#64748B",
              display: "flex", alignItems: "center", gap: 6,
            }}>
              <span style={{ fontSize: 14 }}>{item.icon}</span> {item.label}
            </button>
          ))}
        </nav>

        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
            padding: "4px 10px", borderRadius: 20, background: "#05966920", border: "1px solid #05966940",
            fontFamily: "JetBrains Mono", fontSize: 10, color: "#059669", fontWeight: 600,
          }}>● LIVE — Schema v3.0</div>
          <div style={{
            padding: "4px 10px", borderRadius: 20, background: "#1E293B", border: "1px solid #334155",
            fontFamily: "JetBrains Mono", fontSize: 10, color: "#94A3B8",
          }}>ISO/SAE 21434 | UNECE R155</div>
        </div>
      </header>

      {/* ── MAIN CONTENT ── */}
      <main style={{ maxWidth: 1440, margin: "0 auto", padding: "24px 32px" }}>

        {/* ── DASHBOARD VIEW ── */}
        {view === "dashboard" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <DashboardStats vulns={allVulns} />
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <ECUDistribution vulns={allVulns} />
              <div style={{ padding: 20, borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B" }}>
                <h3 style={{ fontFamily: "DM Sans", fontSize: 13, fontWeight: 700, color: "#94A3B8", margin: "0 0 14px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Priority Distribution</h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {Object.entries(PRIORITY_TIERS).map(([tier, info]) => {
                    const count = allVulns.filter(v => v.priority_tier === tier).length;
                    const pct = allVulns.length ? ((count / allVulns.length) * 100).toFixed(0) : 0;
                    return (
                      <div key={tier} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ minWidth: 90 }}><PriorityBadge tier={tier} /></span>
                        <div style={{ flex: 1, height: 22, background: "#1E293B", borderRadius: 4, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${pct}%`, background: `${info.color}50`, borderRadius: 4, transition: "width 0.8s ease", display: "flex", alignItems: "center", justifyContent: "flex-end", paddingRight: 6 }}>
                            <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#F1F5F9", fontWeight: 700 }}>{count}</span>
                          </div>
                        </div>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 11, color: "#64748B", minWidth: 30, textAlign: "right" }}>{pct}%</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Recent Critical */}
            <div style={{ padding: 20, borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B" }}>
              <h3 style={{ fontFamily: "DM Sans", fontSize: 13, fontWeight: 700, color: "#94A3B8", margin: "0 0 14px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Recent Critical & High Findings</h3>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {allVulns.filter(v => v.priority_tier === "P0_critical" || v.priority_tier === "P1_high").slice(0, 6).map(v => (
                  <div key={v.cve_id} onClick={() => { setSelectedVuln(v); }} style={{
                    display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", borderRadius: 6,
                    background: "#0F172A", border: "1px solid #1E293B", cursor: "pointer",
                    transition: "border-color 0.2s",
                  }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = "#334155"}
                    onMouseLeave={e => e.currentTarget.style.borderColor = "#1E293B"}
                  >
                    <ARSGauge score={v.ars} size={40} />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, fontWeight: 700, color: "#F1F5F9" }}>{v.cve_id}</span>
                        <PriorityBadge tier={v.priority_tier} />
                        {v.kev_listed && <KEVBadge />}
                      </div>
                      <div style={{ fontSize: 11, color: "#64748B", marginTop: 2 }}>{v.affected_product} — {v.description?.slice(0, 80)}...</div>
                    </div>
                    <ECUBadge domain={v.ecu_domain} />
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── SEARCH VIEW ── */}
        {view === "search" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {/* Search Bar */}
            <div style={{
              display: "flex", gap: 10, padding: 16, borderRadius: 10,
              background: "#0B1120", border: "1px solid #1E293B",
            }}>
              <div style={{ flex: 1, position: "relative" }}>
                <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: "#64748B", fontSize: 16 }}>⌕</span>
                <input
                  value={search} onChange={e => setSearch(e.target.value)}
                  placeholder="Search CVE ID, product, ECU domain, CWE, description..."
                  style={{
                    width: "100%", background: "#0F172A", border: "1px solid #1E293B", borderRadius: 6,
                    padding: "10px 12px 10px 36px", color: "#F1F5F9", fontFamily: "JetBrains Mono",
                    fontSize: 13, outline: "none",
                  }}
                />
              </div>
              <select value={filterDomain} onChange={e => setFilterDomain(e.target.value)} style={selectStyle}>
                <option value="all">All ECU Domains</option>
                {Object.entries(ECU_DOMAINS).map(([k, v]) => <option key={k} value={k}>{v.icon} {v.label}</option>)}
              </select>
              <select value={filterPriority} onChange={e => setFilterPriority(e.target.value)} style={selectStyle}>
                <option value="all">All Priorities</option>
                {Object.entries(PRIORITY_TIERS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
              <button onClick={() => setFilterKEV(!filterKEV)} style={{
                ...selectStyle, background: filterKEV ? "#DC262620" : "#0F172A",
                border: filterKEV ? "1px solid #DC262660" : "1px solid #1E293B",
                color: filterKEV ? "#DC2626" : "#64748B", fontWeight: 600,
              }}>⚡ KEV</button>
              <select value={sortBy} onChange={e => setSortBy(e.target.value)} style={selectStyle}>
                <option value="ars_desc">ARS ↓</option>
                <option value="ars_asc">ARS ↑</option>
                <option value="cvss_desc">CVSS ↓</option>
                <option value="date_desc">Date ↓</option>
              </select>
            </div>

            <div style={{ fontFamily: "DM Sans", fontSize: 12, color: "#64748B" }}>
              Showing <strong style={{ color: "#F1F5F9" }}>{filtered.length}</strong> of {allVulns.length} automotive-relevant vulnerabilities
            </div>

            {/* Results Table */}
            <div style={{ borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B", overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "#0F172A", borderBottom: "1px solid #1E293B" }}>
                    {["ARS", "CVE ID", "Priority", "ECU Domain", "CVSS", "Exploit", "Product", "KEV", "Date"].map(h => (
                      <th key={h} style={{
                        padding: "10px 12px", textAlign: "left", fontFamily: "DM Sans",
                        fontSize: 10, fontWeight: 700, color: "#64748B", textTransform: "uppercase",
                        letterSpacing: "0.06em",
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(v => (
                    <tr key={v.cve_id} onClick={() => setSelectedVuln(v)} style={{
                      borderBottom: "1px solid #1E293B", cursor: "pointer", transition: "background 0.15s",
                    }}
                      onMouseEnter={e => e.currentTarget.style.background = "#0F172A"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <td style={{ padding: "8px 12px" }}><ARSGauge score={v.ars} size={44} /></td>
                      <td style={{ padding: "8px 12px", fontFamily: "JetBrains Mono", fontSize: 12, fontWeight: 700, color: "#F1F5F9" }}>{v.cve_id}</td>
                      <td style={{ padding: "8px 12px" }}><PriorityBadge tier={v.priority_tier} /></td>
                      <td style={{ padding: "8px 12px" }}><ECUBadge domain={v.ecu_domain} /></td>
                      <td style={{ padding: "8px 12px", fontFamily: "JetBrains Mono", fontSize: 12, color: "#94A3B8" }}>{v.cvss_v4_base_score}</td>
                      <td style={{ padding: "8px 12px" }}><code style={{ ...codeStyle, fontSize: 10 }}>{v.exploit_maturity}</code></td>
                      <td style={{ padding: "8px 12px", fontSize: 11, color: "#94A3B8", maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.affected_product}</td>
                      <td style={{ padding: "8px 12px" }}>{v.kev_listed ? <KEVBadge /> : <span style={{ color: "#334155", fontSize: 11 }}>—</span>}</td>
                      <td style={{ padding: "8px 12px", fontFamily: "JetBrains Mono", fontSize: 10, color: "#64748B" }}>{v.published}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filtered.length === 0 && (
                <div style={{ padding: 40, textAlign: "center", color: "#64748B", fontFamily: "DM Sans" }}>
                  <div style={{ fontSize: 32, marginBottom: 8, opacity: 0.3 }}>⌕</div>
                  <div>No vulnerabilities match your search criteria</div>
                </div>
              )}
            </div>

            {/* Bulk Export */}
            <div style={{ display: "flex", gap: 10 }}>
              <button onClick={() => {
                const exportData = filtered.map(v => ({
                  cve_id: v.cve_id, ars: v.ars, priority_tier: v.priority_tier,
                  ecu_domain: v.ecu_domain, cvss_v4: v.cvss_v4_base_score,
                  exploit_maturity: v.exploit_maturity, kev_listed: v.kev_listed,
                  recommended_action: v.recommended_action, affected_product: v.affected_product,
                }));
                const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a"); a.href = url; a.download = "AutoVIA_Export.json"; a.click();
                URL.revokeObjectURL(url);
              }} style={exportBtnStyle}>⬇ Export Filtered Results (JSON)</button>
              <button onClick={() => {
                const csv = ["CVE_ID,ARS,Priority,ECU_Domain,CVSS_v4,Exploit_Maturity,KEV,Action,Product",
                  ...filtered.map(v => `${v.cve_id},${v.ars},${v.priority_tier},${v.ecu_domain},${v.cvss_v4_base_score},${v.exploit_maturity},${v.kev_listed},${v.recommended_action},"${v.affected_product}"`)
                ].join("\n");
                const blob = new Blob([csv], { type: "text/csv" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a"); a.href = url; a.download = "AutoVIA_Export.csv"; a.click();
                URL.revokeObjectURL(url);
              }} style={exportBtnStyle}>⬇ Export as CSV</button>
            </div>
          </div>
        )}

        {/* ── MANUAL ASSESSMENT VIEW ── */}
        {view === "assess" && (
          <div style={{ maxWidth: 900, margin: "0 auto" }}>
            <CustomCVEInput onCompute={handleCustomCompute} />
          </div>
        )}
      </main>

      {/* ── DETAIL PANEL OVERLAY ── */}
      {selectedVuln && (
        <>
          <div onClick={() => setSelectedVuln(null)} style={{
            position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
            background: "rgba(0,0,0,0.6)", zIndex: 999,
          }} />
          <VulnDetailPanel vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />
        </>
      )}

      {/* ── FOOTER ── */}
      <footer style={{
        padding: "16px 32px", borderTop: "1px solid #1E293B", background: "#0B1120",
        display: "flex", justifyContent: "space-between", alignItems: "center",
      }}>
        <span style={{ fontFamily: "DM Sans", fontSize: 11, color: "#475569" }}>
          Auto-VIA v2.5 — Open-Source Automotive Vulnerability Intelligence Aggregator
        </span>
        <div style={{ display: "flex", gap: 12 }}>
          {["ISO/SAE 21434 Cl.15", "UNECE WP.29 R155", "CVSS v4.0", "STIX 2.1"].map(s => (
            <span key={s} style={{
              padding: "3px 8px", borderRadius: 4, background: "#1E293B", border: "1px solid #334155",
              fontFamily: "JetBrains Mono", fontSize: 9, color: "#64748B",
            }}>{s}</span>
          ))}
        </div>
      </footer>
    </div>
  );
}
