import { useState, useEffect, useRef, useCallback, useMemo } from "react";

// ═══════════════════════════════════════════════════════════════════
// AUTO-VIA: Automotive Vulnerability Intelligence Aggregator
// LIVE EDITION — NVD API + CISA KEV + Automotive Relevance Classifier
// ═══════════════════════════════════════════════════════════════════

// ── NVD API CONFIGURATION ─────────────────────────────────────────
const NVD_API_KEY = import.meta.env.VITE_NVD_API_KEY || "";
const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

// ── CONSTANTS & TAXONOMY ──────────────────────────────────────────

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

const REACHABILITY_MODIFIERS = {
  "remote_external|telematics": 1.25, "remote_external|wifi_bt": 1.18,
  "remote_adjacent|wifi_bt": 1.15, "remote_adjacent|ethernet": 1.12,
  "local|can": 1.05, "local|diagnostic": 1.05,
  "physical|diagnostic": 1.00, "physical|can": 0.95,
};

const EXPLOIT_MODIFIERS = {
  active_exploitation: 1.40, weaponized: 1.30, functional: 1.15, poc: 1.10, unknown: 0.90,
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

// ═══════════════════════════════════════════════════════════════════
// STAGE 1: CPE-TO-ECU RULE FILTER (Auto-VIA Automotive Relevance Classifier)
// Per Technical Architecture §5.2 — Three-Stage Classification Pipeline
// ═══════════════════════════════════════════════════════════════════

const CPE_TO_ECU_RULES = [
  // RTOS / Safety-Critical OS
  { pattern: /blackberry.*qnx|qnx.*neutrino/i, domains: ["adas", "gateway", "infotainment"], primaryDomain: "adas" },
  { pattern: /wind_river.*vxworks|vxworks/i, domains: ["adas", "powertrain", "chassis"], primaryDomain: "powertrain" },
  { pattern: /autosar/i, domains: ["powertrain", "chassis", "adas", "braking"], primaryDomain: "powertrain" },
  { pattern: /green_hills.*integrity|integrity.*rtos/i, domains: ["adas", "braking", "steering"], primaryDomain: "adas" },
  { pattern: /freertos|free_rtos/i, domains: ["body", "telematics", "gateway"], primaryDomain: "gateway" },
  { pattern: /zephyr/i, domains: ["body", "telematics", "diagnostics"], primaryDomain: "body" },
  { pattern: /threadx|azure.*rtos/i, domains: ["telematics", "body", "gateway"], primaryDomain: "telematics" },
  { pattern: /riot.*os|riot-os/i, domains: ["body", "diagnostics"], primaryDomain: "body" },
  { pattern: /nucleus.*rtos/i, domains: ["telematics", "gateway"], primaryDomain: "telematics" },

  // Infotainment / IVI
  { pattern: /android.*auto|google.*android.*automotive/i, domains: ["infotainment"], primaryDomain: "infotainment" },
  { pattern: /apple.*carplay/i, domains: ["infotainment"], primaryDomain: "infotainment" },
  { pattern: /genivi|automotive_grade_linux|agl/i, domains: ["infotainment", "gateway"], primaryDomain: "infotainment" },

  // Connectivity / TLS / Crypto
  { pattern: /openssl/i, domains: ["gateway", "telematics", "infotainment"], primaryDomain: "gateway" },
  { pattern: /wolfssl|wolf_ssl/i, domains: ["telematics", "adas", "gateway"], primaryDomain: "telematics" },
  { pattern: /mbedtls|mbed_tls|arm.*mbed/i, domains: ["telematics", "gateway", "body"], primaryDomain: "telematics" },
  { pattern: /boringssl/i, domains: ["infotainment", "telematics"], primaryDomain: "infotainment" },
  { pattern: /libressl/i, domains: ["gateway", "telematics"], primaryDomain: "gateway" },
  { pattern: /gnutls/i, domains: ["infotainment", "gateway"], primaryDomain: "gateway" },

  // Linux Kernel (automotive context)
  { pattern: /linux.*kernel|linux_kernel/i, domains: ["infotainment", "gateway", "telematics"], primaryDomain: "gateway" },

  // Communication Protocols
  { pattern: /can.*bus|socketcan|can_utils|j1939/i, domains: ["gateway", "powertrain", "chassis"], primaryDomain: "gateway" },
  { pattern: /flexray/i, domains: ["chassis", "braking", "steering"], primaryDomain: "chassis" },
  { pattern: /lin_bus|lin.*protocol/i, domains: ["body", "chassis"], primaryDomain: "body" },
  { pattern: /ethernet.*automotive|broadr.*reach|100base.*t1/i, domains: ["adas", "gateway"], primaryDomain: "gateway" },
  { pattern: /doip|diagnostics.*over.*ip/i, domains: ["diagnostics", "gateway"], primaryDomain: "diagnostics" },
  { pattern: /uds|unified.*diagnostic/i, domains: ["diagnostics", "gateway"], primaryDomain: "diagnostics" },
  { pattern: /some.*ip|someip/i, domains: ["adas", "gateway"], primaryDomain: "adas" },
  { pattern: /obd|on.*board.*diagnostic/i, domains: ["diagnostics"], primaryDomain: "diagnostics" },

  // Bluetooth / Wi-Fi
  { pattern: /bluetooth|ble|bluez/i, domains: ["infotainment", "telematics", "body"], primaryDomain: "infotainment" },
  { pattern: /wifi|wi-fi|wpa_supplicant|hostapd/i, domains: ["infotainment", "telematics"], primaryDomain: "infotainment" },

  // V2X / Connectivity
  { pattern: /v2x|dsrc|c-v2x|wave.*1609/i, domains: ["telematics", "adas"], primaryDomain: "telematics" },
  { pattern: /5g.*nr|cellular.*modem|qualcomm.*mdm|sierra.*wireless/i, domains: ["telematics"], primaryDomain: "telematics" },
  { pattern: /gnss|gps.*receiver/i, domains: ["telematics", "adas"], primaryDomain: "telematics" },
  { pattern: /ota|over.*the.*air.*update/i, domains: ["telematics", "gateway"], primaryDomain: "telematics" },

  // Diagnostic / Engineering Tools
  { pattern: /vector.*can|canalyzer|canoe|candb/i, domains: ["diagnostics"], primaryDomain: "diagnostics" },
  { pattern: /etas.*inca|inca/i, domains: ["diagnostics"], primaryDomain: "diagnostics" },
  { pattern: /dspace|dspace/i, domains: ["diagnostics", "adas"], primaryDomain: "diagnostics" },

  // ADAS-specific
  { pattern: /lidar|velodyne|luminar|innoviz/i, domains: ["adas"], primaryDomain: "adas" },
  { pattern: /radar.*ecu|continental.*radar|bosch.*radar/i, domains: ["adas"], primaryDomain: "adas" },
  { pattern: /mobileye|nvidia.*drive|nvidia.*orin|nvidia.*xavier/i, domains: ["adas"], primaryDomain: "adas" },
  { pattern: /ros2|robot.*operating.*system/i, domains: ["adas"], primaryDomain: "adas" },
  { pattern: /tensorflow|pytorch|onnx.*runtime/i, domains: ["adas"], primaryDomain: "adas" },
  { pattern: /opencv/i, domains: ["adas", "infotainment"], primaryDomain: "adas" },

  // Automotive vendors
  { pattern: /bosch/i, domains: ["braking", "powertrain", "adas"], primaryDomain: "braking" },
  { pattern: /continental/i, domains: ["braking", "chassis", "adas"], primaryDomain: "chassis" },
  { pattern: /denso/i, domains: ["powertrain", "adas", "telematics"], primaryDomain: "powertrain" },
  { pattern: /aptiv|delphi/i, domains: ["adas", "gateway"], primaryDomain: "adas" },
  { pattern: /harman|samsung.*harman/i, domains: ["infotainment"], primaryDomain: "infotainment" },
  { pattern: /nxp|nxp_semiconductors/i, domains: ["gateway", "adas", "body"], primaryDomain: "gateway" },
  { pattern: /infineon/i, domains: ["powertrain", "braking", "steering"], primaryDomain: "powertrain" },
  { pattern: /renesas/i, domains: ["powertrain", "chassis", "adas"], primaryDomain: "powertrain" },
  { pattern: /texas_instruments|ti\.com/i, domains: ["adas", "body", "gateway"], primaryDomain: "gateway" },
  { pattern: /microchip|atmel/i, domains: ["body", "diagnostics"], primaryDomain: "body" },

  // Safety-critical
  { pattern: /brake|braking|abs|esc|electronic.*stability/i, domains: ["braking"], primaryDomain: "braking" },
  { pattern: /steering|eps|electric.*power.*steer/i, domains: ["steering"], primaryDomain: "steering" },
  { pattern: /airbag|srs|supplemental.*restraint/i, domains: ["chassis"], primaryDomain: "chassis" },
  { pattern: /engine.*control|ecu.*engine|ecm|tcm.*transmission/i, domains: ["powertrain"], primaryDomain: "powertrain" },
  { pattern: /battery.*management|bms|ev.*battery/i, domains: ["powertrain"], primaryDomain: "powertrain" },
  { pattern: /hvac|door.*lock|passive.*entry|keyless/i, domains: ["body"], primaryDomain: "body" },
  { pattern: /gateway.*ecu|central.*gateway|vehicle.*gateway/i, domains: ["gateway"], primaryDomain: "gateway" },
  { pattern: /tcu|telematics.*control/i, domains: ["telematics"], primaryDomain: "telematics" },
  { pattern: /head.*unit|infotainment|ivi|in.*vehicle/i, domains: ["infotainment"], primaryDomain: "infotainment" },
];

// ═══════════════════════════════════════════════════════════════════
// STAGE 2: KEYWORD & PATTERN MATCHING (Relevance Score 0.0–1.0)
// Per Technical Architecture §5.2 — Stage 2
// ═══════════════════════════════════════════════════════════════════

const AUTOMOTIVE_KEYWORDS = {
  // High-relevance keywords (0.3 each, max contribution 0.6)
  high: [
    "ecu", "vehicle", "automotive", "car", "autosar", "can bus", "can-bus", "canbus",
    "obd-ii", "obd2", "j1939", "uds", "unified diagnostic", "doip", "flexray",
    "lin bus", "v2x", "adas", "lidar", "radar", "autonomous driving",
    "telematics", "infotainment", "ivi", "head unit", "tcell", "tcu",
    "powertrain", "braking system", "steering system", "chassis",
    "electric vehicle", "ev charging", "battery management", "bms",
    "ota update", "over-the-air", "connected vehicle", "connected car",
    "vehicle-to", "dsrc", "c-v2x", "gnss", "iso 26262", "asil",
    "iso 21434", "unece", "r155", "r156", "cybersecurity management system",
    "csms", "type approval", "homologation", "vsoc", "vehicle soc",
    "fleet management", "vehicle fleet", "ecall", "tire pressure",
    "tpms", "abs", "esc", "eps", "srs", "airbag",
  ],
  // Medium-relevance keywords (0.15 each, max contribution 0.3)
  medium: [
    "rtos", "real-time operating system", "vxworks", "qnx", "integrity",
    "freertos", "zephyr", "embedded", "firmware", "bootloader",
    "can", "spi", "i2c", "uart", "jtag", "swd",
    "openssl", "wolfssl", "mbedtls", "tls", "dtls",
    "bluetooth", "ble", "wifi", "wi-fi", "nfc", "uwb",
    "5g", "lte", "cellular", "modem", "gps",
    "sensor", "camera", "accelerometer", "gyroscope",
    "gateway", "firewall", "ids", "intrusion detection",
    "calibration", "flashing", "diagnostic",
    "safety-critical", "safety critical", "functional safety",
    "misra", "cert-c", "secure boot", "secure update",
    "hsm", "hardware security module", "tpm", "trusted platform",
    "sbom", "software bill of materials", "supply chain",
    "mqtt", "dds", "some/ip", "someip",
    "ethernet", "100base-t1", "1000base-t1",
  ],
  // Low-relevance keywords (0.08 each, max contribution 0.16)
  low: [
    "embedded system", "microcontroller", "mcu", "soc", "system on chip",
    "arm", "cortex", "risc-v", "powerpc",
    "flash memory", "nvram", "eeprom",
    "usb", "serial", "rs-232",
    "linux", "android", "windows ce",
    "real-time", "deterministic", "low-latency",
    "cryptograph", "cipher", "certificate", "x.509", "pki",
    "denial of service", "buffer overflow", "code execution",
    "privilege escalation", "authentication bypass",
    "injection", "memory corruption", "use after free",
    "stack overflow", "heap overflow", "integer overflow",
    "race condition", "format string",
  ],
};

function computeAutomotiveRelevanceScore(description, cpeStrings) {
  if (!description) return 0;
  const text = (description + " " + (cpeStrings || []).join(" ")).toLowerCase();
  let score = 0;
  let highCount = 0, medCount = 0, lowCount = 0;

  for (const kw of AUTOMOTIVE_KEYWORDS.high) {
    if (text.includes(kw.toLowerCase())) { highCount++; }
  }
  for (const kw of AUTOMOTIVE_KEYWORDS.medium) {
    if (text.includes(kw.toLowerCase())) { medCount++; }
  }
  for (const kw of AUTOMOTIVE_KEYWORDS.low) {
    if (text.includes(kw.toLowerCase())) { lowCount++; }
  }

  score += Math.min(highCount * 0.3, 0.6);
  score += Math.min(medCount * 0.15, 0.3);
  score += Math.min(lowCount * 0.08, 0.16);

  return Math.min(score, 1.0);
}

function classifyCVEtoDomain(description, cpeStrings) {
  const text = (description + " " + (cpeStrings || []).join(" "));
  for (const rule of CPE_TO_ECU_RULES) {
    if (rule.pattern.test(text)) {
      return { domain: rule.primaryDomain, allDomains: rule.domains, method: "cpe_taxonomy_rule" };
    }
  }
  return { domain: "gateway", allDomains: ["gateway"], method: "heuristic_default" };
}

function inferAttackSurface(cvssVector, description) {
  const desc = (description || "").toLowerCase();
  let surface = "local";
  let path = "unknown";

  if (cvssVector) {
    if (cvssVector.includes("AV:N")) surface = "remote_external";
    else if (cvssVector.includes("AV:A")) surface = "remote_adjacent";
    else if (cvssVector.includes("AV:L")) surface = "local";
    else if (cvssVector.includes("AV:P")) surface = "physical";
  }

  // Infer network path from description
  if (desc.match(/cellular|ota|over.the.air|cloud|remote.*server|telematics|5g|lte|v2x/)) path = "telematics";
  else if (desc.match(/bluetooth|ble|wifi|wi-fi|wireless|nfc|uwb|dsrc/)) path = "wifi_bt";
  else if (desc.match(/ethernet|100base|1000base|tcp.*ip|ip.*network|some.ip/)) path = "ethernet";
  else if (desc.match(/can|can.bus|j1939|obd|lin.bus|flexray/)) path = "can";
  else if (desc.match(/diagnostic|uds|doip|obd-ii|jtag|debug|serial|usb/)) path = "diagnostic";
  else if (surface === "remote_external") path = "telematics";
  else if (surface === "remote_adjacent") path = "wifi_bt";
  else if (surface === "physical") path = "diagnostic";
  else path = "can";

  return { surface, path };
}

function inferExploitMaturity(cvssData) {
  // Check for exploit code maturity in CVSS metrics
  if (cvssData?.exploitCodeMaturity === "HIGH" || cvssData?.exploitCodeMaturity === "FUNCTIONAL") return "functional";
  if (cvssData?.exploitCodeMaturity === "PROOF_OF_CONCEPT") return "poc";
  return "unknown";
}

// ═══════════════════════════════════════════════════════════════════
// ARS COMPUTATION ENGINE (Per Schema Spec §3.1)
// ═══════════════════════════════════════════════════════════════════

function computeARS(vuln) {
  const base = vuln.cvss_v4_base_score || vuln.cvss_v3_base_score || 0;
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
    `Base severity: CVSS base ${base} (${vuln.cvss_vector || "N/A"})`,
    `ECU domain: ${ecuDomain?.label || vuln.ecu_domain} — ASIL modifier ×${asilMod}`,
    `Reachability: ${vuln.attack_surface}/${vuln.network_path} — modifier ×${reachMod}`,
    `Exploit maturity: ${vuln.exploit_maturity} — modifier ×${exploitMod}`,
    `Raw computation: ${base} × ${asilMod} × ${reachMod} × ${exploitMod} = ${rawScore.toFixed(3)}`,
    `ARS capped at MIN(10.0, ${rawScore.toFixed(3)}) = ${ars}`,
    vuln.kev_listed ? "KEV listing forces P0_critical priority tier override" : `Priority tier: ${priority_tier} (ARS ${ars})`,
    `Recommended action: ${recommended_action}`,
    `Automotive relevance score: ${(vuln.relevance_score || 0).toFixed(2)}`,
    `Classification method: ${vuln.classification_method || "N/A"}`,
  ];

  return { ars, priority_tier, recommended_action, justification_trace, raw_score: rawScore, asil_modifier: asilMod, reachability_modifier: reachMod, exploit_modifier: exploitMod };
}

// ═══════════════════════════════════════════════════════════════════
// NVD API PARSER — Transform NVD JSON to Auto-VIA AVR
// ═══════════════════════════════════════════════════════════════════

function parseNVDtoAVR(nvdItem, kevSet) {
  const cve = nvdItem.cve;
  const cveId = cve.id;
  const description = cve.descriptions?.find(d => d.lang === "en")?.value || "";
  const published = cve.published?.split("T")[0] || "";
  const modified = cve.lastModified?.split("T")[0] || "";

  // Extract CVSS scores
  let cvss_v4_base_score = 0, cvss_v3_base_score = 0, cvss_vector = "";
  let cvssData = {};
  const metrics = cve.metrics || {};

  if (metrics.cvssMetricV40?.length) {
    const m = metrics.cvssMetricV40[0].cvssData;
    cvss_v4_base_score = m.baseScore || 0;
    cvss_vector = m.vectorString || "";
    cvssData = m;
  }
  if (metrics.cvssMetricV31?.length) {
    const m = metrics.cvssMetricV31[0].cvssData;
    cvss_v3_base_score = m.baseScore || 0;
    if (!cvss_vector) cvss_vector = m.vectorString || "";
    if (!cvssData.attackVector) cvssData = m;
  }
  if (metrics.cvssMetricV30?.length) {
    const m = metrics.cvssMetricV30[0].cvssData;
    if (!cvss_v3_base_score) cvss_v3_base_score = m.baseScore || 0;
    if (!cvss_vector) cvss_vector = m.vectorString || "";
    if (!cvssData.attackVector) cvssData = m;
  }
  if (metrics.cvssMetricV2?.length && !cvss_v3_base_score) {
    const m = metrics.cvssMetricV2[0].cvssData;
    cvss_v3_base_score = m.baseScore || 0;
    if (!cvss_vector) cvss_vector = m.vectorString || "";
  }

  const baseScore = cvss_v4_base_score || cvss_v3_base_score;
  if (baseScore === 0) return null; // Skip CVEs without scores

  // Extract CPE strings
  const cpeStrings = [];
  const configs = cve.configurations || [];
  configs.forEach(cfg => {
    (cfg.nodes || []).forEach(node => {
      (node.cpeMatch || []).forEach(match => {
        if (match.criteria) cpeStrings.push(match.criteria);
      });
    });
  });

  // Extract CWE IDs
  const cweIds = [];
  (cve.weaknesses || []).forEach(w => {
    (w.description || []).forEach(d => {
      if (d.value && d.value !== "NVD-CWE-Other" && d.value !== "NVD-CWE-noinfo") {
        cweIds.push(d.value);
      }
    });
  });

  // Stage 1 & 2: Automotive Relevance Classification
  const relevanceScore = computeAutomotiveRelevanceScore(description, cpeStrings);
  const classification = classifyCVEtoDomain(description, cpeStrings);
  const { surface, path } = inferAttackSurface(cvss_vector, description);
  const exploitMaturity = inferExploitMaturity(cvssData);
  const isKEV = kevSet.has(cveId);

  // Extract affected product from CPE or description
  let affectedProduct = "";
  if (cpeStrings.length > 0) {
    const parts = cpeStrings[0].split(":");
    if (parts.length >= 5) affectedProduct = `${parts[3]}:${parts[4]}${parts[5] && parts[5] !== "*" ? ":" + parts[5] : ""}`;
  }
  if (!affectedProduct) {
    const match = description.match(/(?:in|of|for|affecting)\s+([A-Z][\w\s.-]+?)(?:\s+(?:before|prior|through|allows|could|may|is|has|via|version))/i);
    affectedProduct = match ? match[1].trim() : cveId;
  }

  // Source feeds
  const sourceFeed = ["NVD"];
  if (isKEV) sourceFeed.push("CISA_KEV");

  const vuln = {
    cve_id: cveId, published, modified, description,
    cvss_v4_base_score, cvss_v3_base_score,
    cvss_v4_base_score: baseScore,
    cvss_vector,
    cwe_ids: cweIds,
    cpe_matches: cpeStrings,
    affected_product: affectedProduct,
    ecu_domain: classification.domain,
    all_ecu_domains: classification.allDomains,
    classification_method: classification.method,
    attack_surface: surface,
    network_path: path,
    exploit_maturity: isKEV ? "active_exploitation" : exploitMaturity,
    kev_listed: isKEV,
    source_feeds: sourceFeed,
    relevance_score: relevanceScore,
    sbom_component: affectedProduct.split(":")[0] || "",
    sbom_version: affectedProduct.split(":")[1] || "",
    sbom_purl: "",
    vendor_advisories: [],
  };

  return { ...vuln, ...computeARS(vuln) };
}

// ═══════════════════════════════════════════════════════════════════
// AUTOMOTIVE SEARCH KEYWORDS FOR NVD QUERIES
// ═══════════════════════════════════════════════════════════════════

const AUTOMOTIVE_NVD_SEARCHES = [
  // Core automotive RTOS / OS
  { keyword: "qnx", label: "QNX Neutrino RTOS" },
  { keyword: "vxworks", label: "VxWorks RTOS" },
  { keyword: "autosar", label: "AUTOSAR Platform" },
  { keyword: "android automotive", label: "Android Automotive" },
  { keyword: "freertos", label: "FreeRTOS" },
  { keyword: "zephyr rtos", label: "Zephyr RTOS" },
  // TLS / Crypto libraries
  { keyword: "openssl", label: "OpenSSL" },
  { keyword: "wolfssl", label: "WolfSSL" },
  { keyword: "mbedtls", label: "mbed TLS" },
  // Communication protocols
  { keyword: "can bus", label: "CAN Bus" },
  { keyword: "bluetooth automotive", label: "Automotive Bluetooth" },
  // Automotive suppliers
  { keyword: "bosch automotive", label: "Bosch Automotive" },
  { keyword: "continental automotive", label: "Continental" },
  { keyword: "denso", label: "Denso" },
  { keyword: "harman", label: "Harman" },
  // ADAS / Autonomous
  { keyword: "nvidia drive", label: "NVIDIA DRIVE" },
  { keyword: "mobileye", label: "Mobileye" },
  // Linux kernel (automotive context)
  { keyword: "linux kernel can", label: "Linux CAN Subsystem" },
  { keyword: "linux kernel bluetooth", label: "Linux BT Subsystem" },
  // Connectivity
  { keyword: "telematics", label: "Telematics" },
  { keyword: "vehicle gateway", label: "Vehicle Gateway" },
  // NXP / Semiconductors
  { keyword: "nxp", label: "NXP Semiconductors" },
  { keyword: "infineon", label: "Infineon" },
  { keyword: "renesas", label: "Renesas" },
];

// ═══════════════════════════════════════════════════════════════════
// UI COMPONENTS
// ═══════════════════════════════════════════════════════════════════

const fonts = `@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');`;

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
  const info = PRIORITY_TIERS[tier]; if (!info) return null;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "3px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700, fontFamily: "JetBrains Mono", letterSpacing: "0.05em", color: info.color, background: `${info.color}18`, border: `1px solid ${info.color}40` }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: info.color, display: "inline-block" }} />{info.label}
    </span>
  );
}

function KEVBadge() {
  return <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "3px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, fontFamily: "JetBrains Mono", color: "#FEF2F2", background: "#DC2626" }}>⚡ KEV</span>;
}

function ECUBadge({ domain }) {
  const info = ECU_DOMAINS[domain]; if (!info) return <span>{domain}</span>;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, padding: "3px 10px", borderRadius: 4, fontSize: 11, fontWeight: 600, fontFamily: "DM Sans", color: info.color, background: `${info.color}15`, border: `1px solid ${info.color}30` }}>
      <span>{info.icon}</span> {info.label}
    </span>
  );
}

function ASILBadge({ asil }) {
  const colors = { ASIL_D: "#DC2626", ASIL_C: "#EA580C", ASIL_B: "#D97706", ASIL_A: "#2563EB", QM: "#6B7280" };
  const c = colors[asil] || "#6B7280";
  return <span style={{ padding: "2px 8px", borderRadius: 3, fontSize: 10, fontWeight: 700, fontFamily: "JetBrains Mono", color: c, background: `${c}15`, border: `1px solid ${c}40` }}>{asil?.replace("_", "-")}</span>;
}

function SourceBadge({ source }) {
  const colors = { NVD: "#2563EB", MITRE: "#7C3AED", CISA_KEV: "#DC2626", ExploitDB: "#EA580C", Manual: "#059669" };
  const c = colors[source] || "#6B7280";
  return <span style={{ padding: "1px 6px", borderRadius: 3, fontSize: 9, fontWeight: 600, fontFamily: "JetBrains Mono", color: c, background: `${c}12`, border: `1px solid ${c}25` }}>{source}</span>;
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
const exportBtnStyle = { background: "#1E293B", border: "1px solid #334155", borderRadius: 6, color: "#60A5FA", padding: "10px 16px", cursor: "pointer", fontFamily: "JetBrains Mono", fontSize: 12, fontWeight: 600, textAlign: "center" };

// ── DETAIL PANEL ──────────────────────────────────────────────────

function VulnDetailPanel({ vuln, onClose }) {
  if (!vuln) return null;
  const ecuInfo = ECU_DOMAINS[vuln.ecu_domain];
  const tierInfo = PRIORITY_TIERS[vuln.priority_tier];
  const [activeTab, setActiveTab] = useState("overview");
  const tabs = [{ id: "overview", label: "Overview" }, { id: "ars", label: "ARS Scoring" }, { id: "avr", label: "AVR Record" }, { id: "tara", label: "TARA Export" }];

  const avrJson = {
    record_id: `avia-${vuln.cve_id.replace("CVE-", "").replace("-", "-")}`,
    cve_id: vuln.cve_id, source_feeds: vuln.source_feeds,
    published_date: vuln.published, last_modified_date: vuln.modified,
    cvss_v4_base_score: vuln.cvss_v4_base_score,
    cvss_vector: vuln.cvss_vector,
    exploit_maturity: vuln.exploit_maturity, kev_listed: vuln.kev_listed,
    affected_product: vuln.affected_product, cpe_matches: vuln.cpe_matches?.slice(0, 3),
    ecu_domain: vuln.ecu_domain, safety_criticality: ecuInfo?.asil || "QM",
    attack_surface: vuln.attack_surface, network_path: vuln.network_path,
    reachability: vuln.attack_surface?.startsWith("remote") ? "reachable" : "limited",
    contextual_risk_score: vuln.ars, priority_tier: vuln.priority_tier,
    recommended_action: vuln.recommended_action,
    automotive_relevance_score: vuln.relevance_score?.toFixed(2),
    classification_method: vuln.classification_method,
    justification_trace: vuln.justification_trace,
  };

  return (
    <div style={{ position: "fixed", top: 0, right: 0, bottom: 0, width: "min(700px, 92vw)", background: "#0B1120", borderLeft: "1px solid #1E293B", zIndex: 1000, display: "flex", flexDirection: "column", boxShadow: "-8px 0 40px rgba(0,0,0,0.5)", animation: "slideIn 0.3s ease" }}>
      <style>{`@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }`}</style>
      {/* Header */}
      <div style={{ padding: "20px 24px", borderBottom: "1px solid #1E293B", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <ARSGauge score={vuln.ars} size={56} />
          <div>
            <div style={{ fontFamily: "JetBrains Mono", fontSize: 16, fontWeight: 700, color: "#F1F5F9" }}>{vuln.cve_id}</div>
            <div style={{ display: "flex", gap: 6, marginTop: 4, flexWrap: "wrap" }}>
              <PriorityBadge tier={vuln.priority_tier} />{vuln.kev_listed && <KEVBadge />}
            </div>
          </div>
        </div>
        <button onClick={onClose} style={{ background: "none", border: "1px solid #334155", borderRadius: 6, color: "#94A3B8", padding: "6px 10px", cursor: "pointer", fontSize: 14 }}>✕</button>
      </div>
      {/* Tabs */}
      <div style={{ display: "flex", borderBottom: "1px solid #1E293B", padding: "0 24px", overflowX: "auto" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} style={{ background: "none", border: "none", padding: "10px 16px", cursor: "pointer", fontFamily: "DM Sans", fontSize: 13, fontWeight: 600, color: activeTab === t.id ? "#60A5FA" : "#64748B", borderBottom: activeTab === t.id ? "2px solid #60A5FA" : "2px solid transparent", whiteSpace: "nowrap" }}>{t.label}</button>
        ))}
      </div>
      {/* Content */}
      <div style={{ flex: 1, overflow: "auto", padding: 24 }}>
        {activeTab === "overview" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <Section title="Description"><p style={{ color: "#CBD5E1", fontSize: 13, lineHeight: 1.7, margin: 0 }}>{vuln.description}</p></Section>
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
                <InfoCard label="CVSS Base Score"><span style={{ fontFamily: "JetBrains Mono", fontWeight: 700, color: "#F1F5F9" }}>{vuln.cvss_v4_base_score}</span></InfoCard>
                <InfoCard label="Exploit Maturity"><code style={codeStyle}>{vuln.exploit_maturity}</code></InfoCard>
                <InfoCard label="CWE">{vuln.cwe_ids?.slice(0, 3).map(c => <code key={c} style={{ ...codeStyle, marginRight: 4 }}>{c}</code>)}</InfoCard>
                <InfoCard label="KEV Listed"><span style={{ color: vuln.kev_listed ? "#DC2626" : "#64748B", fontWeight: 600 }}>{vuln.kev_listed ? "YES" : "NO"}</span></InfoCard>
              </div>
            </Section>
            <Section title="Automotive Classification">
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <InfoCard label="Relevance Score"><span style={{ fontFamily: "JetBrains Mono", fontWeight: 700, color: vuln.relevance_score >= 0.3 ? "#059669" : "#D97706" }}>{(vuln.relevance_score || 0).toFixed(2)}</span></InfoCard>
                <InfoCard label="Classification Method"><code style={codeStyle}>{vuln.classification_method}</code></InfoCard>
              </div>
              {vuln.all_ecu_domains?.length > 1 && (
                <div style={{ marginTop: 8 }}><InfoCard label="All Affected Domains">
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>{vuln.all_ecu_domains.map(d => <ECUBadge key={d} domain={d} />)}</div>
                </InfoCard></div>
              )}
            </Section>
            <Section title="Source Feeds"><div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>{vuln.source_feeds?.map(s => <SourceBadge key={s} source={s} />)}</div></Section>
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
                <thead><tr style={{ borderBottom: "1px solid #1E293B" }}><th style={thStyle}>Factor</th><th style={thStyle}>Value</th><th style={thStyle}>Modifier</th><th style={thStyle}>Running</th></tr></thead>
                <tbody>
                  <tr style={trStyle}><td style={tdStyle}>CVSS Base</td><td style={tdStyle}><code style={codeStyle}>{vuln.cvss_v4_base_score}</code></td><td style={tdStyle}>—</td><td style={tdStyle}><strong style={{ color: "#F1F5F9" }}>{vuln.cvss_v4_base_score?.toFixed(2)}</strong></td></tr>
                  <tr style={trStyle}><td style={tdStyle}>ASIL Safety ({ecuInfo?.asil})</td><td style={tdStyle}>{vuln.ecu_domain}</td><td style={tdStyle}><code style={codeStyle}>×{vuln.asil_modifier}</code></td><td style={tdStyle}><strong style={{ color: "#F1F5F9" }}>{(vuln.cvss_v4_base_score * vuln.asil_modifier).toFixed(2)}</strong></td></tr>
                  <tr style={trStyle}><td style={tdStyle}>Reachability</td><td style={tdStyle}>{vuln.attack_surface}/{vuln.network_path}</td><td style={tdStyle}><code style={codeStyle}>×{vuln.reachability_modifier}</code></td><td style={tdStyle}><strong style={{ color: "#F1F5F9" }}>{(vuln.cvss_v4_base_score * vuln.asil_modifier * vuln.reachability_modifier).toFixed(2)}</strong></td></tr>
                  <tr style={trStyle}><td style={tdStyle}>Exploit Maturity</td><td style={tdStyle}>{vuln.exploit_maturity}</td><td style={tdStyle}><code style={codeStyle}>×{vuln.exploit_modifier}</code></td><td style={tdStyle}><strong style={{ color: "#F1F5F9" }}>{vuln.raw_score?.toFixed(2)}</strong></td></tr>
                  <tr style={{ borderTop: "2px solid #334155" }}><td colSpan={3} style={{ ...tdStyle, fontWeight: 700, color: "#F1F5F9" }}>Final ARS (capped at 10.0)</td><td style={tdStyle}><span style={{ fontFamily: "JetBrains Mono", fontSize: 18, fontWeight: 700, color: PRIORITY_TIERS[vuln.priority_tier]?.color }}>{vuln.ars?.toFixed(1)}</span></td></tr>
                </tbody>
              </table>
            </Section>
            <Section title="Justification Trace (Audit Trail)">
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {vuln.justification_trace?.map((line, i) => (
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
              <pre style={{ background: "#0F172A", border: "1px solid #1E293B", borderRadius: 8, padding: 16, fontSize: 11, fontFamily: "JetBrains Mono", color: "#CBD5E1", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6, maxHeight: 500 }}>{JSON.stringify(avrJson, null, 2)}</pre>
            </Section>
            <button onClick={() => { const b = new Blob([JSON.stringify(avrJson, null, 2)], { type: "application/json" }); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = `${vuln.cve_id}_AVR.json`; a.click(); URL.revokeObjectURL(u); }} style={exportBtnStyle}>⬇ Export AVR as JSON</button>
          </div>
        )}
        {activeTab === "tara" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <Section title="TARA Asset Register Entry (ISO/SAE 21434 Cl.9)">
              <pre style={{ background: "#0F172A", border: "1px solid #1E293B", borderRadius: 8, padding: 16, fontSize: 11, fontFamily: "JetBrains Mono", color: "#CBD5E1", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6, maxHeight: 500 }}>
                {JSON.stringify({ asset_id: `TARA-ASSET-${(vuln.sbom_component || vuln.cve_id).replace(/[\s:]/g, "_")}-${vuln.ecu_domain}`, asset_name: vuln.affected_product, asset_type: "software_component", ecu_domain: vuln.ecu_domain, safety_criticality: ecuInfo?.asil || "QM", affected_cve: vuln.cve_id, cybersecurity_properties: { confidentiality: vuln.ars >= 7 ? "high" : "medium", integrity: vuln.ars >= 7 ? "high" : "medium", availability: vuln.ars >= 7 ? "high" : "medium" }, damage_scenario: `Exploitation of ${vuln.affected_product} in ${ecuInfo?.label} domain via ${vuln.attack_surface} (${vuln.network_path}) — ${vuln.description?.slice(0, 200)}...`, ars_score: vuln.ars, priority_tier: vuln.priority_tier, recommended_action: vuln.recommended_action, treatment_sla: tierInfo?.sla, iso_21434_clause: "Cl.15 — Vulnerability Management", generated_at: new Date().toISOString() }, null, 2)}
              </pre>
            </Section>
            <button onClick={() => { const d = { asset_id: `TARA-ASSET-${vuln.cve_id}-${vuln.ecu_domain}`, asset_name: vuln.affected_product, ecu_domain: vuln.ecu_domain, safety_criticality: ecuInfo?.asil, affected_cve: vuln.cve_id, ars_score: vuln.ars, priority_tier: vuln.priority_tier }; const b = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" }); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = `TARA_${vuln.cve_id}.json`; a.click(); URL.revokeObjectURL(u); }} style={exportBtnStyle}>⬇ Export TARA Entry</button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── DASHBOARD STATS ───────────────────────────────────────────────

function DashboardStats({ vulns, loading }) {
  const p0 = vulns.filter(v => v.priority_tier === "P0_critical").length;
  const p1 = vulns.filter(v => v.priority_tier === "P1_high").length;
  const p2 = vulns.filter(v => v.priority_tier === "P2_medium").length;
  const p3 = vulns.filter(v => v.priority_tier === "P3_low").length;
  const kev = vulns.filter(v => v.kev_listed).length;
  const avgArs = vulns.length ? (vulns.reduce((s, v) => s + v.ars, 0) / vulns.length).toFixed(1) : "0.0";
  const stats = [
    { label: "Total AVRs", value: loading ? "..." : vulns.length, color: "#60A5FA", icon: "⬡" },
    { label: "P0 Critical", value: loading ? "..." : p0, color: "#DC2626", icon: "⊘" },
    { label: "P1 High", value: loading ? "..." : p1, color: "#EA580C", icon: "◈" },
    { label: "P2 Medium", value: loading ? "..." : p2, color: "#D97706", icon: "▣" },
    { label: "P3 Low", value: loading ? "..." : p3, color: "#2563EB", icon: "◇" },
    { label: "KEV Listed", value: loading ? "..." : kev, color: "#DC2626", icon: "⚡" },
    { label: "Avg ARS", value: loading ? "..." : avgArs, color: "#7C3AED", icon: "◎" },
  ];
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(7, 1fr)", gap: 10 }}>
      {stats.map(s => (
        <div key={s.label} style={{ padding: "14px 12px", borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B", display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
          <span style={{ fontSize: 20, opacity: 0.7 }}>{s.icon}</span>
          <span style={{ fontFamily: "JetBrains Mono", fontSize: 22, fontWeight: 700, color: s.color }}>{s.value}</span>
          <span style={{ fontFamily: "DM Sans", fontSize: 10, color: "#64748B", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em" }}>{s.label}</span>
        </div>
      ))}
    </div>
  );
}

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
              <span style={{ minWidth: 140, fontFamily: "DM Sans", fontSize: 11, color: info?.color || "#94A3B8", fontWeight: 600 }}>{info?.icon} {info?.label || domain}</span>
              <div style={{ flex: 1, height: 18, background: "#1E293B", borderRadius: 4, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${(count / max) * 100}%`, background: `linear-gradient(90deg, ${info?.color}60, ${info?.color}20)`, borderRadius: 4, transition: "width 0.8s ease" }} />
              </div>
              <span style={{ minWidth: 30, fontFamily: "JetBrains Mono", fontSize: 12, color: "#F1F5F9", fontWeight: 700, textAlign: "right" }}>{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── INGESTION LOG ─────────────────────────────────────────────────

function IngestionLog({ logs }) {
  if (!logs.length) return null;
  return (
    <div style={{ padding: 16, borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B", maxHeight: 200, overflow: "auto" }}>
      <h3 style={{ fontFamily: "DM Sans", fontSize: 12, fontWeight: 700, color: "#94A3B8", margin: "0 0 10px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Ingestion Pipeline Log</h3>
      <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
        {logs.map((log, i) => (
          <div key={i} style={{ display: "flex", gap: 8, fontSize: 10, fontFamily: "JetBrains Mono" }}>
            <span style={{ color: "#334155", minWidth: 60 }}>{log.time}</span>
            <span style={{ color: log.type === "error" ? "#DC2626" : log.type === "success" ? "#059669" : log.type === "warn" ? "#D97706" : "#64748B" }}>{log.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── CUSTOM CVE INPUT ──────────────────────────────────────────────

function CustomCVEInput({ onCompute }) {
  const [form, setForm] = useState({ cve_id: "", description: "", cvss_v4_base_score: 7.5, ecu_domain: "gateway", attack_surface: "remote_external", network_path: "telematics", exploit_maturity: "poc", kev_listed: false, affected_product: "", sbom_component: "", sbom_version: "" });
  const update = (k, v) => setForm(p => ({ ...p, [k]: v }));
  const inputStyle = { background: "#0F172A", border: "1px solid #1E293B", borderRadius: 6, padding: "8px 12px", color: "#F1F5F9", fontFamily: "JetBrains Mono", fontSize: 12, outline: "none", width: "100%", boxSizing: "border-box" };
  const selectStyle = { ...inputStyle, cursor: "pointer" };
  const labelStyle = { fontSize: 10, color: "#64748B", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4, display: "block", fontFamily: "DM Sans" };
  const handleSubmit = () => {
    if (!form.cve_id) return;
    const vuln = { ...form, cvss_v4_base_score: parseFloat(form.cvss_v4_base_score), published: new Date().toISOString().split("T")[0], modified: new Date().toISOString().split("T")[0], cvss_vector: "CVSS:4.0/Manual", cwe_ids: [], cpe_matches: [], source_feeds: ["Manual"], relevance_score: 1.0, classification_method: "manual_assessment", sbom_purl: "", vendor_advisories: [], all_ecu_domains: [form.ecu_domain] };
    onCompute({ ...vuln, ...computeARS(vuln) });
  };
  return (
    <div style={{ padding: 24, background: "#0B1120", borderRadius: 12, border: "1px solid #1E293B" }}>
      <h3 style={{ fontFamily: "DM Sans", fontSize: 15, fontWeight: 700, color: "#F1F5F9", margin: "0 0 16px", display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ width: 28, height: 28, borderRadius: 6, background: "#1E293B", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14 }}>+</span>Manual CVE Assessment
      </h3>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
        <div><label style={labelStyle}>CVE ID</label><input style={inputStyle} value={form.cve_id} onChange={e => update("cve_id", e.target.value)} placeholder="CVE-2026-XXXXX" /></div>
        <div><label style={labelStyle}>Affected Product</label><input style={inputStyle} value={form.affected_product} onChange={e => update("affected_product", e.target.value)} placeholder="Product name" /></div>
        <div><label style={labelStyle}>CVSS v4.0 Base Score</label><input type="number" step="0.1" min="0" max="10" style={inputStyle} value={form.cvss_v4_base_score} onChange={e => update("cvss_v4_base_score", e.target.value)} /></div>
        <div><label style={labelStyle}>ECU Domain</label><select style={selectStyle} value={form.ecu_domain} onChange={e => update("ecu_domain", e.target.value)}>{Object.entries(ECU_DOMAINS).map(([k, v]) => <option key={k} value={k}>{v.icon} {v.label}</option>)}</select></div>
        <div><label style={labelStyle}>Attack Surface</label><select style={selectStyle} value={form.attack_surface} onChange={e => update("attack_surface", e.target.value)}>{ATTACK_SURFACES.map(s => <option key={s} value={s}>{s}</option>)}</select></div>
        <div><label style={labelStyle}>Network Path</label><select style={selectStyle} value={form.network_path} onChange={e => update("network_path", e.target.value)}>{NETWORK_PATHS.map(s => <option key={s} value={s}>{s}</option>)}</select></div>
        <div><label style={labelStyle}>Exploit Maturity</label><select style={selectStyle} value={form.exploit_maturity} onChange={e => update("exploit_maturity", e.target.value)}>{EXPLOIT_MATURITIES.map(s => <option key={s} value={s}>{s}</option>)}</select></div>
        <div><label style={labelStyle}>KEV Listed</label><select style={selectStyle} value={form.kev_listed} onChange={e => update("kev_listed", e.target.value === "true")}><option value="false">No</option><option value="true">Yes</option></select></div>
        <div><label style={labelStyle}>SBOM Component</label><input style={inputStyle} value={form.sbom_component} onChange={e => update("sbom_component", e.target.value)} placeholder="Component name" /></div>
      </div>
      <div style={{ marginTop: 12 }}><label style={labelStyle}>Description</label><textarea style={{ ...inputStyle, height: 60, resize: "vertical" }} value={form.description} onChange={e => update("description", e.target.value)} placeholder="Vulnerability description..." /></div>
      <button onClick={handleSubmit} style={{ marginTop: 16, width: "100%", padding: "10px 20px", borderRadius: 6, background: "linear-gradient(135deg, #2563EB, #7C3AED)", border: "none", color: "#fff", fontFamily: "DM Sans", fontSize: 13, fontWeight: 700, cursor: "pointer" }}>Compute ARS & Generate AVR</button>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// MAIN APP WITH LIVE API INGESTION
// ═══════════════════════════════════════════════════════════════════

export default function AutoVIA() {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [ingestionLogs, setIngestionLogs] = useState([]);
  const [search, setSearch] = useState("");
  const [filterDomain, setFilterDomain] = useState("all");
  const [filterPriority, setFilterPriority] = useState("all");
  const [filterKEV, setFilterKEV] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState(null);
  const [view, setView] = useState("dashboard");
  const [sortBy, setSortBy] = useState("ars_desc");
  const [fetchProgress, setFetchProgress] = useState({ current: 0, total: 0, source: "" });
  const [kevCount, setKevCount] = useState(0);

  const addLog = useCallback((message, type = "info") => {
    const time = new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
    setIngestionLogs(prev => [...prev.slice(-100), { time, message, type }]);
  }, []);

  // ── LIVE DATA INGESTION ─────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;

    async function ingestData() {
      addLog("Auto-VIA Ingestion Pipeline starting...", "info");
      addLog("Stage 0: Loading CISA KEV catalog...", "info");

      // Step 1: Fetch CISA KEV catalog
      let kevSet = new Set();
      try {
        const kevResp = await fetch(KEV_FEED_URL);
        if (kevResp.ok) {
          const kevData = await kevResp.json();
          kevData.vulnerabilities?.forEach(v => kevSet.add(v.cveID));
          setKevCount(kevSet.size);
          addLog(`KEV catalog loaded: ${kevSet.size} known exploited vulnerabilities`, "success");
        } else {
          addLog(`KEV fetch failed (${kevResp.status}) — continuing without KEV data`, "warn");
        }
      } catch (e) {
        addLog(`KEV fetch error: ${e.message} — continuing without KEV data`, "warn");
      }

      // Step 2: Fetch CVEs from NVD using automotive search keywords
      addLog("Stage 1: Querying NVD API v2.0 for automotive-relevant CVEs...", "info");
      const allAVRs = new Map();
      let searchIndex = 0;

      for (const searchItem of AUTOMOTIVE_NVD_SEARCHES) {
        if (cancelled) break;
        searchIndex++;
        setFetchProgress({ current: searchIndex, total: AUTOMOTIVE_NVD_SEARCHES.length, source: searchItem.label });
        addLog(`[${searchIndex}/${AUTOMOTIVE_NVD_SEARCHES.length}] Querying: ${searchItem.label} (${searchItem.keyword})`, "info");

        try {
          const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(searchItem.keyword)}&resultsPerPage=50&apiKey=${NVD_API_KEY}`;
          const resp = await fetch(url);

          if (resp.status === 403) {
            addLog(`Rate limited on "${searchItem.keyword}" — waiting 6s...`, "warn");
            await new Promise(r => setTimeout(r, 6000));
            continue;
          }

          if (!resp.ok) {
            addLog(`NVD query failed for "${searchItem.keyword}" (${resp.status})`, "error");
            continue;
          }

          const data = await resp.json();
          const items = data.vulnerabilities || [];
          let added = 0;

          for (const item of items) {
            const cveId = item.cve?.id;
            if (!cveId || allAVRs.has(cveId)) continue; // Deduplication

            const avr = parseNVDtoAVR(item, kevSet);
            if (avr && avr.cvss_v4_base_score > 0) {
              allAVRs.set(cveId, avr);
              added++;
            }
          }

          addLog(`  → ${items.length} CVEs received, ${added} new AVRs created (${allAVRs.size} total)`, "success");

          // Update UI progressively
          if (!cancelled) {
            setVulns(Array.from(allAVRs.values()).sort((a, b) => b.ars - a.ars));
          }

          // Rate limiting: NVD allows 50 req/30s with API key
          await new Promise(r => setTimeout(r, 700));

        } catch (e) {
          addLog(`Error querying "${searchItem.keyword}": ${e.message}`, "error");
        }
      }

      if (!cancelled) {
        const finalVulns = Array.from(allAVRs.values()).sort((a, b) => b.ars - a.ars);
        setVulns(finalVulns);
        setLoading(false);

        const kevMatched = finalVulns.filter(v => v.kev_listed).length;
        const p0 = finalVulns.filter(v => v.priority_tier === "P0_critical").length;
        addLog(`═══════════════════════════════════════════`, "info");
        addLog(`Ingestion complete: ${finalVulns.length} automotive AVRs created`, "success");
        addLog(`KEV matches: ${kevMatched} | P0 Critical: ${p0}`, "success");
        addLog(`Pipeline status: LIVE — ready for triage`, "success");
      }
    }

    ingestData();
    return () => { cancelled = true; };
  }, [addLog]);

  // Add manual CVE
  const handleCustomCompute = (vuln) => {
    setVulns(prev => [vuln, ...prev]);
    setSelectedVuln(vuln);
    setView("search");
  };

  // Filtering
  const filtered = useMemo(() => {
    let result = vulns;
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(v =>
        v.cve_id?.toLowerCase().includes(q) || v.description?.toLowerCase().includes(q) ||
        v.affected_product?.toLowerCase().includes(q) || v.ecu_domain?.toLowerCase().includes(q) ||
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
  }, [vulns, search, filterDomain, filterPriority, filterKEV, sortBy]);

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: "▦" },
    { id: "search", label: "Search & Triage", icon: "⌕" },
    { id: "assess", label: "Manual Assessment", icon: "+" },
  ];
  const selectStyle = { background: "#0F172A", border: "1px solid #1E293B", borderRadius: 6, padding: "7px 10px", color: "#94A3B8", fontFamily: "DM Sans", fontSize: 12, outline: "none", cursor: "pointer" };

  return (
    <div style={{ minHeight: "100vh", background: "#060A14", color: "#F1F5F9", fontFamily: "DM Sans" }}>
      <style>{fonts}</style>
      <style>{`* { box-sizing: border-box; } ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #0B1120; } ::-webkit-scrollbar-thumb { background: #1E293B; border-radius: 3px; } ::selection { background: #2563EB40; } input:focus, select:focus, textarea:focus { border-color: #2563EB !important; } option { background: #0F172A; color: #F1F5F9; }`}</style>

      {/* HEADER */}
      <header style={{ padding: "0 32px", height: 64, display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid #1E293B", background: "#0B1120", position: "sticky", top: 0, zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ width: 36, height: 36, borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", background: "linear-gradient(135deg, #2563EB, #7C3AED)", fontFamily: "JetBrains Mono", fontWeight: 800, fontSize: 14, color: "#fff" }}>AV</div>
          <div>
            <div style={{ fontFamily: "JetBrains Mono", fontWeight: 700, fontSize: 16, color: "#F1F5F9", letterSpacing: "-0.02em" }}>Auto-VIA</div>
            <div style={{ fontFamily: "DM Sans", fontSize: 10, color: "#64748B", letterSpacing: "0.08em", textTransform: "uppercase" }}>Automotive Vulnerability Intelligence Aggregator</div>
          </div>
        </div>
        <nav style={{ display: "flex", gap: 4 }}>
          {navItems.map(item => (
            <button key={item.id} onClick={() => setView(item.id)} style={{ background: view === item.id ? "#1E293B" : "transparent", border: view === item.id ? "1px solid #334155" : "1px solid transparent", borderRadius: 6, padding: "7px 14px", cursor: "pointer", fontFamily: "DM Sans", fontSize: 12, fontWeight: 600, color: view === item.id ? "#60A5FA" : "#64748B", display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 14 }}>{item.icon}</span> {item.label}
            </button>
          ))}
        </nav>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {loading ? (
            <div style={{ padding: "4px 10px", borderRadius: 20, background: "#D9770620", border: "1px solid #D9770640", fontFamily: "JetBrains Mono", fontSize: 10, color: "#D97706", fontWeight: 600 }}>
              ◌ INGESTING — {fetchProgress.source} ({fetchProgress.current}/{fetchProgress.total})
            </div>
          ) : (
            <div style={{ padding: "4px 10px", borderRadius: 20, background: "#05966920", border: "1px solid #05966940", fontFamily: "JetBrains Mono", fontSize: 10, color: "#059669", fontWeight: 600 }}>
              ● LIVE — {vulns.length} AVRs | NVD + KEV
            </div>
          )}
          <div style={{ padding: "4px 10px", borderRadius: 20, background: "#1E293B", border: "1px solid #334155", fontFamily: "JetBrains Mono", fontSize: 10, color: "#94A3B8" }}>ISO/SAE 21434 | R155</div>
        </div>
      </header>

      {/* MAIN */}
      <main style={{ maxWidth: 1440, margin: "0 auto", padding: "24px 32px" }}>

        {/* DASHBOARD */}
        {view === "dashboard" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <DashboardStats vulns={vulns} loading={loading} />
            <IngestionLog logs={ingestionLogs} />
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
              <ECUDistribution vulns={vulns} />
              <div style={{ padding: 20, borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B" }}>
                <h3 style={{ fontFamily: "DM Sans", fontSize: 13, fontWeight: 700, color: "#94A3B8", margin: "0 0 14px", textTransform: "uppercase", letterSpacing: "0.05em" }}>Priority Distribution</h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  {Object.entries(PRIORITY_TIERS).map(([tier, info]) => {
                    const count = vulns.filter(v => v.priority_tier === tier).length;
                    const pct = vulns.length ? ((count / vulns.length) * 100).toFixed(0) : 0;
                    return (
                      <div key={tier} style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <span style={{ minWidth: 90 }}><PriorityBadge tier={tier} /></span>
                        <div style={{ flex: 1, height: 22, background: "#1E293B", borderRadius: 4, overflow: "hidden" }}>
                          <div style={{ height: "100%", width: `${pct}%`, background: `${info.color}50`, borderRadius: 4, transition: "width 0.8s ease", display: "flex", alignItems: "center", justifyContent: "flex-end", paddingRight: 6 }}>
                            {count > 0 && <span style={{ fontFamily: "JetBrains Mono", fontSize: 10, color: "#F1F5F9", fontWeight: 700 }}>{count}</span>}
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
                {vulns.filter(v => v.priority_tier === "P0_critical" || v.priority_tier === "P1_high").slice(0, 8).map(v => (
                  <div key={v.cve_id} onClick={() => setSelectedVuln(v)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", borderRadius: 6, background: "#0F172A", border: "1px solid #1E293B", cursor: "pointer", transition: "border-color 0.2s" }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = "#334155"}
                    onMouseLeave={e => e.currentTarget.style.borderColor = "#1E293B"}>
                    <ARSGauge score={v.ars} size={40} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <span style={{ fontFamily: "JetBrains Mono", fontSize: 12, fontWeight: 700, color: "#F1F5F9" }}>{v.cve_id}</span>
                        <PriorityBadge tier={v.priority_tier} />{v.kev_listed && <KEVBadge />}
                      </div>
                      <div style={{ fontSize: 11, color: "#64748B", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.affected_product} — {v.description?.slice(0, 100)}...</div>
                    </div>
                    <ECUBadge domain={v.ecu_domain} />
                  </div>
                ))}
                {vulns.filter(v => v.priority_tier === "P0_critical" || v.priority_tier === "P1_high").length === 0 && !loading && (
                  <div style={{ padding: 20, textAlign: "center", color: "#64748B", fontSize: 12 }}>No critical or high findings yet</div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* SEARCH */}
        {view === "search" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div style={{ display: "flex", gap: 10, padding: 16, borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B", flexWrap: "wrap" }}>
              <div style={{ flex: 1, position: "relative", minWidth: 250 }}>
                <span style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: "#64748B", fontSize: 16 }}>⌕</span>
                <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search CVE ID, product, ECU domain, CWE, description..."
                  style={{ width: "100%", background: "#0F172A", border: "1px solid #1E293B", borderRadius: 6, padding: "10px 12px 10px 36px", color: "#F1F5F9", fontFamily: "JetBrains Mono", fontSize: 13, outline: "none" }} />
              </div>
              <select value={filterDomain} onChange={e => setFilterDomain(e.target.value)} style={selectStyle}>
                <option value="all">All ECU Domains</option>
                {Object.entries(ECU_DOMAINS).map(([k, v]) => <option key={k} value={k}>{v.icon} {v.label}</option>)}
              </select>
              <select value={filterPriority} onChange={e => setFilterPriority(e.target.value)} style={selectStyle}>
                <option value="all">All Priorities</option>
                {Object.entries(PRIORITY_TIERS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>
              <button onClick={() => setFilterKEV(!filterKEV)} style={{ ...selectStyle, background: filterKEV ? "#DC262620" : "#0F172A", border: filterKEV ? "1px solid #DC262660" : "1px solid #1E293B", color: filterKEV ? "#DC2626" : "#64748B", fontWeight: 600 }}>⚡ KEV</button>
              <select value={sortBy} onChange={e => setSortBy(e.target.value)} style={selectStyle}>
                <option value="ars_desc">ARS ↓</option><option value="ars_asc">ARS ↑</option><option value="cvss_desc">CVSS ↓</option><option value="date_desc">Date ↓</option>
              </select>
            </div>
            <div style={{ fontFamily: "DM Sans", fontSize: 12, color: "#64748B" }}>
              Showing <strong style={{ color: "#F1F5F9" }}>{filtered.length}</strong> of {vulns.length} automotive-relevant vulnerabilities
              {loading && <span style={{ color: "#D97706" }}> (still ingesting...)</span>}
            </div>
            <div style={{ borderRadius: 10, background: "#0B1120", border: "1px solid #1E293B", overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ background: "#0F172A", borderBottom: "1px solid #1E293B" }}>
                    {["ARS", "CVE ID", "Priority", "ECU Domain", "CVSS", "Exploit", "Product", "KEV", "Date"].map(h => (
                      <th key={h} style={{ padding: "10px 12px", textAlign: "left", fontFamily: "DM Sans", fontSize: 10, fontWeight: 700, color: "#64748B", textTransform: "uppercase", letterSpacing: "0.06em" }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.slice(0, 200).map(v => (
                    <tr key={v.cve_id} onClick={() => setSelectedVuln(v)} style={{ borderBottom: "1px solid #1E293B", cursor: "pointer", transition: "background 0.15s" }}
                      onMouseEnter={e => e.currentTarget.style.background = "#0F172A"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
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
              {filtered.length === 0 && !loading && (
                <div style={{ padding: 40, textAlign: "center", color: "#64748B" }}>
                  <div style={{ fontSize: 32, marginBottom: 8, opacity: 0.3 }}>⌕</div>No vulnerabilities match your criteria
                </div>
              )}
              {filtered.length > 200 && (
                <div style={{ padding: 12, textAlign: "center", color: "#64748B", fontSize: 11, borderTop: "1px solid #1E293B" }}>
                  Showing 200 of {filtered.length} results. Use filters to narrow down.
                </div>
              )}
            </div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button onClick={() => { const d = filtered.slice(0, 500).map(v => ({ cve_id: v.cve_id, ars: v.ars, priority_tier: v.priority_tier, ecu_domain: v.ecu_domain, cvss: v.cvss_v4_base_score, exploit_maturity: v.exploit_maturity, kev_listed: v.kev_listed, recommended_action: v.recommended_action, affected_product: v.affected_product })); const b = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" }); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = "AutoVIA_Export.json"; a.click(); URL.revokeObjectURL(u); }} style={exportBtnStyle}>⬇ Export JSON</button>
              <button onClick={() => { const csv = ["CVE_ID,ARS,Priority,ECU_Domain,CVSS,Exploit_Maturity,KEV,Action,Product", ...filtered.slice(0, 500).map(v => `${v.cve_id},${v.ars},${v.priority_tier},${v.ecu_domain},${v.cvss_v4_base_score},${v.exploit_maturity},${v.kev_listed},${v.recommended_action},"${(v.affected_product || "").replace(/"/g, "'")}"`)].join("\n"); const b = new Blob([csv], { type: "text/csv" }); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href = u; a.download = "AutoVIA_Export.csv"; a.click(); URL.revokeObjectURL(u); }} style={exportBtnStyle}>⬇ Export CSV</button>
            </div>
          </div>
        )}

        {/* MANUAL ASSESSMENT */}
        {view === "assess" && (
          <div style={{ maxWidth: 900, margin: "0 auto" }}>
            <CustomCVEInput onCompute={handleCustomCompute} />
          </div>
        )}
      </main>

      {/* DETAIL PANEL */}
      {selectedVuln && (
        <>
          <div onClick={() => setSelectedVuln(null)} style={{ position: "fixed", top: 0, left: 0, right: 0, bottom: 0, background: "rgba(0,0,0,0.6)", zIndex: 999 }} />
          <VulnDetailPanel vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />
        </>
      )}

      {/* FOOTER */}
      <footer style={{ padding: "16px 32px", borderTop: "1px solid #1E293B", background: "#0B1120", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
        <span style={{ fontFamily: "DM Sans", fontSize: 11, color: "#475569" }}>Auto-VIA v2.5 — Live NVD + CISA KEV Ingestion — Open-Source Automotive Vulnerability Intelligence</span>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {["ISO/SAE 21434", "UNECE R155", "CVSS v4.0", "NVD API v2.0", "CISA KEV"].map(s => (
            <span key={s} style={{ padding: "3px 8px", borderRadius: 4, background: "#1E293B", border: "1px solid #334155", fontFamily: "JetBrains Mono", fontSize: 9, color: "#64748B" }}>{s}</span>
          ))}
        </div>
      </footer>
    </div>
  );
}
