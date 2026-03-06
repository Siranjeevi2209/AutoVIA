// scripts/fetch-cves.js
// Auto-VIA CVE Database Builder
// Fetches automotive-relevant CVEs from NVD API + CISA KEV
// Runs via GitHub Actions weekly or on-demand

const fs = require('fs');
const path = require('path');

const API_KEY = process.env.NVD_API_KEY || '';
const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const KEYWORDS = [
  "qnx", "vxworks", "autosar", "android automotive", "freertos",
  "zephyr rtos", "threadx", "integrity rtos", "automotive grade linux",
  "nucleus rtos", "yocto embedded", "RIOT-OS",
  "openssl", "wolfssl", "mbedtls", "boringssl", "libressl", "gnutls",
  "CAN bus vulnerability", "CAN injection", "j1939", "OBD-II",
  "unified diagnostic services", "SOME/IP", "flexray",
  "automotive ethernet", "vehicle to everything", "DSRC",
  "diagnostics over IP",
  "bluetooth vehicle", "bluetooth automotive", "wifi automotive",
  "telematics", "vehicle gateway", "OTA update vehicle",
  "vehicle infotainment", "connected car", "NFC vehicle",
  "UWB vehicle", "eSIM automotive",
  "toyota vehicle", "tesla vehicle", "BMW vehicle",
  "mercedes benz vehicle", "volkswagen vehicle", "ford vehicle",
  "hyundai vehicle", "honda vehicle", "nissan vehicle",
  "kia vehicle", "volvo vehicle", "audi vehicle",
  "subaru vehicle", "porsche vehicle", "jaguar land rover",
  "stellantis vehicle", "rivian vehicle", "mazda vehicle",
  "mitsubishi vehicle", "general motors vehicle",
  "bosch automotive", "continental automotive", "denso",
  "harman", "aptiv", "ZF friedrichshafen", "valeo automotive",
  "visteon", "magna automotive", "lear corporation",
  "panasonic automotive", "yazaki", "alpine electronics",
  "nxp semiconductor", "infineon", "renesas automotive",
  "nvidia drive", "mobileye", "qualcomm automotive",
  "microchip technology automotive", "texas instruments automotive",
  "STMicroelectronics automotive",
  "lidar vehicle", "radar automotive", "autonomous driving",
  "adaptive cruise control", "automatic emergency braking",
  "lane departure warning", "autopilot vehicle",
  "camera ECU automotive", "ROS2 robot",
  "electronic braking system", "anti-lock braking",
  "electronic stability control", "electric power steering",
  "airbag ECU", "tire pressure monitoring",
  "battery management vehicle", "EV charging station",
  "electric vehicle charger",
  "keyless entry vehicle", "relay attack vehicle",
  "key fob vulnerability", "immobilizer vehicle",
  "remote start vehicle",
  "vector CANalyzer", "ECU flashing", "vehicle firmware",
  "dSPACE automotive", "ETAS INCA",
  "fleet management vehicle", "geotab", "vehicle tracking GPS",
  "vehicle API", "car sharing platform",
  "linux kernel CAN", "linux kernel bluetooth",
  "linux kernel automotive", "linux kernel USB gadget",
];

const CPE_TO_ECU_RULES = [
  { pattern: /blackberry.*qnx|qnx.*neutrino/i, domain: "adas" },
  { pattern: /wind_river.*vxworks|vxworks/i, domain: "powertrain" },
  { pattern: /autosar/i, domain: "powertrain" },
  { pattern: /green_hills.*integrity|integrity.*rtos/i, domain: "adas" },
  { pattern: /freertos|free_rtos/i, domain: "gateway" },
  { pattern: /zephyr/i, domain: "body" },
  { pattern: /threadx|azure.*rtos/i, domain: "telematics" },
  { pattern: /android.*auto|google.*android.*automotive/i, domain: "infotainment" },
  { pattern: /openssl/i, domain: "gateway" },
  { pattern: /wolfssl|wolf_ssl/i, domain: "telematics" },
  { pattern: /mbedtls|mbed_tls/i, domain: "telematics" },
  { pattern: /linux.*kernel|linux_kernel/i, domain: "gateway" },
  { pattern: /can.*bus|socketcan|can_utils|j1939/i, domain: "gateway" },
  { pattern: /flexray/i, domain: "chassis" },
  { pattern: /doip|diagnostics.*over.*ip/i, domain: "diagnostics" },
  { pattern: /uds|unified.*diagnostic/i, domain: "diagnostics" },
  { pattern: /some.*ip|someip/i, domain: "adas" },
  { pattern: /obd|on.*board.*diagnostic/i, domain: "diagnostics" },
  { pattern: /bluetooth|ble|bluez/i, domain: "infotainment" },
  { pattern: /wifi|wi-fi|wpa_supplicant/i, domain: "infotainment" },
  { pattern: /v2x|dsrc|c-v2x/i, domain: "telematics" },
  { pattern: /5g.*nr|cellular.*modem|qualcomm.*mdm/i, domain: "telematics" },
  { pattern: /gnss|gps.*receiver/i, domain: "telematics" },
  { pattern: /ota|over.*the.*air/i, domain: "telematics" },
  { pattern: /lidar|velodyne|luminar/i, domain: "adas" },
  { pattern: /radar.*ecu|continental.*radar|bosch.*radar/i, domain: "adas" },
  { pattern: /mobileye|nvidia.*drive|nvidia.*orin/i, domain: "adas" },
  { pattern: /opencv|tensorflow|pytorch/i, domain: "adas" },
  { pattern: /bosch/i, domain: "braking" },
  { pattern: /continental/i, domain: "chassis" },
  { pattern: /denso/i, domain: "powertrain" },
  { pattern: /harman|samsung.*harman/i, domain: "infotainment" },
  { pattern: /nxp|nxp_semi/i, domain: "gateway" },
  { pattern: /infineon/i, domain: "powertrain" },
  { pattern: /renesas/i, domain: "powertrain" },
  { pattern: /brake|braking|abs|esc|electronic.*stability/i, domain: "braking" },
  { pattern: /steering|eps|electric.*power.*steer/i, domain: "steering" },
  { pattern: /airbag|srs|supplemental.*restraint/i, domain: "chassis" },
  { pattern: /engine.*control|ecu.*engine|ecm|tcm.*transmission/i, domain: "powertrain" },
  { pattern: /battery.*management|bms|ev.*battery/i, domain: "powertrain" },
  { pattern: /hvac|door.*lock|passive.*entry|keyless/i, domain: "body" },
  { pattern: /gateway.*ecu|central.*gateway|vehicle.*gateway/i, domain: "gateway" },
  { pattern: /tcu|telematics.*control/i, domain: "telematics" },
  { pattern: /head.*unit|infotainment|ivi|in.*vehicle/i, domain: "infotainment" },
  { pattern: /toyota|lexus/i, domain: "gateway" },
  { pattern: /tesla/i, domain: "adas" },
  { pattern: /bmw|mercedes|volkswagen|audi|porsche/i, domain: "gateway" },
  { pattern: /ford|general.*motors|gm|chevrolet/i, domain: "gateway" },
  { pattern: /hyundai|kia|nissan|honda/i, domain: "gateway" },
  { pattern: /vector.*can|canalyzer/i, domain: "diagnostics" },
  { pattern: /geotab|fleet/i, domain: "telematics" },
  { pattern: /charging.*station|evse|ev.*charg/i, domain: "powertrain" },
  { pattern: /key.*fob|relay.*attack|immobiliz/i, domain: "body" },
  { pattern: /tire.*pressure|tpms/i, domain: "body" },
];

function classifyDomain(text) {
  for (const rule of CPE_TO_ECU_RULES) {
    if (rule.pattern.test(text)) return rule.domain;
  }
  return "gateway";
}

function inferAttackSurface(vector, desc) {
  let surface = "local", netPath = "unknown";
  if (vector) {
    if (vector.includes("AV:N")) surface = "remote_external";
    else if (vector.includes("AV:A")) surface = "remote_adjacent";
    else if (vector.includes("AV:L")) surface = "local";
    else if (vector.includes("AV:P")) surface = "physical";
  }
  const d = (desc || "").toLowerCase();
  if (d.match(/cellular|ota|over.the.air|cloud|telematics|5g|lte|v2x/)) netPath = "telematics";
  else if (d.match(/bluetooth|ble|wifi|wi-fi|wireless|nfc|uwb|dsrc/)) netPath = "wifi_bt";
  else if (d.match(/ethernet|100base|tcp.*ip|some.ip/)) netPath = "ethernet";
  else if (d.match(/can|can.bus|j1939|obd|lin.bus|flexray/)) netPath = "can";
  else if (d.match(/diagnostic|uds|doip|obd-ii|jtag|serial|usb/)) netPath = "diagnostic";
  else if (surface === "remote_external") netPath = "telematics";
  else if (surface === "remote_adjacent") netPath = "wifi_bt";
  else if (surface === "physical") netPath = "diagnostic";
  else netPath = "can";
  return { surface, netPath };
}

const ECU_ASIL = {
  braking: "ASIL_D", steering: "ASIL_D", powertrain: "ASIL_C", chassis: "ASIL_C",
  adas: "ASIL_D", gateway: "ASIL_B", telematics: "ASIL_A",
  infotainment: "QM", body: "QM", diagnostics: "QM",
};

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function fetchNVD(keyword) {
  const url = `${NVD_BASE}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=100`;
  const headers = { 'User-Agent': 'AutoVIA/2.5' };
  if (API_KEY) headers['apiKey'] = API_KEY;
  try {
    const resp = await fetch(url, { headers });
    if (resp.status === 429) {
      console.log(`  Rate limited, waiting 10s...`);
      await sleep(10000);
      const retry = await fetch(url, { headers });
      if (!retry.ok) return [];
      return (await retry.json()).vulnerabilities || [];
    }
    if (!resp.ok) { console.log(`  HTTP ${resp.status}`); return []; }
    return (await resp.json()).vulnerabilities || [];
  } catch (e) { console.log(`  Error: ${e.message}`); return []; }
}

async function fetchKEV() {
  try {
    const resp = await fetch(KEV_URL);
    if (!resp.ok) return new Set();
    const data = await resp.json();
    return new Set((data.vulnerabilities || []).map(v => v.cveID));
  } catch (e) { console.log(`KEV error: ${e.message}`); return new Set(); }
}

async function main() {
  console.log("=== Auto-VIA CVE Database Builder ===");
  console.log(`API Key present: ${!!API_KEY}`);
  console.log(`Keywords: ${KEYWORDS.length}\n`);

  console.log("Fetching CISA KEV catalog...");
  const kevSet = await fetchKEV();
  console.log(`KEV loaded: ${kevSet.size} entries\n`);

  const allCVEs = new Map();

  for (let i = 0; i < KEYWORDS.length; i++) {
    const kw = KEYWORDS[i];
    console.log(`[${i + 1}/${KEYWORDS.length}] ${kw}`);
    const items = await fetchNVD(kw);
    let added = 0;

    for (const item of items) {
      const cve = item.cve;
      if (!cve?.id || allCVEs.has(cve.id)) continue;
      const desc = cve.descriptions?.find(d => d.lang === "en")?.value || "";
      const metrics = cve.metrics || {};
      let baseScore = 0, vector = "";
      if (metrics.cvssMetricV40?.length) {
        baseScore = metrics.cvssMetricV40[0].cvssData?.baseScore || 0;
        vector = metrics.cvssMetricV40[0].cvssData?.vectorString || "";
      } else if (metrics.cvssMetricV31?.length) {
        baseScore = metrics.cvssMetricV31[0].cvssData?.baseScore || 0;
        vector = metrics.cvssMetricV31[0].cvssData?.vectorString || "";
      } else if (metrics.cvssMetricV30?.length) {
        baseScore = metrics.cvssMetricV30[0].cvssData?.baseScore || 0;
        vector = metrics.cvssMetricV30[0].cvssData?.vectorString || "";
      } else if (metrics.cvssMetricV2?.length) {
        baseScore = metrics.cvssMetricV2[0].cvssData?.baseScore || 0;
        vector = metrics.cvssMetricV2[0].cvssData?.vectorString || "";
      }
      if (baseScore === 0) continue;

      const cpes = [];
      (cve.configurations || []).forEach(c => {
        (c.nodes || []).forEach(n => {
          (n.cpeMatch || []).forEach(m => { if (m.criteria) cpes.push(m.criteria); });
        });
      });
      const cwes = [];
      (cve.weaknesses || []).forEach(w => {
        (w.description || []).forEach(d => {
          if (d.value && !d.value.includes("noinfo") && !d.value.includes("Other")) cwes.push(d.value);
        });
      });

      const fullText = desc + " " + cpes.join(" ");
      const domain = classifyDomain(fullText);
      const { surface, netPath } = inferAttackSurface(vector, desc);
      const isKEV = kevSet.has(cve.id);

      let product = "";
      if (cpes.length > 0) {
        const p = cpes[0].split(":");
        if (p.length >= 5) product = `${p[3]}:${p[4]}${p[5] && p[5] !== "*" ? ":" + p[5] : ""}`;
      }
      if (!product) {
        const m = desc.match(/(?:in|of|for|affecting)\s+([A-Z][\w\s.-]+?)(?:\s+(?:before|prior|through|allows|could|may|is|has|via|version))/i);
        product = m ? m[1].trim() : "";
      }

      allCVEs.set(cve.id, {
        cve_id: cve.id,
        published: cve.published?.split("T")[0] || "",
        modified: cve.lastModified?.split("T")[0] || "",
        description: desc,
        cvss_base_score: baseScore,
        cvss_vector: vector,
        cwe_ids: cwes,
        cpe_matches: cpes.slice(0, 5),
        affected_product: product,
        ecu_domain: domain,
        attack_surface: surface,
        network_path: netPath,
        exploit_maturity: isKEV ? "active_exploitation" : "unknown",
        kev_listed: isKEV,
        source_feeds: isKEV ? ["NVD", "CISA_KEV"] : ["NVD"],
        safety_criticality: ECU_ASIL[domain] || "QM",
      });
      added++;
    }
    console.log(`  -> ${items.length} received, ${added} new (total: ${allCVEs.size})`);
    if (i < KEYWORDS.length - 1) await sleep(2000);
  }

  const output = {
    generated_at: new Date().toISOString(),
    generator: "Auto-VIA CVE Database Builder v2.5",
    total_cves: allCVEs.size,
    kev_count: kevSet.size,
    keywords_used: KEYWORDS.length,
    vulnerabilities: Array.from(allCVEs.values()),
  };

  const outPath = path.join(__dirname, '..', 'public', 'cve-database.json');
  fs.writeFileSync(outPath, JSON.stringify(output));
  const sizeMB = (Buffer.byteLength(JSON.stringify(output)) / 1024 / 1024).toFixed(2);

  console.log(`\n=== Database built: ${allCVEs.size} CVEs ===`);
  console.log(`KEV matches: ${Array.from(allCVEs.values()).filter(v => v.kev_listed).length}`);
  console.log(`File size: ${sizeMB} MB`);
  console.log(`Saved to: ${outPath}`);
}

main().catch(console.error);
