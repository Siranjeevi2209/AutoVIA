#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════
// Auto-VIA Static Analysis Generator
// File: scripts/generate-analysis.cjs
// ═══════════════════════════════════════════════════════════════════
//
// Generates pre-computed AI analysis for all CVEs in your database.
// Run this locally or via GitHub Actions on a schedule.
//
// USAGE:
//   ANTHROPIC_API_KEY=sk-ant-xxx node scripts/generate-analysis.cjs
//
// OUTPUT:
//   public/ai-analysis.json — loaded by the dashboard at runtime
//
// COST: ~$0.50-1.50 per full run depending on CVE count
// SCHEDULE: Run after each CVE database update

const fs = require("fs");
const path = require("path");

const API_KEY = process.env.ANTHROPIC_API_KEY;
if (!API_KEY) {
  console.error("ERROR: Set ANTHROPIC_API_KEY environment variable");
  process.exit(1);
}

const DB_PATH = path.join(__dirname, "..", "public", "cve-database.json");
const OUTPUT_PATH = path.join(__dirname, "..", "public", "ai-analysis.json");

// ── Helpers ───────────────────────────────────────────────────────
async function callClaude(systemPrompt, userPrompt, maxTokens = 1500) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Claude API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  return data.content?.map((c) => c.text || "").join("") || "";
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// ── ECU Domain Info ───────────────────────────────────────────────
const ECU_INFO = {
  braking: { full: "Electronic Braking", asil: "ASIL-D" },
  steering: { full: "Power Steering", asil: "ASIL-D" },
  powertrain: { full: "Powertrain / Engine", asil: "ASIL-C" },
  chassis: { full: "Chassis Control", asil: "ASIL-C" },
  adas: { full: "ADAS / Autonomous", asil: "ASIL-D" },
  gateway: { full: "Gateway ECU", asil: "ASIL-B" },
  telematics: { full: "Telematics Unit", asil: "ASIL-A" },
  infotainment: { full: "Infotainment / IVI", asil: "QM" },
  body: { full: "Body Control", asil: "QM" },
  diagnostics: { full: "Diagnostics", asil: "QM" },
};

const SYSTEM_PROMPT = `You are a senior automotive cybersecurity analyst specializing in ISO/SAE 21434 and UNECE WP.29 R155 compliance. You analyze CVE vulnerabilities in the context of vehicle electronic systems.

When analyzing vulnerabilities, always consider:
- The specific automotive impact (not generic IT impact)
- Safety implications based on the ECU domain and ASIL level
- Concrete remediation steps (firmware patch, network segmentation, ECU firewall rules, etc.)
- Relevant ISO/SAE 21434 clauses and UNECE R155 requirements
- Attack chain specifics in an automotive context

Be concise, technical, and actionable. No fluff.`;

// ── Generate per-CVE remediation summaries ────────────────────────
async function generateCVEAnalysis(vulns) {
  console.log(`\n── Generating per-CVE analysis for top ${Math.min(vulns.length, 50)} critical/high CVEs ──`);

  // Only analyze P0 and P1 — these are the ones engineers actually need help with
  const critical = vulns
    .filter((v) => v.priority_tier === "P0_critical" || v.priority_tier === "P1_high")
    .sort((a, b) => (b.ars || b.cvss_base_score || 0) - (a.ars || a.cvss_base_score || 0))
    .slice(0, 50);

  const analyses = {};
  for (let i = 0; i < critical.length; i++) {
    const v = critical[i];
    const ecuInfo = ECU_INFO[v.ecu_domain] || { full: v.ecu_domain, asil: "QM" };

    console.log(`  [${i + 1}/${critical.length}] ${v.cve_id} (${v.ecu_domain}, ARS: ${v.ars || "N/A"})`);

    try {
      const prompt = `Analyze this automotive CVE and provide a concise remediation brief:

CVE: ${v.cve_id}
Description: ${v.description || "No description available"}
CVSS Score: ${v.cvss_base_score || v.cvss_v4_base_score || "Unknown"}
ECU Domain: ${ecuInfo.full} (${ecuInfo.asil})
Attack Surface: ${v.attack_surface || "Unknown"}
Network Path: ${v.network_path || "Unknown"}
Exploit Maturity: ${v.exploit_maturity || "Unknown"}
KEV Listed: ${v.kev_listed ? "Yes" : "No"}
Affected Product: ${v.affected_product || "Unknown"}

Respond in this exact JSON format (no markdown, no backticks):
{"automotive_impact":"What specifically could go wrong in a vehicle (2-3 sentences)","attack_chain":"How an attacker would exploit this in an automotive context (2-3 sentences)","remediation":["Step 1","Step 2","Step 3"],"iso_clause":"Which ISO/SAE 21434 clause applies","urgency":"Critical/High/Medium with 1-sentence justification"}`;

      const text = await callClaude(SYSTEM_PROMPT, prompt, 800);

      // Try to parse JSON response
      try {
        // Clean potential markdown fences
        const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
        analyses[v.cve_id] = JSON.parse(clean);
      } catch {
        // If JSON parse fails, store as raw text
        analyses[v.cve_id] = { raw_analysis: text };
      }

      // Rate limiting — wait between requests
      await sleep(1500);
    } catch (err) {
      console.error(`    ERROR: ${err.message}`);
      analyses[v.cve_id] = { error: err.message };
      await sleep(3000); // Wait longer on errors
    }
  }

  return analyses;
}

// ── Generate domain-level risk summaries ──────────────────────────
async function generateDomainSummaries(vulns) {
  console.log("\n── Generating ECU domain risk summaries ──");

  const domains = {};
  vulns.forEach((v) => {
    if (!domains[v.ecu_domain]) domains[v.ecu_domain] = [];
    domains[v.ecu_domain].push(v);
  });

  const summaries = {};
  for (const [domain, dvulns] of Object.entries(domains)) {
    const ecuInfo = ECU_INFO[domain] || { full: domain, asil: "QM" };
    const p0 = dvulns.filter((v) => v.priority_tier === "P0_critical").length;
    const p1 = dvulns.filter((v) => v.priority_tier === "P1_high").length;
    const kev = dvulns.filter((v) => v.kev_listed).length;
    const surfaces = {};
    dvulns.forEach((v) => {
      surfaces[v.attack_surface] = (surfaces[v.attack_surface] || 0) + 1;
    });
    const topProducts = {};
    dvulns.forEach((v) => {
      if (v.affected_product) topProducts[v.affected_product] = (topProducts[v.affected_product] || 0) + 1;
    });
    const topProds = Object.entries(topProducts).sort((a, b) => b[1] - a[1]).slice(0, 5);

    console.log(`  ${ecuInfo.full} (${dvulns.length} CVEs)`);

    try {
      const prompt = `Generate a risk posture summary for this ECU domain:

Domain: ${ecuInfo.full}
ASIL: ${ecuInfo.asil}
Total CVEs: ${dvulns.length}
Critical (P0): ${p0}
High (P1): ${p1}
KEV Listed: ${kev}
Attack Surfaces: ${JSON.stringify(surfaces)}
Top Products: ${topProds.map(([p, c]) => `${p} (${c})`).join(", ") || "N/A"}

Respond in this exact JSON format (no markdown, no backticks):
{"risk_level":"Critical/High/Medium/Low","summary":"2-3 sentence risk posture summary","key_concerns":["concern 1","concern 2","concern 3"],"recommended_actions":["action 1","action 2","action 3"],"compliance_note":"1 sentence about ISO 21434 / R155 implications"}`;

      const text = await callClaude(SYSTEM_PROMPT, prompt, 600);
      try {
        const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
        summaries[domain] = JSON.parse(clean);
      } catch {
        summaries[domain] = { raw_analysis: text };
      }
      await sleep(1500);
    } catch (err) {
      console.error(`    ERROR: ${err.message}`);
      summaries[domain] = { error: err.message };
      await sleep(3000);
    }
  }

  return summaries;
}

// ── Generate overall risk report ──────────────────────────────────
async function generateOverallReport(vulns) {
  console.log("\n── Generating overall risk report ──");

  const tierCounts = {};
  vulns.forEach((v) => { tierCounts[v.priority_tier] = (tierCounts[v.priority_tier] || 0) + 1; });
  const domCounts = {};
  vulns.forEach((v) => { domCounts[v.ecu_domain] = (domCounts[v.ecu_domain] || 0) + 1; });
  const surfaceCounts = {};
  vulns.forEach((v) => { surfaceCounts[v.attack_surface] = (surfaceCounts[v.attack_surface] || 0) + 1; });
  const kevCount = vulns.filter((v) => v.kev_listed).length;

  const prompt = `Generate an executive risk report for an automotive CSMS based on this vulnerability data:

Total CVEs: ${vulns.length}
Priority: ${JSON.stringify(tierCounts)}
ECU Domains: ${JSON.stringify(domCounts)}
Attack Surfaces: ${JSON.stringify(surfaceCounts)}
KEV Listed: ${kevCount}

Respond in this exact JSON format (no markdown, no backticks):
{"executive_summary":"3-4 sentence overall risk assessment","risk_rating":"Critical/High/Medium/Low","top_risks":["risk 1","risk 2","risk 3","risk 4","risk 5"],"immediate_actions":["action 1","action 2","action 3"],"compliance_status":"2 sentences on ISO 21434 / UNECE R155 posture","trend_note":"1 sentence on whether risk is increasing/decreasing based on the data"}`;

  try {
    const text = await callClaude(SYSTEM_PROMPT, prompt, 800);
    const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    return JSON.parse(clean);
  } catch (err) {
    console.error(`  ERROR: ${err.message}`);
    return { error: err.message };
  }
}

// ── Main ──────────────────────────────────────────────────────────
async function main() {
  console.log("═══ Auto-VIA Static Analysis Generator ═══\n");

  // Load CVE database
  if (!fs.existsSync(DB_PATH)) {
    console.error(`ERROR: CVE database not found at ${DB_PATH}`);
    process.exit(1);
  }

  const db = JSON.parse(fs.readFileSync(DB_PATH, "utf-8"));
  const vulns = db.vulnerabilities || [];
  console.log(`Loaded ${vulns.length} vulnerabilities from database`);

  // Generate all analysis
  const cveAnalysis = await generateCVEAnalysis(vulns);
  const domainSummaries = await generateDomainSummaries(vulns);
  const overallReport = await generateOverallReport(vulns);

  // Write output
  const output = {
    generated_at: new Date().toISOString(),
    version: "1.0",
    total_cves_analyzed: Object.keys(cveAnalysis).length,
    cve_analysis: cveAnalysis,
    domain_summaries: domainSummaries,
    overall_report: overallReport,
  };

  fs.writeFileSync(OUTPUT_PATH, JSON.stringify(output, null, 2));
  console.log(`\n✓ Analysis written to ${OUTPUT_PATH}`);
  console.log(`  - ${Object.keys(cveAnalysis).length} CVE remediation briefs`);
  console.log(`  - ${Object.keys(domainSummaries).length} domain risk summaries`);
  console.log(`  - 1 overall risk report`);
}

main().catch((err) => {
  console.error("FATAL:", err);
  process.exit(1);
});
