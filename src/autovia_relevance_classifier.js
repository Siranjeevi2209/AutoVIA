// ═══════════════════════════════════════════════════════════════════
// AUTOMOTIVE RELEVANCE CLASSIFIER  (data-driven, two-signal blend)
//   Loads the vocabulary from autovia_relevance_datasets.json and builds
//   weighted, WHOLE-WORD matchers once at module load.
//
//   P_auto = 0.625·P_cpe + 0.375·P_keyword
//   (your fixed weights α=0.50, β=0.30 renormalized over the two live
//    signals. When P_ml is added: 0.50·P_cpe + 0.30·P_keyword + 0.20·P_ml)
// ═══════════════════════════════════════════════════════════════════

import datasets from "./autovia_relevance_datasets.json";   // adjust path to where the JSON lives

// escape regex metacharacters so terms like "comma.ai" / "kuksa.val" match literally
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Group a signal's entries by weight, compile one whole-word regex per weight tier.
// global=true keeps the /g flag so keyword matches can be COUNTED; CPE only needs presence.
function buildTiers(entries, global) {
  const byWeight = new Map();
  for (const { term, weight } of entries) {
    if (!byWeight.has(weight)) byWeight.set(weight, []);
    byWeight.get(weight).push(escapeRegex(String(term).toLowerCase()));
  }
  return [...byWeight.entries()]
    .sort((a, b) => b[0] - a[0])                       // strongest tier first
    .map(([weight, terms]) => ({
      weight,
      regex: new RegExp("\\b(" + terms.join("|") + ")\\b", global ? "gi" : "i"),
    }));
}

const CPE_TIERS = buildTiers(datasets.cpe_products, false);  // presence test -> max weight
const KW_TIERS  = buildTiers(datasets.keyword_terms, true);  // counted -> saturating sum

// -- P_cpe : strongest automotive signal from the STRUCTURED CPE fields --
function scoreCPE(cpeList) {
  let best = 0;
  for (const cpe of (cpeList || [])) {
    const p = String(cpe).split(":");                  // cpe:2.3:a:vendor:product:...
    const tok = ((p[3] || "") + " " + (p[4] || "")).replace(/_/g, " ").toLowerCase();
    for (const { weight, regex } of CPE_TIERS) {
      if (regex.test(tok)) best = Math.max(best, weight);
    }
  }
  return best;                                          // 0..1
}

// -- P_keyword : weighted whole-word matches over the description prose --
function scoreKeyword(desc) {
  const t = String(desc || "").toLowerCase();
  let raw = 0;
  for (const { weight, regex } of KW_TIERS) {
    regex.lastIndex = 0;                                // reset stateful /g regex
    const m = t.match(regex);
    if (m) raw += weight * m.length;
  }
  return 1 - Math.exp(-raw);                            // saturating -> 0..1
}

// -- blend + decision --
const REL_THRESHOLD = 0.25;   // tune on real data; higher = more precision, lower = more recall
function automotiveRelevance(cpeList, desc) {
  const p_cpe = scoreCPE(cpeList);
  const p_keyword = scoreKeyword(desc);
  const p_auto = 0.625 * p_cpe + 0.375 * p_keyword;    // add 0.20*p_ml later (revert to .5/.3/.2)
  return {
    p_cpe: +p_cpe.toFixed(3),
    p_keyword: +p_keyword.toFixed(3),
    p_auto: +p_auto.toFixed(3),
    is_automotive: p_auto >= REL_THRESHOLD,
  };
}

export { scoreCPE, scoreKeyword, automotiveRelevance };
