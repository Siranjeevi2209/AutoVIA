// /api/analytics-admin.js — Returns aggregated analytics for the admin dashboard
// Protected: requires ?secret=autovia query param (change this to your own secret)
// This endpoint reads from Upstash Redis and returns the full analytics picture

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

// ⚠️ CHANGE THIS to your own secret — this is what protects your data
const ADMIN_SECRET = process.env.ANALYTICS_ADMIN_SECRET || "autovia";

async function redis(command) {
  const res = await fetch(`${UPSTASH_URL}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${UPSTASH_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(command),
  });
  return res.json();
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET") return res.status(405).json({ error: "GET only" });

  // Auth check
  const { secret } = req.query;
  if (secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: "Unauthorized" });
  }

  try {
    // Fetch all data from Redis
    const [
      totals,
      countries,
      daily,
      monthly,
      ecuDomains,
      priorities,
      features,
      uniqueCveCount,
      uniqueVisitorCount,
      searches,
      auditLog,
    ] = await Promise.all([
      redis(["HGETALL", "autovia:totals"]),
      redis(["HGETALL", "autovia:countries"]),
      redis(["HGETALL", "autovia:daily"]),
      redis(["HGETALL", "autovia:monthly"]),
      redis(["HGETALL", "autovia:ecu_domains"]),
      redis(["HGETALL", "autovia:priorities"]),
      redis(["HGETALL", "autovia:features"]),
      redis(["SCARD", "autovia:unique_cves"]),
      redis(["SCARD", "autovia:visitors"]),
      redis(["LRANGE", "autovia:searches", 0, 199]),
      redis(["LRANGE", "autovia:audit_log", 0, 499]),
    ]);

    // Parse HGETALL results (returns flat array: [key, value, key, value, ...])
    function parseHash(result) {
      const obj = {};
      const arr = result.result || [];
      for (let i = 0; i < arr.length; i += 2) {
        obj[arr[i]] = arr[i + 1];
      }
      return obj;
    }

    const t = parseHash(totals);
    const c = parseHash(countries);
    const d = parseHash(daily);
    const m = parseHash(monthly);
    const ecu = parseHash(ecuDomains);
    const pri = parseHash(priorities);
    const feat = parseHash(features);

    // Convert string counts to numbers
    function numHash(obj) {
      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        out[k] = isNaN(v) ? v : parseInt(v);
      }
      return out;
    }

    // Parse audit log entries
    const parsedAuditLog = (auditLog.result || []).map((entry) => {
      try { return JSON.parse(entry); } catch { return entry; }
    });

    // Parse search queries
    const parsedSearches = (searches.result || []).map((entry) => {
      try { return JSON.parse(entry); } catch { return entry; }
    });

    const analytics = {
      total_events: parseInt(t.total_events) || 0,
      total_sessions: parseInt(t.total_session_start) || 0,
      total_analyses: parseInt(t.total_analysis_complete) || 0,
      total_cve_views: parseInt(t.total_cve_view) || 0,
      total_avr_downloads: parseInt(t.total_avr_download) || 0,
      total_tara_exports: parseInt(t.total_tara_export) || 0,
      total_csv_exports: parseInt(t.total_csv_export) || 0,
      total_json_exports: parseInt(t.total_json_export) || 0,
      total_ai_queries: parseInt(t.total_ai_query) || 0,
      total_live_searches: parseInt(t.total_live_search) || 0,
      total_manual_assessments: parseInt(t.total_manual_assess) || 0,
      peak_concurrent_avrs: parseInt(t.peak_concurrent_avrs) || 0,
      unique_cves_reviewed: uniqueCveCount.result || 0,

      // ── Returning user metrics ──
      unique_visitors: uniqueVisitorCount.result || 0,
      returning_sessions: parseInt(t.returning_sessions) || 0,
      new_sessions: parseInt(t.new_sessions) || 0,

      first_seen: t.first_seen || new Date().toISOString(),
      last_seen: t.last_seen || new Date().toISOString(),
      audit_chain_head: t.audit_chain_head || null,
      countries: numHash(c),
      daily_activity: numHash(d),
      monthly_analyses: numHash(m),
      ecu_domains_analyzed: numHash(ecu),
      priority_tiers_viewed: numHash(pri),
      feature_usage: numHash(feat),
      search_queries: parsedSearches,
      audit_log: parsedAuditLog,
      visitor_ids: {}, // Kept empty — individual visitor data stays in Redis for privacy
    };

    return res.status(200).json(analytics);
  } catch (err) {
    console.error("Analytics admin error:", err);
    return res.status(500).json({ error: "Internal error" });
  }
}
