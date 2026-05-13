// /api/analytics.js — Receives events from ALL Auto-VIA users
// Stores aggregated metrics in Upstash Redis (free tier)
// No authentication needed — this is a write-only endpoint
// The data it collects: event type, country (from timezone), timestamp, visitor_id
// It does NOT collect: IP addresses, user agents, or any PII

const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

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
  // CORS headers for your domain
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });

  try {
    const { event, country, meta, visitor_id, is_returning, visit_count } = req.body;

    if (!event) return res.status(400).json({ error: "Missing event" });

    const today = new Date().toISOString().split("T")[0];
    const month = today.slice(0, 7);
    const ts = new Date().toISOString();

    // Pipeline: batch multiple Redis commands in one request
    const pipeline = [
      // Total counters
      ["HINCRBY", "autovia:totals", "total_events", 1],
      ["HINCRBY", "autovia:totals", `total_${event}`, 1],

      // Daily activity
      ["HINCRBY", "autovia:daily", today, 1],

      // Monthly activity
      ["HINCRBY", "autovia:monthly", month, 1],

      // Country tracking
      ...(country && country !== "XX"
        ? [["HINCRBY", "autovia:countries", country, 1]]
        : []),

      // Update last_seen
      ["HSET", "autovia:totals", "last_seen", ts],
    ];

    // Set first_seen only once
    const firstSeen = await redis(["HGET", "autovia:totals", "first_seen"]);
    if (!firstSeen.result) {
      pipeline.push(["HSET", "autovia:totals", "first_seen", ts]);
    }

    // ── Returning user tracking ──────────────────────────────────
    // Track unique visitors via Redis Set
    if (visitor_id) {
      pipeline.push(["SADD", "autovia:visitors", visitor_id]);
    }

    // Track returning vs new sessions
    if (event === "session_start") {
      if (is_returning) {
        pipeline.push(["HINCRBY", "autovia:totals", "returning_sessions", 1]);
      } else {
        pipeline.push(["HINCRBY", "autovia:totals", "new_sessions", 1]);
      }
      // Store per-visitor metadata
      if (visitor_id) {
        pipeline.push([
          "HSET",
          `autovia:visitor:${visitor_id}`,
          "last_seen", ts,
          "visit_count", String(visit_count || 1),
          "country", country || "XX",
        ]);
      }
    }

    // Event-specific tracking
    if (event === "cve_view" && meta?.cve_id) {
      pipeline.push(["SADD", "autovia:unique_cves", meta.cve_id]);
    }

    if (event === "ecu_analyzed" && meta?.domain) {
      pipeline.push(["HINCRBY", "autovia:ecu_domains", meta.domain, 1]);
    }

    if (event === "priority_viewed" && meta?.tier) {
      pipeline.push(["HINCRBY", "autovia:priorities", meta.tier, 1]);
    }

    if (event === "view_change" && meta?.view) {
      pipeline.push(["HINCRBY", "autovia:features", meta.view, 1]);
    }

    if (event === "live_search" && meta?.query) {
      pipeline.push([
        "LPUSH",
        "autovia:searches",
        JSON.stringify({ q: meta.query, t: today }),
      ]);
      pipeline.push(["LTRIM", "autovia:searches", 0, 199]);
    }

    if (event === "peak_avrs" && meta?.count) {
      const currentPeak = await redis([
        "HGET",
        "autovia:totals",
        "peak_concurrent_avrs",
      ]);
      if (!currentPeak.result || meta.count > parseInt(currentPeak.result)) {
        pipeline.push([
          "HSET",
          "autovia:totals",
          "peak_concurrent_avrs",
          meta.count,
        ]);
      }
    }

    // Audit log entry (hash-chained)
    const prevHash = await redis(["HGET", "autovia:totals", "audit_chain_head"]);
    const auditEntry = {
      ts,
      ev: event,
      co: country || "XX",
      vid: visitor_id || "unknown",
      ret: !!is_returning,
      prev: prevHash.result || "genesis",
    };
    const entryStr = JSON.stringify(auditEntry);
    // SHA-256 hash using Node.js crypto
    const crypto = await import("crypto");
    const hash = crypto
      .createHash("sha256")
      .update(entryStr)
      .digest("hex");

    pipeline.push([
      "LPUSH",
      "autovia:audit_log",
      JSON.stringify({ ...auditEntry, hash }),
    ]);
    pipeline.push(["LTRIM", "autovia:audit_log", 0, 999]);
    pipeline.push(["HSET", "autovia:totals", "audit_chain_head", hash]);

    // Execute pipeline
    for (const cmd of pipeline) {
      await redis(cmd);
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error("Analytics error:", err);
    return res.status(500).json({ error: "Internal error" });
  }
}
