// ═══════════════════════════════════════════════════════════════════
// Auto-VIA AI Chat Proxy — Vercel Serverless Function
// File: api/chat.js
// ═══════════════════════════════════════════════════════════════════
//
// SETUP:
// 1. Place this file at: api/chat.js (next to your existing proxy.js)
// 2. Add your Anthropic API key in Vercel:
//    Dashboard → Your Project → Settings → Environment Variables
//    Key:   ANTHROPIC_API_KEY
//    Value: sk-ant-xxxxx (your key from console.anthropic.com)
// 3. Push to GitHub — Vercel auto-deploys
//
// The frontend calls /api/chat, this function adds your API key
// and forwards to Anthropic. Your key never reaches the browser.

export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    const body = req.body;

    // Validate request
    if (!body.messages || !Array.isArray(body.messages)) {
      return res.status(400).json({ error: "Missing or invalid 'messages' field" });
    }

    // Get API key from environment
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      return res.status(500).json({
        error: "ANTHROPIC_API_KEY not configured",
        fix: "Go to Vercel → Settings → Environment Variables → Add ANTHROPIC_API_KEY",
      });
    }

    // Forward to Anthropic
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: body.model || "claude-sonnet-4-20250514",
        max_tokens: body.max_tokens || 2000,
        system: body.system || "",
        messages: body.messages,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({
        error: `Anthropic API error: ${response.status}`,
        details: errorText,
      });
    }

    const data = await response.json();
    return res.status(200).json(data);
  } catch (error) {
    return res.status(500).json({
      error: "Internal server error",
      message: error.message,
    });
  }
}
