// ═══════════════════════════════════════════════════════════════════
// Auto-VIA AI Chat Proxy — Gemini Free Tier
// File: api/chat.js
// ═══════════════════════════════════════════════════════════════════
//
// SETUP:
// 1. Go to https://aistudio.google.com/apikey → Create API Key (free, no credit card)
// 2. Go to Vercel Dashboard → Your Project → Settings → Environment Variables
//    Add: GEMINI_API_KEY = your key
// 3. Place this file at: api/chat.js (next to proxy.js)
// 4. Push to GitHub — Vercel auto-deploys
//
// FREE TIER LIMITS (Gemini 2.5 Flash):
// - 10 requests per minute
// - 250 requests per day
// - No credit card required

export default async function handler(req, res) {
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { system, messages } = req.body;

    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: "Missing or invalid 'messages' field" });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({
        error: "GEMINI_API_KEY not configured",
        fix: "Get a free key at https://aistudio.google.com/apikey then add it in Vercel → Settings → Environment Variables",
      });
    }

    // Convert messages from our format to Gemini format
    // Our format: [{role:"user", content:"hello"}, {role:"assistant", content:"hi"}]
    // Gemini:     [{role:"user", parts:[{text:"hello"}]}, {role:"model", parts:[{text:"hi"}]}]
    const geminiContents = messages.map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: [{ text: m.content }],
    }));

    // Prepend system instruction as first user message if provided
    const systemInstruction = system
      ? { role: "user", parts: [{ text: system }] }
      : null;

    const geminiBody = {
      contents: systemInstruction
        ? [
            systemInstruction,
            {
              role: "model",
              parts: [
                {
                  text: "Understood. I am the Auto-VIA AI Analyst. I will follow these instructions for all subsequent responses.",
                },
              ],
            },
            ...geminiContents,
          ]
        : geminiContents,
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 2048,
      },
    };

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(geminiBody),
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({
        error: `Gemini API error: ${response.status}`,
        details: errorText,
      });
    }

    const data = await response.json();

    // Extract text from Gemini response and convert to Anthropic-compatible format
    // so the frontend doesn't need to change its response parsing
    const text =
      data.candidates?.[0]?.content?.parts?.map((p) => p.text).join("") || "";

    // Return in Anthropic-compatible format for frontend compatibility
    return res.status(200).json({
      content: [{ type: "text", text }],
    });
  } catch (error) {
    return res.status(500).json({
      error: "Internal server error",
      message: error.message,
    });
  }
}
