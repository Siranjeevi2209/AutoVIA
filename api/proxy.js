export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const { source, keyword, resultsPerPage } = req.query;

  try {
    if (source === "kev") {
      const resp = await fetch(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
      );
      if (!resp.ok) return res.status(resp.status).json({ error: "KEV failed" });
      return res.status(200).json(await resp.json());
    }

    if (source === "nvd") {
      const apiKey = process.env.NVD_API_KEY || "";
      const perPage = resultsPerPage || "50";
      const url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" +
        encodeURIComponent(keyword || "qnx") + "&resultsPerPage=" + perPage;

      const resp = await fetch(url, {
        headers: apiKey ? { "apiKey": apiKey } : {}
      });

      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        return res.status(resp.status).json({
          error: "NVD returned " + resp.status,
          detail: text.substring(0, 200),
          keyPresent: !!apiKey
        });
      }

      return res.status(200).json(await resp.json());
    }

    if (source === "test") {
      return res.status(200).json({
        working: true,
        keyPresent: !!process.env.NVD_API_KEY,
        keyLength: (process.env.NVD_API_KEY || "").length
      });
    }

    return res.status(400).json({ error: "Use ?source=nvd or ?source=kev or ?source=test" });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}
