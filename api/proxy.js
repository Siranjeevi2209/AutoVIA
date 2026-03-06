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
      const kevResp = await fetch(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
      );
      if (!kevResp.ok) {
        return res.status(kevResp.status).json({ error: "KEV fetch failed" });
      }
      const kevData = await kevResp.json();
      return res.status(200).json(kevData);
    }

    if (source === "nvd") {
      const apiKey = process.env.VITE_NVD_API_KEY || "";
      const perPage = resultsPerPage || "50";
      let url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" +
        encodeURIComponent(keyword || "qnx") + "&resultsPerPage=" + perPage;

      if (apiKey) {
        url += "&apiKey=" + apiKey;
      }

      const nvdResp = await fetch(url, {
        headers: {
          "User-Agent": "AutoVIA/2.5 (Automotive Vulnerability Intelligence Aggregator)",
        },
      });

      if (!nvdResp.ok) {
        return res.status(nvdResp.status).json({ error: "NVD API returned " + nvdResp.status });
      }

      const nvdData = await nvdResp.json();
      return res.status(200).json(nvdData);
    }

    return res.status(400).json({ error: "Invalid source. Use ?source=nvd or ?source=kev" });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
