// server.js — DNS Mail Checker API
const express = require("express");
const dns = require("dns").promises;
const cors = require("cors");

const app = express();
app.use(cors());
const PORT = process.env.PORT || 3000;

app.get("/api/dns", async (req, res) => {
  const domain = (req.query.domain || "").trim();
  if (!domain) return res.status(400).json({ error: "Missing domain" });

  if (!/^[a-zA-Z0-9.-]+$/.test(domain))
    return res.status(400).json({ error: "Invalid domain" });

  try {
    const mx = await dns.resolveMx(domain).catch(() => []);
    const txt = await dns.resolveTxt(domain).catch(() => []).map(t => t.join(""));
    const dmarc = await dns.resolveTxt("_dmarc." + domain).catch(() => []).map(t => t.join(""));
    const A = await dns.resolve4(domain).catch(() => []);
    const AAAA = await dns.resolve6(domain).catch(() => []);

    res.json({ domain, A, AAAA, mx, txt, dmarc, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DNS query failed" });
  }
});

app.listen(PORT, () => console.log(`✅ DNS Mail Checker API on port ${PORT}`));
