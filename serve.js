// server.js — DNS Mail Checker
// Node.js + Express app that checks MX, SPF, DKIM, DMARC, and IPs for a domain.

const express = require("express");
const dns = require("dns").promises;
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// GET /api/dns?domain=example.com
app.get("/api/dns", async (req, res) => {
  const domain = (req.query.domain || "").trim();
  if (!domain) return res.status(400).json({ error: "Domain missing" });

  if (!/^[a-zA-Z0-9.-]+$/.test(domain))
    return res.status(400).json({ error: "Invalid domain format" });

  try {
    // 1. MX records
    let mxRecords = [];
    try {
      mxRecords = await dns.resolveMx(domain);
      mxRecords.sort((a, b) => a.priority - b.priority);
    } catch {
      mxRecords = [];
    }

    // 2. TXT records (SPF, DKIM, etc.)
    let txtRecords = [];
    try {
      const txt = await dns.resolveTxt(domain);
      txtRecords = txt.map(t => t.join(""));
    } catch {
      txtRecords = [];
    }

    // 3. DMARC record (_dmarc.domain)
    let dmarcRecords = [];
    try {
      const txt = await dns.resolveTxt("_dmarc." + domain);
      dmarcRecords = txt.map(t => t.join(""));
    } catch {
      dmarcRecords = [];
    }

    // 4. Resolve A and AAAA for domain
    const domainA = (await dns.resolve4(domain).catch(() => []));
    const domainAAAA = (await dns.resolve6(domain).catch(() => []));

    // 5. Resolve A/AAAA for each MX
    const mxWithIPs = await Promise.all(mxRecords.map(async (r) => {
      const host = r.exchange;
      const A = await dns.resolve4(host).catch(() => []);
      const AAAA = await dns.resolve6(host).catch(() => []);
      return { ...r, A, AAAA };
    }));

    res.json({
      domain,
      domainAddresses: { A: domainA, AAAA: domainAAAA },
      mx: mxWithIPs,
      txt: txtRecords,
      dmarc: dmarcRecords,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DNS query failed" });
  }
});

// Simple frontend
app.get("/", (req, res) => {
  res.setHeader("Content-Type", "text/html");
  res.end(`
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>DNS Mail Checker</title>
<style>
  body { font-family: sans-serif; background: #f7f9fc; padding: 20px; color: #222; }
  h1 { color: #2563eb; }
  input { padding: 10px; width: 300px; border-radius: 6px; border: 1px solid #ccc; }
  button { padding: 10px; background: #2563eb; color: white; border: none; border-radius: 6px; margin-left: 5px; }
  pre { background: #1e293b; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow: auto; }
</style>
</head>
<body>
  <h1>DNS Mail Checker</h1>
  <p>Enter a domain to check its mail DNS configuration:</p>
  <input id="domain" placeholder="example.com" />
  <button id="check">Check</button>
  <pre id="result">Results will appear here...</pre>
<script>
document.getElementById('check').onclick = async () => {
  const domain = document.getElementById('domain').value.trim();
  if(!domain) return alert('Enter a domain!');
  document.getElementById('result').textContent = 'Loading...';
  const r = await fetch('/api/dns?domain=' + encodeURIComponent(domain));
  const data = await r.json();
  document.getElementById('result').textContent = JSON.stringify(data, null, 2);
};
</script>
</body>
</html>
`);
});

app.listen(PORT, () =>
  console.log(`✅ DNS Mail Checker running → http://localhost:${PORT}`)
);
