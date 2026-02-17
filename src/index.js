// Collect API — batch /collect -> PostgreSQL (Render-ready)
// ✅ Domain lock (exact + subdomains)
// ✅ project.is_active enforcement
// ✅ server-side IP injection to event.context.ip
// ✅ Strong CORS + preflight
// ✅ SINGLE /collect route

import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import pg from "pg";

dotenv.config();

const { Pool } = pg;
const app = express();
const port = process.env.PORT || 4000;

// -------------------- CORS --------------------
// Optional: CORS_ORIGINS="https://a.com,https://b.com"
// If empty -> allow all origins (reflect origin)
const ALLOW_LIST = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOW_LIST.length === 0) return cb(null, true);
    if (ALLOW_LIST.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  methods: ["POST", "OPTIONS", "GET"],
  allowedHeaders: ["Content-Type", "X-PT-Signature"],
  maxAge: 86400,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.text({ type: ["text/plain", "application/json"], limit: "1mb" }));

app.set("trust proxy", true);

// -------------------- DB pool (lazy) --------------------
let pool = null;

function getPool() {
  if (pool) return pool;

  const url = process.env.DATABASE_URL;
  if (!url) return null;

  const needsSSL = /sslmode=require/i.test(url);

  pool = new Pool({
    connectionString: url,
    ...(needsSSL ? { ssl: { rejectUnauthorized: false } } : {}),
  });

  return pool;
}

// -------------------- Helpers --------------------
function parseBody(req) {
  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      return null;
    }
  }
  return req.body;
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(v) {
  return typeof v === "string" && UUID_RE.test(v);
}

function getClientIp(req) {
  const cf = req.headers["cf-connecting-ip"];
  if (cf) return String(cf);

  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();

  return req.ip || null;
}

function getOriginHost(req) {
  try {
    const origin = req.headers.origin;
    if (origin) return new URL(String(origin)).hostname.toLowerCase();

    // fallback: some clients might send referer
    const ref = req.headers.referer || req.headers.referrer;
    if (ref) return new URL(String(ref)).hostname.toLowerCase();
  } catch {}
  return null;
}

function normalizeDomain(d) {
  return String(d || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "") // remove path
    .replace(/:\d+$/, "") // remove port
    .replace(/^\./, "")   // ".example.com" -> "example.com"
    .replace(/\.$/, "");
}

function isSubdomainOf(host, root) {
  // host = shop.example.com, root = example.com  => true
  if (!host || !root) return false;
  if (host === root) return true;
  return host.endsWith("." + root);
}

function isAllowedHost(host, allowedDomains, allowSubdomains) {
  if (!host) return false;

  const list = Array.isArray(allowedDomains) ? allowedDomains : [];
  if (list.length === 0) return true; // ✅ if not configured => allow all (your choice)

  const h = normalizeDomain(host);

  for (const d of list) {
    const root = normalizeDomain(d);
    if (!root) continue;

    // exact
    if (h === root) return true;

    // subdomains
    if (allowSubdomains && isSubdomainOf(h, root)) return true;
  }

  return false;
}

// -------------------- Routes --------------------
app.get("/health", async (_req, res) => {
  try {
    const p = getPool();
    if (p) await p.query("select 1");
    return res.status(200).json({ ok: true, db: p ? "up" : "not_configured" });
  } catch {
    return res.status(200).json({ ok: true, db: "down" });
  }
});

app.post("/collect", async (req, res) => {
  const body = parseBody(req);
  if (!body) return res.status(400).json({ error: "invalid_json" });

  const { project_id, events, sent_at } = body;

  if (!isUuid(project_id)) return res.status(400).json({ error: "invalid_project_id" });
  if (!Array.isArray(events)) return res.status(400).json({ error: "events_required" });
  if (events.length > 200) return res.status(400).json({ error: "events_too_many" });

  const originHost = getOriginHost(req);
  const ip = getClientIp(req);

  // ✅ MOCK MODE (still enforces domain lock only if you want — here we allow)
  if (!process.env.DATABASE_URL || process.env.MOCK_MODE === "1") {
    for (const ev of events) {
      if (!ev) continue;
      ev.context = ev.context && typeof ev.context === "object" ? ev.context : {};
      ev.context.ip = ip;
      ev.context.origin_host = originHost;
    }

    console.log("[MOCK] /collect batch:", {
      project_id,
      sent_at,
      events_count: events.length,
      originHost,
    });
    return res.status(204).send();
  }

  const p = getPool();
  if (!p) return res.status(503).json({ error: "db_not_configured" });

  try {
    // ✅ project must exist + active + allowed domains
    const proj = await p.query(
      "select id, is_active, allowed_domains, allow_subdomains from projects where id = $1",
      [project_id]
    );

    if (!proj.rowCount) return res.status(404).json({ error: "project_not_found" });

    const row = proj.rows[0];
    if (!row.is_active) return res.status(403).json({ error: "project_inactive" });

    const allowedDomains = row.allowed_domains || [];
    const allowSubdomains = row.allow_subdomains !== false;

    // ✅ Domain lock check
    const okDomain = isAllowedHost(originHost, allowedDomains, allowSubdomains);
    if (!okDomain) {
      return res.status(403).json({
        error: "domain_not_allowed",
        origin_host: originHost,
      });
    }

    const values = [];
    const rows = [];
    let idx = 1;

    for (const ev of events) {
      if (!ev || ev.project_id !== project_id) {
        return res.status(400).json({ error: "project_id_mismatch" });
      }
      if (typeof ev.event_name !== "string" || !ev.event_name) {
        return res.status(400).json({ error: "invalid_event_name" });
      }
      if (typeof ev.event_ts !== "number") {
        return res.status(400).json({ error: "invalid_event_ts" });
      }

      // ✅ inject ip + originHost
      ev.context = ev.context && typeof ev.context === "object" ? ev.context : {};
      ev.context.ip = ip;
      ev.context.origin_host = originHost;

      const placeholders = [
        `$${idx++}`,
        `$${idx++}`,
        `to_timestamp($${idx++}/1000.0)`,
        "now()",
        `$${idx++}`,
        `$${idx++}`,
        `$${idx++}`,
        `$${idx++}`,
        `$${idx++}`,
        `$${idx++}`,
        `$${idx++}`,
        `$${idx++}`,
        `$${idx++}::jsonb`,
        `$${idx++}::jsonb`,
        `$${idx++}::jsonb`,
      ];

      rows.push(`(${placeholders.join(",")})`);

      values.push(
        ev.project_id,
        ev.event_name,
        ev.event_ts,
        ev.anonymous_id || null,
        ev.session_id || null,
        ev.user_id || null,
        ev.page_url || null,
        ev.page_path || null,
        ev.page_title || null,
        ev.referrer || null,
        ev.previous_url || null,
        ev.context || {},
        ev.properties || {},
        ev.web_vitals || {}
      );
    }

    const sql = `
      insert into events_raw (
        project_id,
        event_name,
        event_ts,
        received_at,
        anonymous_id,
        session_id,
        user_id,
        page_url,
        page_path,
        page_title,
        referrer,
        previous_url,
        context,
        properties,
        web_vitals
      ) values ${rows.join(",")}
    `;

    await p.query(sql, values);
    return res.status(204).send();
  } catch (err) {
    console.error("COLLECT_ERROR:", err);
    return res.status(500).json({ error: "server_error" });
  }
});

app.listen(port, () => {
  console.log(`Collect API running on port ${port}`);
});

process.on("SIGTERM", async () => {
  try {
    if (pool) await pool.end();
  } catch {}
  process.exit(0);
});
