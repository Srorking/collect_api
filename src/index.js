// collect-api/src/index.js
// Collect API — batch /collect -> PostgreSQL (Render-ready)
// - Strong CORS (2xx/4xx/5xx + preflight)
// - Lazy DB pool (no crash if DATABASE_URL missing)
// - MOCK_MODE supported
// - Server-side domain enforcement using projects.allowed_domains + allow_subdomains
// - Adds per-event UUID (fixes: null value in column "id" of events_raw)
// - ✅ NEW: /bootstrap endpoint to allow/deny SDK download BEFORE it loads

import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import pg from "pg";
import crypto from "crypto";


app.get("/bootstrap", async (req, res) => {
  try {
    const project_id = req.query?.pid ? String(req.query.pid) : "";
    if (!isUuid(project_id)) return res.status(400).json({ allow: false, error: "invalid_pid" });

    // إذا DB مو موجودة => منع (أمان)
    if (!process.env.DATABASE_URL || process.env.MOCK_MODE === "1") {
      return res.status(200).json({ allow: false, error: "db_not_ready" });
    }

    const p = getPool();
    if (!p) return res.status(200).json({ allow: false, error: "db_not_configured" });

    // جلب المشروع
    const proj = await p.query(
      "select id, is_active, allowed_domains, allow_subdomains from projects where id = $1",
      [project_id]
    );

    if (!proj.rowCount) return res.status(200).json({ allow: false, error: "project_not_found" });
    if (!proj.rows[0].is_active) return res.status(200).json({ allow: false, error: "project_inactive" });

    const { allowed_domains, allow_subdomains } = proj.rows[0];

    // نفس منطق التحقق من الدومين
    const origin = req.headers.origin ? String(req.headers.origin) : "";
    const referer = req.headers.referer ? String(req.headers.referer) : "";

    const originHost = origin ? hostFromUrl(origin) : "";
    const refererHost = referer ? hostFromUrl(referer) : "";
    const incomingHost = originHost || refererHost;

    const ok = isAllowedHost({
      host: incomingHost,
      allowedDomains: allowed_domains,
      allowSubdomains: !!allow_subdomains,
    });

    // ✅ إذا مسموح: allow=true
    return res.status(200).json({ allow: ok });
  } catch (e) {
    return res.status(200).json({ allow: false, error: "server_error" });
  }
});



dotenv.config();

const { Pool } = pg;

const app = express();
const port = process.env.PORT || 4000;

// -------------------- Trust proxy (Render / Cloudflare) --------------------
app.set("trust proxy", true);

// -------------------- CORS --------------------
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

// -------------------- Body parsers --------------------
app.use(express.json({ limit: "1mb" }));
app.use(express.text({ type: ["text/plain", "application/json"], limit: "1mb" }));

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
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUuid(v) {
  return typeof v === "string" && UUID_RE.test(v);
}

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

function getClientIp(req) {
  const cf = req.headers["cf-connecting-ip"];
  if (cf) return String(cf);

  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();

  return req.ip || null;
}

// domain helpers
function hostFromUrl(url) {
  try {
    const u = new URL(url);
    return (u.hostname || "").toLowerCase();
  } catch {
    return "";
  }
}

function isAllowedHost({ host, allowedDomains, allowSubdomains }) {
  const h = (host || "").toLowerCase();
  if (!h) return false;

  // IMPORTANT: empty list => deny all
  if (!Array.isArray(allowedDomains) || allowedDomains.length === 0) return false;

  for (const dRaw of allowedDomains) {
    const d = String(dRaw || "").toLowerCase().trim();
    if (!d) continue;

    if (h === d) return true;
    if (allowSubdomains && h.endsWith("." + d)) return true;
  }
  return false;
}

function getIncomingHost(req) {
  const origin = req.headers.origin ? String(req.headers.origin) : "";
  const referer = req.headers.referer ? String(req.headers.referer) : "";

  const originHost = origin ? hostFromUrl(origin) : "";
  const refererHost = referer ? hostFromUrl(referer) : "";

  return originHost || refererHost || "";
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

// ✅ NEW: bootstrap (gate) — this decides if SDK is allowed to download
// Example: GET /bootstrap?pid=<project_uuid>
app.get("/bootstrap", async (req, res) => {
  const project_id = String(req.query.pid || "").trim();
  if (!isUuid(project_id)) {
    return res.status(400).json({ allow: false, error: "invalid_project_id" });
  }

  // If DB missing => safest: deny (because you want no download for unknown)
  if (!process.env.DATABASE_URL || process.env.MOCK_MODE === "1") {
    return res.status(403).json({ allow: false, error: "service_not_ready" });
  }

  const p = getPool();
  if (!p) return res.status(403).json({ allow: false, error: "db_not_configured" });

  try {
    const proj = await p.query(
      "select id, allowed_domains, allow_subdomains from projects where id = $1 and is_active = true",
      [project_id]
    );
    if (!proj.rowCount) return res.status(403).json({ allow: false, error: "project_inactive" });

    const { allowed_domains, allow_subdomains } = proj.rows[0];

    const host = getIncomingHost(req);

    const ok = isAllowedHost({
      host,
      allowedDomains: allowed_domains,
      allowSubdomains: !!allow_subdomains,
    });

    if (!ok) {
      return res.status(403).json({ allow: false, error: "domain_not_allowed", host: host || null });
    }

    return res.json({ allow: true });
  } catch (err) {
    console.error("BOOTSTRAP_ERROR:", err);
    return res.status(500).json({ allow: false, error: "server_error" });
  }
});

app.post("/collect", async (req, res) => {
  const body = parseBody(req);
  if (!body) return res.status(400).json({ error: "invalid_json" });

  const { project_id, events, sent_at } = body;

  if (!isUuid(project_id)) return res.status(400).json({ error: "invalid_project_id" });
  if (!Array.isArray(events)) return res.status(400).json({ error: "events_required" });
  if (events.length > 200) return res.status(400).json({ error: "events_too_many" });

  const ip = getClientIp(req);

  // MOCK MODE
  if (!process.env.DATABASE_URL || process.env.MOCK_MODE === "1") {
    console.log("[MOCK] /collect batch:", {
      project_id,
      sent_at,
      events_count: events.length,
      origin: req.headers.origin || null,
      referer: req.headers.referer || null,
      sample_event: events[0]
        ? {
            event_name: events[0].event_name,
            event_ts: events[0].event_ts,
            page_url: events[0].page_url,
            user_id: events[0].user_id,
            anonymous_id: events[0].anonymous_id,
          }
        : null,
    });
    return res.status(204).send();
  }

  const p = getPool();
  if (!p) return res.status(503).json({ error: "db_not_configured" });

  try {
    const proj = await p.query(
      "select id, allowed_domains, allow_subdomains from projects where id = $1 and is_active = true",
      [project_id]
    );
    if (!proj.rowCount) return res.status(403).json({ error: "project_inactive" });

    const { allowed_domains, allow_subdomains } = proj.rows[0];

    const host = getIncomingHost(req);
    if (
      !isAllowedHost({
        host,
        allowedDomains: allowed_domains,
        allowSubdomains: !!allow_subdomains,
      })
    ) {
      return res.status(403).json({
        error: "domain_not_allowed",
        host: host || null,
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

      const eventId = crypto.randomUUID();

      const context = ev.context && typeof ev.context === "object" ? ev.context : {};
      context.ip = ip;

      const placeholders = [
        `$${idx++}`, // id
        `$${idx++}`, // project_id
        `$${idx++}`, // event_name
        `to_timestamp($${idx++}/1000.0)`, // event_ts
        "now()", // received_at
        `$${idx++}`, // anonymous_id
        `$${idx++}`, // session_id
        `$${idx++}`, // user_id
        `$${idx++}`, // page_url
        `$${idx++}`, // page_path
        `$${idx++}`, // page_title
        `$${idx++}`, // referrer
        `$${idx++}`, // previous_url
        `$${idx++}::jsonb`, // context
        `$${idx++}::jsonb`, // properties
        `$${idx++}::jsonb`, // web_vitals
      ];

      rows.push(`(${placeholders.join(",")})`);

      values.push(
        eventId,
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
        context || {},
        ev.properties || {},
        ev.web_vitals || {}
      );
    }

    const sql = `
      insert into events_raw (
        id,
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

// -------------------- Start --------------------
app.listen(port, () => {
  console.log(`Collect API running on port ${port}`);
});

process.on("SIGTERM", async () => {
  try {
    if (pool) await pool.end();
  } catch {}
  process.exit(0);
});