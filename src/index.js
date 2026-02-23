// collect-api/src/index.js
// Collect API — batch /collect -> PostgreSQL (Render-ready)
// - Strong CORS (2xx/4xx/5xx + preflight)
// - Lazy DB pool (no crash if DATABASE_URL missing)
// - MOCK_MODE supported
// - Server-side domain enforcement using projects.allowed_domains + allow_subdomains
// - Adds per-event UUID (fixes: null value in column "id" of events_raw)
// - /bootstrap endpoint to allow/deny SDK download BEFORE it loads
// - ✅ AES-GCM optional encrypted payload support via /crypto/bootstrap

import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import pg from "pg";
import crypto from "crypto";

dotenv.config();

const { Pool } = pg;

const app = express();
const port = process.env.PORT || 4000;

// -------------------- Trust proxy (Render / Cloudflare) --------------------
app.set("trust proxy", true);

// -------------------- CORS --------------------
// Optional env: CORS_ORIGINS="https://a.com,https://b.com"
// If not set -> allow all origins (reflect origin)
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

// IMPORTANT: CORS must be before helmet/routes, and OPTIONS must be global
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// Helmet (disable CORP to avoid any cross-origin resource policy surprises)
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
  // Cloudflare
  const cf = req.headers["cf-connecting-ip"];
  if (cf) return String(cf);

  // Proxies
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

  // IMPORTANT: empty list => deny all (safer)
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

// -------------------- AES-GCM session store --------------------
// NOTE: This is in-memory. On multi-instance you need Redis/shared store.
const cryptoSessions = new Map(); // kid -> { key: Buffer, exp: number }

function b64(buf) {
  return Buffer.from(buf).toString("base64");
}
function b64ToBuf(str) {
  return Buffer.from(String(str || ""), "base64");
}
function cleanupCryptoSessions() {
  const now = Date.now();
  for (const [kid, s] of cryptoSessions.entries()) {
    if (!s || !s.exp || now > s.exp) cryptoSessions.delete(kid);
  }
}
setInterval(cleanupCryptoSessions, 60 * 1000).unref?.();

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

// ✅ Gate BEFORE downloading SDK
// Example: GET /bootstrap?pid=<project_uuid>
app.get("/bootstrap", async (req, res) => {
  const project_id = String(req.query.pid || "").trim();
  if (!isUuid(project_id)) {
    return res.status(400).json({ allow: false, error: "invalid_project_id" });
  }

  // If DB missing => safest: deny (because you want no download for unknown)
  if (!process.env.DATABASE_URL || process.env.MOCK_MODE === "1") {
    return res.status(200).json({ allow: false, error: "service_not_ready" });
  }

  const p = getPool();
  if (!p) return res.status(200).json({ allow: false, error: "db_not_configured" });

  try {
    const proj = await p.query(
      "select id, allowed_domains, allow_subdomains from projects where id = $1 and is_active = true",
      [project_id]
    );
    if (!proj.rowCount) return res.status(200).json({ allow: false, error: "project_inactive" });

    const { allowed_domains, allow_subdomains } = proj.rows[0];
    const host = getIncomingHost(req);

    const ok = isAllowedHost({
      host,
      allowedDomains: allowed_domains,
      allowSubdomains: !!allow_subdomains,
    });

    return res.status(200).json(ok ? { allow: true } : { allow: false, error: "domain_not_allowed", host: host || null });
  } catch (err) {
    console.error("BOOTSTRAP_ERROR:", err);
    return res.status(200).json({ allow: false, error: "server_error" });
  }
});

// ✅ AES key bootstrap (temporary session key)
// Example: GET /crypto/bootstrap?pid=<project_uuid>
app.get("/crypto/bootstrap", async (req, res) => {
  const project_id = String(req.query.pid || "").trim();
  if (!isUuid(project_id)) return res.status(400).json({ error: "invalid_project_id" });

  // If DB not ready => deny issuing key
  if (!process.env.DATABASE_URL || process.env.MOCK_MODE === "1") {
    return res.status(403).json({ error: "service_not_ready" });
  }

  const p = getPool();
  if (!p) return res.status(403).json({ error: "db_not_configured" });

  try {
    // OPTIONAL: enforce same rules as /bootstrap before issuing key
    const proj = await p.query(
      "select id, allowed_domains, allow_subdomains from projects where id = $1 and is_active = true",
      [project_id]
    );
    if (!proj.rowCount) return res.status(403).json({ error: "project_inactive" });

    const { allowed_domains, allow_subdomains } = proj.rows[0];
    const host = getIncomingHost(req);

    const ok = isAllowedHost({
      host,
      allowedDomains: allowed_domains,
      allowSubdomains: !!allow_subdomains,
    });

    if (!ok) return res.status(403).json({ error: "domain_not_allowed", host: host || null });

    const kid = crypto.randomUUID();
    const key = crypto.randomBytes(32); // AES-256 key
    const exp = Date.now() + 5 * 60 * 1000; // 5 minutes

    cryptoSessions.set(kid, { key, exp });

    return res.json({
      kid,
      key: b64(key),
      exp,
    });
  } catch (e) {
    console.error("CRYPTO_BOOTSTRAP_ERROR:", e);
    return res.status(500).json({ error: "server_error" });
  }
});

app.post("/collect", async (req, res) => {
  let body = parseBody(req);
  if (!body) return res.status(400).json({ error: "invalid_json" });

  // ✅ If encrypted payload, decrypt first
  if (body.encrypted === true) {
    const kid = String(body.kid || "");
    const session = cryptoSessions.get(kid);

    if (!session) return res.status(403).json({ error: "invalid_kid" });
    if (Date.now() > session.exp) return res.status(403).json({ error: "key_expired" });

    try {
      const iv = b64ToBuf(body.iv);
      const aad = b64ToBuf(body.aad);
      const raw = b64ToBuf(body.ciphertext);

      if (iv.length !== 12) return res.status(400).json({ error: "invalid_iv" });
      if (raw.length < 16) return res.status(400).json({ error: "invalid_ciphertext" });

      // WebCrypto AES-GCM returns ciphertext||tag (tag 16 bytes)
      const tag = raw.subarray(raw.length - 16);
      const enc = raw.subarray(0, raw.length - 16);

      const decipher = crypto.createDecipheriv("aes-256-gcm", session.key, iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);

      const decrypted = Buffer.concat([decipher.update(enc), decipher.final()]);
      body = JSON.parse(decrypted.toString("utf8"));
    } catch (e) {
      return res.status(400).json({ error: "decryption_failed" });
    }
  }

  const { project_id, events, sent_at } = body;

  if (!isUuid(project_id)) return res.status(400).json({ error: "invalid_project_id" });
  if (!Array.isArray(events)) return res.status(400).json({ error: "events_required" });
  if (events.length > 200) return res.status(400).json({ error: "events_too_many" });

  const ip = getClientIp(req);

  // ✅ MOCK MODE (no DB)
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
    // project must exist + active + domain rules
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
      return res.status(403).json({ error: "domain_not_allowed", host: host || null });
    }

    // validate + prepare insert
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
        `to_timestamp($${idx++}/1000.0)`, // event_ts (ms)
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

// Optional: graceful shutdown
process.on("SIGTERM", async () => {
  try {
    if (pool) await pool.end();
  } catch {}
  process.exit(0);
});