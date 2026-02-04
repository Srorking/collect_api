// Collect API — batch /collect -> PostgreSQL (Render-ready)
// - Strong CORS (works for 2xx/4xx/5xx + preflight)
// - Lazy DB pool (no crash if DATABASE_URL missing)
// - MOCK_MODE supported
// - Keeps your schema mapping exactly

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
// You can optionally set: CORS_ORIGINS="https://a.com,https://b.com"
// If not set -> allow all origins (reflect origin)
const ALLOW_LIST = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    // allow non-browser requests (curl/postman) with no Origin
    if (!origin) return cb(null, true);

    // if no allow-list specified, allow all (reflect origin)
    if (ALLOW_LIST.length === 0) return cb(null, true);

    // allow only listed origins
    if (ALLOW_LIST.includes(origin)) return cb(null, true);

    // reject but still return CORS headers via middleware order below
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
// keep text/plain support (some clients might send text)
app.use(express.text({ type: ["text/plain", "application/json"], limit: "1mb" }));

// -------------------- DB pool (lazy) --------------------
let pool = null;

function getPool() {
  if (pool) return pool;

  const url = process.env.DATABASE_URL;
  if (!url) return null;

  // Render/Postgres often needs TLS. If DATABASE_URL contains sslmode=require => enable ssl.
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

// -------------------- Routes --------------------
app.get("/health", async (_req, res) => {
  // Optionally check DB connection if available
  try {
    const p = getPool();
    if (p) await p.query("select 1");
    return res.status(200).json({ ok: true, db: p ? "up" : "not_configured" });
  } catch (e) {
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

  // ✅ MOCK MODE (no DB) — if DATABASE_URL missing OR MOCK_MODE=1
  if (!process.env.DATABASE_URL || process.env.MOCK_MODE === "1") {
    console.log("[MOCK] /collect batch:", {
      project_id,
      sent_at,
      events_count: Array.isArray(events) ? events.length : null,
      sample_event:
        Array.isArray(events) && events[0]
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
    // project must exist + active
    const proj = await p.query(
      "select id from projects where id = $1 and is_active = true",
      [project_id]
    );
    if (!proj.rowCount) return res.status(403).json({ error: "project_inactive" });

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

      const placeholders = [
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
