// Collect API لاستقبال الدُفعات وتخزينها في PostgreSQL
import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import pg from "pg";

dotenv.config();

const { Pool } = pg;

const app = express();
const port = process.env.PORT || 4000;

const corsOptions = {
  origin: true,
  methods: ["POST", "OPTIONS", "GET"],
  allowedHeaders: ["Content-Type", "X-PT-Signature"]
};

app.use(helmet());
app.use(cors(corsOptions));
app.options("/collect", cors(corsOptions));

app.use(express.json({ limit: "1mb" }));
app.use(express.text({ type: "text/plain", limit: "1mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

app.get("/health", (_req, res) => {
  res.status(200).json({ ok: true });
});

app.post("/collect", async (req, res) => {
  const body = parseBody(req);
  if (!body) return res.status(400).json({ error: "invalid_json" });

  const { project_id, events } = body;

  if (!isUuid(project_id)) return res.status(400).json({ error: "invalid_project_id" });
  if (!Array.isArray(events)) return res.status(400).json({ error: "events_required" });
  if (events.length > 200) return res.status(400).json({ error: "events_too_many" });
  // ✅ MOCK MODE (بدون DB) — إذا ما في DB شغّالة
if (!process.env.DATABASE_URL || process.env.MOCK_MODE === "1") {
  const { project_id, events, sent_at } = body || {};
  console.log("[MOCK] /collect batch:", {
    project_id,
    sent_at,
    events_count: Array.isArray(events) ? events.length : null,
    sample_event: Array.isArray(events) && events[0] ? {
      event_name: events[0].event_name,
      event_ts: events[0].event_ts,
      page_url: events[0].page_url,
      user_id: events[0].user_id,
      anonymous_id: events[0].anonymous_id
    } : null
  });

  return res.status(204).send();
}


  try {
    const proj = await pool.query(
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
  `$${idx++}`,                       // project_id
  `$${idx++}`,                       // event_name
  `to_timestamp($${idx++}/1000.0)`,  // event_ts (ms)
  "now()",                           // received_at
  `$${idx++}`,                       // anonymous_id
  `$${idx++}`,                       // session_id
  `$${idx++}`,                       // user_id
  `$${idx++}`,                       // page_url
  `$${idx++}`,                       // page_path
  `$${idx++}`,                       // page_title
  `$${idx++}`,                       // referrer
  `$${idx++}`,                       // previous_url
  `$${idx++}::jsonb`,                // context
  `$${idx++}::jsonb`,                // properties
  `$${idx++}::jsonb`                 // web_vitals
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

    await pool.query(sql, values);
    return res.status(204).send();
  } catch (err) {
  console.error("COLLECT_ERROR:", err); // 👈 مهم
  return res.status(500).json({ error: "server_error" });
}

});

app.listen(port, () => {
  console.log(`Collect API يعمل على المنفذ ${port}`);
});
