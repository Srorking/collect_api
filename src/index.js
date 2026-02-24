// collect-api/src/index.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();
const port = process.env.PORT || 4000;

// -------------------- Upstream endpoints --------------------
const UPSTREAM_BASE = process.env.UPSTREAM_BASE || "http://glaros.souryasocial.shop";
const UPSTREAM_PROJECTS_URL = `${UPSTREAM_BASE}/api/Projects/GetAll`;
const UPSTREAM_ADD_EVENT_URL = `${UPSTREAM_BASE}/api/Events/AddEvent`;
const UPSTREAM_ADD_RANGE_URL = `${UPSTREAM_BASE}/api/Events/AddRange`;

// Optional auth (if needed later)
const UPSTREAM_API_KEY = process.env.UPSTREAM_API_KEY || "";

// -------------------- Trust proxy --------------------
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

function hostFromUrl(url) {
  try {
    const u = new URL(url);
    return (u.hostname || "").toLowerCase();
  } catch {
    return "";
  }
}

function getIncomingHost(req) {
  const origin = req.headers.origin ? String(req.headers.origin) : "";
  const referer = req.headers.referer ? String(req.headers.referer) : "";

  const originHost = origin ? hostFromUrl(origin) : "";
  const refererHost = referer ? hostFromUrl(referer) : "";

  return originHost || refererHost || "";
}

/**
 * Normalize allowed_domains to JS array of strings.
 * Supports:
 * - jsonb array (["a.com"])
 * - pg text[] array (["a.com"])
 * - postgres array literal string ("{a.com,b.com}")
 * - JSON string ('["a.com"]')
 * - single string ("a.com")
 */
function normalizeAllowedDomains(value) {
  if (Array.isArray(value)) return value.map(String);
  if (value == null) return [];

  if (typeof value === "string") {
    const s = value.trim();

    // JSON string
    try {
      const parsed = JSON.parse(s);
      if (Array.isArray(parsed)) return parsed.map(String);
    } catch {}

    // Postgres array literal
    if (s.startsWith("{") && s.endsWith("}")) {
      const inner = s.slice(1, -1).trim();
      if (!inner) return [];
      return inner
        .split(",")
        .map((x) => x.trim().replace(/^"(.*)"$/, "$1"))
        .filter(Boolean);
    }

    return s ? [s] : [];
  }

  return [];
}

function isAllowedHost({ host, allowedDomains, allowSubdomains }) {
  const h = (host || "").toLowerCase();
  if (!h) return false;

  const domains = normalizeAllowedDomains(allowedDomains);
  if (domains.length === 0) return false;

  for (const dRaw of domains) {
    const d = String(dRaw || "").toLowerCase().trim();
    if (!d) continue;

    if (h === d) return true;
    if (allowSubdomains && h.endsWith("." + d)) return true;
  }
  return false;
}

// ---- timestamps ----
function toIsoFromMs(ms) {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

function nowIso() {
  return new Date().toISOString();
}

// -------------------- Upstream fetch --------------------
async function upstreamFetch(url, options = {}) {
  const headers = {
    accept: "*/*",
    ...(options.headers || {}),
  };

  if (UPSTREAM_API_KEY) headers["X-API-Key"] = UPSTREAM_API_KEY;

  const res = await fetch(url, { ...options, headers });
  const text = await res.text();

  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const msg = typeof data === "string" ? data : JSON.stringify(data);
    throw new Error(`Upstream ${res.status} ${res.statusText}: ${msg}`);
  }

  return data;
}

/**
 * We don't know exact Project DTO fields returned by GetAll,
 * so we normalize with common field names.
 */
function normalizeProjectFromUpstream(p) {
  const id = String(p.projectId || p.project_id || p.id || p.projectID || "").trim();
  const is_active = Boolean(p.isActive ?? p.is_active ?? p.active ?? p.is_active === true);
  const allow_subdomains = Boolean(p.allowSubdomains ?? p.allow_subdomains ?? false);

  const allowed_domains =
    p.allowedDomains ??
    p.allowed_domains ??
    p.allowed_domains_json ??
    p.domains ??
    p.allowed_domains_list ??
    [];

  return { id, is_active, allow_subdomains, allowed_domains };
}

async function getProjectsFromUpstream() {
  const data = await upstreamFetch(UPSTREAM_PROJECTS_URL, { method: "GET" });

  const arr = Array.isArray(data)
    ? data
    : Array.isArray(data?.data)
      ? data.data
      : Array.isArray(data?.projects)
        ? data.projects
        : null;

  if (!Array.isArray(arr)) throw new Error("Upstream projects response is not an array");

  return arr.map(normalizeProjectFromUpstream).filter((x) => isUuid(x.id));
}

// Map SDK event -> Upstream Event DTO
function toUpstreamEvent(ev, ip) {
  const ctx = ev.context && typeof ev.context === "object" ? { ...ev.context } : {};
  ctx.ip = ip;

  return {
    projectId: ev.project_id,
    eventName: ev.event_name,
    eventTs: toIsoFromMs(ev.event_ts) || nowIso(),
    receivedAt: nowIso(),
    anonymousId: ev.anonymous_id || null,
    sessionId: ev.session_id || null,
    userId: ev.user_id || null,
    pageUrl: ev.page_url || null,
    pagePath: ev.page_path || null,
    pageTitle: ev.page_title || null,
    referrer: ev.referrer || null,
    previousUrl: ev.previous_url || null,
    context: ctx || {},
    properties: ev.properties && typeof ev.properties === "object" ? ev.properties : {},
    webVitals: ev.web_vitals && typeof ev.web_vitals === "object" ? ev.web_vitals : {},
  };
}

// -------------------- Routes --------------------
app.get("/health", async (_req, res) => {
  try {
    // quick upstream check
    await upstreamFetch(UPSTREAM_PROJECTS_URL, { method: "GET" });
    return res.status(200).json({ ok: true, upstream: "up" });
  } catch (e) {
    return res.status(200).json({ ok: true, upstream: "down" });
  }
});

// GET /bootstrap?pid=<project_uuid>
app.get("/bootstrap", async (req, res) => {
  const project_id = String(req.query.pid || "").trim();
  if (!isUuid(project_id)) {
    return res.status(400).json({ allow: false, error: "invalid_project_id" });
  }

  try {
    // const projects = await getProjectsFromUpstream();
    // const proj = projects.find((p) => p.id === project_id);

    // if (!proj || !proj.is_active) {
    //   return res.status(200).json({ allow: false, error: "project_inactive" });
    // }

    // const host = getIncomingHost(req);

    // const ok = isAllowedHost({
    //   host,
    //   allowedDomains: proj.allowed_domains,
    //   allowSubdomains: !!proj.allow_subdomains,
    // });

    // if (!ok) {
    //   return res.status(200).json({
    //     allow: false,
    //     error: "domain_not_allowed",
    //     host: host || null,
    //   });
    // }

    return res.status(200).json({ allow: true });
  } catch (err) {
    console.error("BOOTSTRAP_ERROR:", err);
    return res.status(200).json({ allow: false, error: "server_error" });
  }
});

// POST /collect
app.post("/collect", async (req, res) => {
  const body = parseBody(req);
  if (!body) return res.status(400).json({ error: "invalid_json" });

  const { project_id, events } = body;

  if (!isUuid(project_id)) return res.status(400).json({ error: "invalid_project_id" });
  if (!Array.isArray(events)) return res.status(400).json({ error: "events_required" });
  if (events.length > 200) return res.status(400).json({ error: "events_too_many" });

  const ip = getClientIp(req);

  try {
    // 1) project + domain check via upstream projects
    const projects = await getProjectsFromUpstream();
    const proj = projects.find((p) => p.id === project_id);

    if (!proj || !proj.is_active) return res.status(403).json({ error: "project_inactive" });

    const host = getIncomingHost(req);

    if (
      !isAllowedHost({
        host,
        allowedDomains: proj.allowed_domains,
        allowSubdomains: !!proj.allow_subdomains,
      })
    ) {
      return res.status(403).json({ error: "domain_not_allowed", host: host || null });
    }

    // 2) validate + map
    const upstreamEvents = [];
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

      // (optional) keep local uuid if you want, not required by upstream
      crypto.randomUUID();

      upstreamEvents.push(toUpstreamEvent(ev, ip));
    }

    // 3) Send as batch to upstream AddRange
    await upstreamFetch(UPSTREAM_ADD_RANGE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(upstreamEvents),
    });

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
  process.exit(0);
});