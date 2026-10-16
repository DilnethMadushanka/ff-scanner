// Tiny Upstash Redis REST client (no dependencies).
// Vercel's Upstash / KV integration sets one of these pairs of environment variables.
const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

export const GAMES = {
  freefire: "Free Fire / Free Fire MAX",
  pubgm: "PUBG Mobile / BGMI",
  codm: "Call of Duty Mobile",
  all: "All games",
};
export const SESSION_TTL = 60 * 60 * 24 * 30; // keep sessions and reports 30 days
export const UPLOAD_WINDOW = 60 * 60 * 24;    // a PIN accepts an upload for 24 hours

async function call(path, body) {
  if (!URL_ || !TOKEN) throw new Error("Database not connected. Add an Upstash Redis store to this Vercel project.");
  const r = await fetch(URL_ + path, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json();
  if (!r.ok || data.error) throw new Error(data.error || `Database error ${r.status}`);
  return data;
}

export async function redis(...cmd) {
  return (await call("", cmd)).result;
}

export async function pipeline(cmds) {
  const out = await call("/pipeline", cmds);
  return out.map(x => {
    if (x.error) throw new Error(x.error);
    return x.result;
  });
}

export async function getJSON(key) {
  const v = await redis("GET", key);
  return v ? JSON.parse(v) : null;
}

export function send(res, status, data) {
  res.status(status).setHeader("Cache-Control", "no-store");
  res.json(data);
}

export function newPin() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 100000000;
  return String(n).padStart(8, "0");
}

export function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  try { return JSON.parse(req.body || "{}"); } catch { return {}; }
}
