import { SESSION_TTL, UPLOAD_WINDOW, getJSON, pipeline, readBody, send } from "../lib/store.js";

// Called by FFScanner.exe on the player's PC. No password: the session PIN is the key.
// GET ?pin=: which game/player/mode the organizer set. POST {pin, report}: upload the result once.
export default async function handler(req, res) {
  try {
    const body = req.method === "POST" ? readBody(req) : {};
    const pin = String(req.query.pin || body.pin || "");
    if (!/^\d{8}$/.test(pin)) return send(res, 400, { error: "PIN must be 8 digits." });
    const session = await getJSON(`session:${pin}`);
    if (!session) return send(res, 404, { error: "Unknown PIN. Check the PIN with the organizer." });
    const age = (Date.now() - Date.parse(session.created)) / 1000;
    if (req.method === "GET") {
      return send(res, 200, { pin, game: session.game, gameName: session.gameName, player: session.player, mode: session.mode, status: session.status });
    }
    if (req.method !== "POST") return send(res, 405, { error: "Use GET or POST." });
    if (session.status === "done") return send(res, 409, { error: "This PIN was already used. Ask the organizer for a new one." });
    if (age > UPLOAD_WINDOW) return send(res, 410, { error: "This PIN has expired. Ask the organizer for a new one." });
    const r = body.report;
    if (!r || r.schema !== "ffscan/1" || !Array.isArray(r.findings)) return send(res, 400, { error: "Not a scanner report." });
    r.pin = pin;
    const count = lvl => r.findings.filter(f => f.level === lvl).length;
    const done = {
      ...session, status: "done", uploaded: new Date().toISOString(),
      verdict: r.verdict, high: count("HIGH"), medium: count("MEDIUM"),
      pc: String(r.pc || ""), scannedPlayer: String(r.player || ""), scanTime: r.time || "",
    };
    await pipeline([
      ["SET", `report:${pin}`, JSON.stringify(r), "EX", SESSION_TTL],
      ["SET", `session:${pin}`, JSON.stringify(done), "EX", SESSION_TTL],
    ]);
    send(res, 200, { ok: true, verdict: r.verdict });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
}
