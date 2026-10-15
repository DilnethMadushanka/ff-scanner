import { SESSION_TTL, UPLOAD_WINDOW, getJSON, pipeline, readBody, send } from "../lib/store.js";

// Called by FFScanner.exe on the player's PC. No password: the session PIN is the key.
// GET ?pin=: which game/player/mode the organizer set.
// POST {pin, live: true, report}: what the scan found so far (sent every few seconds while it runs).
// POST {pin, report}: the final result, accepted once.
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
    r.run = String(r.run || "");
    const count = lvl => r.findings.filter(f => f.level === lvl).length;
    const now = new Date().toISOString();
    // A scan that was started earlier with this PIN and never finished (closed, cancelled) is kept,
    // so a player can't hide something by stopping the scan and running it again.
    const old = await getJSON(`report:${pin}`);
    r.earlier = old ? (old.earlier || []) : [];
    if (old && old.live && old.run !== r.run) {
      const { earlier, ...prev } = old;
      r.earlier = [prev, ...r.earlier].slice(0, 5);
    }
    const base = {
      ...session, uploaded: now, lastSeen: now, verdict: r.verdict, high: count("HIGH"), medium: count("MEDIUM"),
      pc: String(r.pc || ""), scannedPlayer: String(r.player || ""), scanTime: r.time || "",
      earlierRuns: r.earlier.length,
      earlierHigh: r.earlier.reduce((n, e) => n + (e.findings || []).filter(f => f.level === "HIGH").length, 0),
    };
    let next;
    if (body.live) {
      r.live = true;
      const p = r.progress || {};
      next = { ...base, status: r.stopped ? "stopped" : "scanning", step: Number(p.step) || 0, total: Number(p.total) || 0, now: String(p.now || "").slice(0, 200) };
    } else {
      delete r.live; delete r.progress; delete r.stopped;
      next = { ...base, status: "done" };
      delete next.step; delete next.total; delete next.now;
    }
    await pipeline([
      ["SET", `report:${pin}`, JSON.stringify(r), "EX", SESSION_TTL],
      ["SET", `session:${pin}`, JSON.stringify(next), "EX", SESSION_TTL],
    ]);
    send(res, 200, { ok: true, verdict: r.verdict });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
}
