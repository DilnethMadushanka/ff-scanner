import { GAMES, SESSION_TTL, getJSON, newPin, pipeline, readBody, redis, requireAdmin, send } from "../lib/store.js";

// GET: list sessions (newest first). POST {game, player}: create a session PIN.
export default async function handler(req, res) {
  if (!requireAdmin(req, res)) return;
  try {
    if (req.method === "GET") {
      const pins = await redis("ZREVRANGE", "sessions", 0, 499);
      if (!pins.length) return send(res, 200, { sessions: [] });
      const raw = await pipeline(pins.map(p => ["GET", `session:${p}`]));
      const sessions = raw.filter(Boolean).map(s => JSON.parse(s));
      const gone = pins.filter((p, i) => !raw[i]);
      if (gone.length) await redis("ZREM", "sessions", ...gone); // expired sessions
      return send(res, 200, { sessions });
    }
    if (req.method === "POST") {
      const { game = "freefire", player = "", mode = "pc" } = readBody(req);
      if (!GAMES[game]) return send(res, 400, { error: "Unknown game." });
      let pin;
      for (let i = 0; i < 5 && !pin; i++) {
        const p = newPin();
        if (!(await getJSON(`session:${p}`))) pin = p;
      }
      const now = Date.now();
      const session = {
        pin, game, gameName: GAMES[game], player: String(player).slice(0, 60),
        mode: ["pc", "phone", "both"].includes(mode) ? mode : "pc",
        status: "waiting", created: new Date(now).toISOString(),
      };
      await pipeline([
        ["SET", `session:${pin}`, JSON.stringify(session), "EX", SESSION_TTL],
        ["ZADD", "sessions", now, pin],
      ]);
      return send(res, 201, { session });
    }
    send(res, 405, { error: "Use GET or POST." });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
}
