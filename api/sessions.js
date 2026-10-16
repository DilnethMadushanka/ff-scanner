import { GAMES, SESSION_TTL, getJSON, newPin, pipeline, readBody, redis, send } from "../lib/store.js";
import { devicesUsed, planOf, requireAccount } from "../lib/account.js";

// GET: this organizer's sessions (newest first). POST {game, player, mode}: create a session PIN.
// A PIN can only be made while the plan is active and has devices left this month.
export default async function handler(req, res) {
  const acct = await requireAccount(req, res);
  if (!acct) return;
  const list = `sessions:${acct.id}`;
  try {
    if (req.method === "GET") {
      const pins = await redis("ZREVRANGE", list, 0, 499);
      if (!pins.length) return send(res, 200, { sessions: [] });
      const raw = await pipeline(pins.map(p => ["GET", `session:${p}`]));
      const sessions = raw.filter(Boolean).map(s => JSON.parse(s));
      const gone = pins.filter((p, i) => !raw[i]);
      if (gone.length) await redis("ZREM", list, ...gone); // expired sessions
      return send(res, 200, { sessions });
    }
    if (req.method === "POST") {
      const p = planOf(acct);
      if (!p.active) return send(res, 402, { error: "Your plan is not active. Choose a plan above to create session PINs." });
      if (p.limit != null && await devicesUsed(acct, p) >= p.limit) {
        return send(res, 402, { error: `You have used all ${p.limit} device scans for this month. Upgrade to Pro for 100.` });
      }
      const { game = "freefire", player = "", mode = "pc" } = readBody(req);
      if (!GAMES[game]) return send(res, 400, { error: "Unknown game." });
      let pin;
      for (let i = 0; i < 5 && !pin; i++) {
        const n = newPin();
        if (!(await getJSON(`session:${n}`))) pin = n;
      }
      const now = Date.now();
      const session = {
        pin, account: acct.id, game, gameName: GAMES[game], player: String(player).slice(0, 60),
        mode: ["pc", "phone", "both"].includes(mode) ? mode : "pc",
        status: "waiting", created: new Date(now).toISOString(),
      };
      await pipeline([
        ["SET", `session:${pin}`, JSON.stringify(session), "EX", SESSION_TTL],
        ["ZADD", list, now, pin],
      ]);
      return send(res, 201, { session });
    }
    send(res, 405, { error: "Use GET or POST." });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
}
