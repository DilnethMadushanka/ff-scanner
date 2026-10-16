import { GAMES, SESSION_TTL, getJSON, newPin, pipeline, readBody, redis, send } from "../lib/store.js";
import { devicesUsed, isOwner, planOf, requireAccount } from "../lib/account.js";

// Every session ever made, for the owner. "sessions" holds the ones from before accounts existed.
const ALL = ["sessions:all", "sessions"];

// GET: this organizer's sessions (newest first); the owner gets everyone's. POST {game, player, mode}: create a session PIN.
// A PIN can only be made while the plan is active and has devices left this month.
export default async function handler(req, res) {
  const acct = await requireAccount(req, res);
  if (!acct) return;
  const list = `sessions:${acct.id}`;
  try {
    if (req.method === "GET") {
      const owner = isOwner(acct);
      const lists = owner ? ALL : [list];
      const ranked = new Map();
      for (const l of lists) {
        const flat = await redis("ZREVRANGE", l, 0, 499, "WITHSCORES");
        for (let i = 0; i < flat.length; i += 2) ranked.set(flat[i], Math.max(ranked.get(flat[i]) || 0, Number(flat[i + 1])));
      }
      const pins = [...ranked.keys()].sort((a, b) => ranked.get(b) - ranked.get(a)).slice(0, 500);
      if (!pins.length) return send(res, 200, { sessions: [], owner });
      const raw = await pipeline(pins.map(p => ["GET", `session:${p}`]));
      const sessions = raw.filter(Boolean).map(s => JSON.parse(s));
      const gone = pins.filter((p, i) => !raw[i]);
      if (gone.length) await pipeline(lists.map(l => ["ZREM", l, ...gone])); // expired sessions
      if (owner) for (const s of sessions) s.org = s.org || (s.account ? "" : "Old password login");
      return send(res, 200, { sessions, owner });
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
        pin, account: acct.id, org: acct.email, game, gameName: GAMES[game], player: String(player).slice(0, 60),
        mode: ["pc", "phone", "both"].includes(mode) ? mode : "pc",
        status: "waiting", created: new Date(now).toISOString(),
      };
      await pipeline([
        ["SET", `session:${pin}`, JSON.stringify(session), "EX", SESSION_TTL],
        ["ZADD", list, now, pin],
        ["ZADD", "sessions:all", now, pin],
      ]);
      return send(res, 201, { session });
    }
    send(res, 405, { error: "Use GET or POST." });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
}
