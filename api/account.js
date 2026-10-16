import { getJSON, readBody, redis, send } from "../lib/store.js";
import {
  PLANS, checkPassword, checkoutLinks, cleanEmail, devicesUsed, hashPassword, newToken, planOf,
  requireAccount, saveAccount, validEmail,
} from "../lib/account.js";

// POST {action: "signup"|"login", email, password} -> {token}. POST {action: "logout"}.
// GET (signed in): the plan, devices used this month, and the buy / manage links.
export default async function handler(req, res) {
  try {
    if (req.method === "GET") {
      const acct = await requireAccount(req, res);
      if (!acct) return;
      const p = planOf(acct);
      return send(res, 200, {
        email: acct.email, plan: p, used: await devicesUsed(acct, p), plans: PLANS,
        checkout: checkoutLinks(acct), portal: acct.sub?.portal || null,
      });
    }
    if (req.method !== "POST") return send(res, 405, { error: "Use GET or POST." });
    const { action, email: rawEmail, password = "" } = readBody(req);
    if (action === "logout") {
      const t = String(req.headers["x-auth"] || "");
      if (t) await redis("DEL", `auth:${t}`);
      return send(res, 200, { ok: true });
    }
    const email = cleanEmail(rawEmail);
    if (!validEmail(email)) return send(res, 400, { error: "Enter a valid email address." });
    if (action === "signup") {
      if (String(password).length < 8) return send(res, 400, { error: "Use a password of at least 8 characters." });
      const id = crypto.randomUUID();
      // NX: two sign-ups with the same email can't both win
      if (await redis("SET", `email:${email}`, id, "NX") !== "OK") return send(res, 409, { error: "This email already has an account. Sign in instead." });
      const acct = { id, email, pw: hashPassword(password), created: new Date().toISOString(), sub: null };
      const pending = await getJSON(`pending:${email}`); // paid before creating the account
      if (pending) { acct.sub = pending; await redis("SET", `lsub:${pending.id}`, id); await redis("DEL", `pending:${email}`); }
      await saveAccount(acct);
      return send(res, 201, { token: await newToken(id) });
    }
    if (action === "login") {
      const failKey = `fail:${email}`;
      if (Number(await redis("GET", failKey)) >= 10) return send(res, 429, { error: "Too many wrong passwords. Try again in 15 minutes." });
      const id = await redis("GET", `email:${email}`);
      const acct = id && await getJSON(`acct:${id}`);
      if (!acct || !checkPassword(password, acct.pw)) {
        await redis("INCR", failKey); await redis("EXPIRE", failKey, 900);
        return send(res, 401, { error: "Wrong email or password." });
      }
      await redis("DEL", failKey);
      return send(res, 200, { token: await newToken(id) });
    }
    send(res, 400, { error: "Unknown action." });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
}
