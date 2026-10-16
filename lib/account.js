// Organizer accounts, monthly plans and the device-scan quota.
// Every check that matters happens here on the server, so a copied scanner exe is useless without
// a PIN from an organizer whose plan is active and still has devices left this month.
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { getJSON, redis, send } from "./store.js";
import { fetchSubscription } from "./lemon.js";

export const PLANS = {
  starter: { name: "Starter", price: "$9.99 / month", devices: 30 },
  pro: { name: "Pro", price: "$20 / month", devices: 100 },
};
const AUTH_TTL = 60 * 60 * 24 * 30;          // a sign-in lasts 30 days
const USAGE_TTL = 60 * 60 * 24 * 45;         // keep a month's device list a little past its end
const GRACE = 1000 * 60 * 60 * 24 * 3;       // a renewal may arrive up to 3 days late before scans stop
const ACTIVE = ["active", "on_trial", "past_due"]; // past_due: the card is being retried, keep working meanwhile

export const cleanEmail = e => String(e || "").trim().toLowerCase().slice(0, 200);
export const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e);
const owners = () => (process.env.OWNER_EMAILS || "").split(",").map(cleanEmail).filter(Boolean);
// The site owner (OWNER_EMAILS) scans with no limit and can see every organizer's sessions and reports.
export const isOwner = acct => owners().includes(acct.email);

export function hashPassword(pw, salt = randomBytes(16).toString("hex")) {
  return { salt, hash: scryptSync(String(pw), salt, 32).toString("hex") };
}
export function checkPassword(pw, rec) {
  if (!rec || !rec.salt) return false;
  return timingSafeEqual(scryptSync(String(pw), rec.salt, 32), Buffer.from(rec.hash, "hex"));
}

export async function newToken(id) {
  const t = randomBytes(24).toString("base64url");
  await redis("SET", `auth:${t}`, id, "EX", AUTH_TTL);
  return t;
}

export async function saveAccount(acct) {
  await redis("SET", `acct:${acct.id}`, JSON.stringify(acct));
}

// Loads an account. If its paid month has run out and no renewal arrived (a lost webhook),
// ask Lemon Squeezy directly, at most every 10 minutes.
export async function getAccount(id) {
  if (!id) return null;
  const acct = await getJSON(`acct:${id}`);
  const s = acct && acct.sub;
  if (s && s.id && Date.now() > Date.parse(s.renewsAt || s.endsAt || 0) && Date.now() - (s.checked || 0) > 600000) {
    try {
      const fresh = await fetchSubscription(s.id);
      if (fresh) { acct.sub = { ...subFrom(s.id, fresh), plan: planKey(fresh.variant_id) || s.plan }; await saveAccount(acct); }
    } catch (e) { /* keep what we have; the GRACE window below still applies */ }
  }
  return acct;
}

export async function requireAccount(req, res) {
  const t = String(req.headers["x-auth"] || "");
  const id = t && await redis("GET", `auth:${t}`);
  const acct = id && await getAccount(id);
  if (!acct) { send(res, 401, { error: "Please sign in again." }); return null; }
  return acct;
}

export function planKey(variantId) {
  const v = String(variantId || "");
  if (v && v === process.env.LEMONSQUEEZY_STARTER_VARIANT) return "starter";
  if (v && v === process.env.LEMONSQUEEZY_PRO_VARIANT) return "pro";
  return null;
}

export function subFrom(id, a) {
  return {
    id: String(id), status: a.status, plan: planKey(a.variant_id),
    renewsAt: a.renews_at || null, endsAt: a.ends_at || null,
    portal: (a.urls || {}).customer_portal || null, checked: Date.now(),
  };
}

// What the account may do right now: { active, plan, name, limit (null = no limit), period, until }
export function planOf(acct) {
  if (isOwner(acct)) {
    return { active: true, plan: "owner", name: "Owner (no limit)", limit: null, period: new Date().toISOString().slice(0, 7), until: null };
  }
  const s = acct.sub;
  if (!s || !PLANS[s.plan]) return { active: false, plan: null, name: "No plan", limit: 0, period: null, until: null };
  const now = Date.now();
  const until = s.status === "cancelled" || s.status === "expired" ? s.endsAt : s.renewsAt;
  let active = ACTIVE.includes(s.status) || (s.status === "cancelled" && Date.parse(s.endsAt || 0) > now);
  if (active && until && Date.parse(until) + GRACE < now) active = false; // paid month over, no renewal seen
  // The device count starts again each billing month; the month is named by the date it renews on.
  return { active, plan: s.plan, name: PLANS[s.plan].name, limit: PLANS[s.plan].devices, period: (s.renewsAt || s.endsAt || "").slice(0, 10), until, status: s.status };
}

const usageKey = (acct, p) => `used:${acct.id}:${p.period}`;

export async function devicesUsed(acct, p = planOf(acct)) {
  return p.period ? Number(await redis("SCARD", usageKey(acct, p))) || 0 : 0;
}

// Counts this PIN as one device scan for the month. The same PIN never counts twice.
// Atomic in Redis, so two scans starting at once can't both take the last device.
const TAKE = `
if redis.call('SISMEMBER', KEYS[1], ARGV[1]) == 1 then return 1 end
local limit = tonumber(ARGV[2])
if limit >= 0 and redis.call('SCARD', KEYS[1]) >= limit then return 0 end
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
return 1`;

export async function takeDevice(acct, pin) {
  const p = planOf(acct);
  if (!p.active) return { ok: false, error: "The organizer's FF Scanner plan is not active. Ask the organizer to renew it." };
  const ok = await redis("EVAL", TAKE, 1, usageKey(acct, p), pin, p.limit == null ? -1 : p.limit, USAGE_TTL);
  return Number(ok) === 1 ? { ok: true } : { ok: false, error: `The organizer has used all ${p.limit} device scans for this month. Ask them to upgrade the plan.` };
}

export function checkoutLinks(acct) {
  const out = {};
  for (const [key, env] of [["starter", "LEMONSQUEEZY_STARTER_URL"], ["pro", "LEMONSQUEEZY_PRO_URL"]]) {
    const base = process.env[env];
    if (!base) continue;
    const u = new URL(base);
    u.searchParams.set("checkout[email]", acct.email);
    u.searchParams.set("checkout[custom][account]", acct.id);
    out[key] = u.toString();
  }
  return out;
}

// A subscription created, renewed, changed, cancelled or expired (from the signed webhook).
// Finds the account by the subscription it already belongs to, then the account id sent through
// the checkout link, then the buyer's email. Bought before signing up: kept until they sign up.
export async function applySubscription(id, a, accountHint) {
  const email = cleanEmail(a.user_email);
  const sub = subFrom(id, a);
  let acctId = await redis("GET", `lsub:${id}`);
  if (!acctId && accountHint && await getJSON(`acct:${accountHint}`)) acctId = String(accountHint);
  if (!acctId && email) acctId = await redis("GET", `email:${email}`);
  if (!acctId) {
    if (email) await redis("SET", `pending:${email}`, JSON.stringify(sub), "EX", 60 * 60 * 24 * 60);
    return { pending: true };
  }
  await redis("SET", `lsub:${id}`, acctId);
  const acct = await getJSON(`acct:${acctId}`);
  const cur = acct.sub;
  // An old subscription ending must not replace a newer one that is still paid.
  if (!cur || cur.id === sub.id || !planOf({ ...acct, sub: cur }).active || planOf({ ...acct, sub }).active) {
    acct.sub = sub;
    await saveAccount(acct);
  }
  return { account: acctId };
}
