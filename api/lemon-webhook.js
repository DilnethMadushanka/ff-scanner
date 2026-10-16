import { applySubscription, planKey } from "../lib/account.js";
import { verifySignature } from "../lib/lemon.js";

// Lemon Squeezy calls this when a subscription is created, renewed, changed, cancelled or expires.
// Only requests signed with LEMONSQUEEZY_WEBHOOK_SECRET are accepted, so nobody can fake a payment.
// (Web-standard handler so the exact raw body is available for the signature check.)
const json = (status, data) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });

export async function POST(request) {
  const raw = await request.text();
  if (!verifySignature(raw, request.headers.get("x-signature"))) return json(401, { error: "Bad signature." });
  let body;
  try { body = JSON.parse(raw); } catch { return json(400, { error: "Not JSON." }); }
  const event = String(body.meta?.event_name || "");
  const d = body.data || {};
  if (!event.startsWith("subscription_") || d.type !== "subscriptions") return json(200, { ignored: event });
  const a = d.attributes || {};
  const store = process.env.LEMONSQUEEZY_STORE_ID;
  if (store && String(a.store_id) !== String(store)) return json(200, { ignored: "other store" });
  if (!planKey(a.variant_id)) return json(200, { ignored: "not an FF Scanner plan" });
  try {
    return json(200, await applySubscription(d.id, a, body.meta?.custom_data?.account));
  } catch (e) {
    return json(500, { error: e.message }); // Lemon Squeezy retries failed deliveries
  }
}
