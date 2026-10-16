// Lemon Squeezy (the checkout and monthly billing). It is the merchant of record, so it handles
// card payments, tax and receipts, and pays out to a Sri Lankan bank account.
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifySignature(raw, signature) {
  const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
  if (!secret || !signature) return false;
  const want = Buffer.from(createHmac("sha256", secret).update(raw).digest("hex"));
  const got = Buffer.from(String(signature));
  return want.length === got.length && timingSafeEqual(want, got);
}

// The subscription's current attributes straight from Lemon Squeezy, or null.
export async function fetchSubscription(id) {
  const key = process.env.LEMONSQUEEZY_API_KEY;
  if (!key || !/^\d+$/.test(String(id))) return null;
  const r = await fetch(`https://api.lemonsqueezy.com/v1/subscriptions/${id}`, {
    headers: { Accept: "application/vnd.api+json", Authorization: `Bearer ${key}` },
  });
  if (!r.ok) return null;
  const a = (await r.json()).data?.attributes;
  const store = process.env.LEMONSQUEEZY_STORE_ID;
  return a && (!store || String(a.store_id) === String(store)) ? a : null;
}
