import { requireAdmin, send } from "../lib/store.js";

// Checks the organizer password. The page keeps it and sends it as x-admin-key.
export default async function handler(req, res) {
  if (req.method !== "POST") return send(res, 405, { error: "Use POST." });
  if (!requireAdmin(req, res)) return;
  send(res, 200, { ok: true });
}
