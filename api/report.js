import { getJSON, pipeline, send } from "../lib/store.js";
import { requireAccount } from "../lib/account.js";

// GET ?pin=: one full report. DELETE ?pin=: remove the session and its report. Only the organizer who made the PIN.
export default async function handler(req, res) {
  const acct = await requireAccount(req, res);
  if (!acct) return;
  const pin = String(req.query.pin || "");
  if (!/^\d{8}$/.test(pin)) return send(res, 400, { error: "PIN must be 8 digits." });
  try {
    const session = await getJSON(`session:${pin}`);
    if (!session || session.account !== acct.id) return send(res, 404, { error: "No session with this PIN." });
    if (req.method === "GET") {
      const report = await getJSON(`report:${pin}`);
      return report ? send(res, 200, { report }) : send(res, 404, { error: "No report for this PIN yet." });
    }
    if (req.method === "DELETE") {
      await pipeline([["DEL", `session:${pin}`], ["DEL", `report:${pin}`], ["ZREM", `sessions:${acct.id}`, pin]]);
      return send(res, 200, { ok: true });
    }
    send(res, 405, { error: "Use GET or DELETE." });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
}
