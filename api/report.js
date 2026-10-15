import { getJSON, pipeline, requireAdmin, send } from "../lib/store.js";

// GET ?pin=: one full report. DELETE ?pin=: remove the session and its report.
export default async function handler(req, res) {
  if (!requireAdmin(req, res)) return;
  const pin = String(req.query.pin || "");
  if (!/^\d{8}$/.test(pin)) return send(res, 400, { error: "PIN must be 8 digits." });
  try {
    if (req.method === "GET") {
      const report = await getJSON(`report:${pin}`);
      return report ? send(res, 200, { report }) : send(res, 404, { error: "No report for this PIN yet." });
    }
    if (req.method === "DELETE") {
      await pipeline([["DEL", `session:${pin}`], ["DEL", `report:${pin}`], ["ZREM", "sessions", pin]]);
      return send(res, 200, { ok: true });
    }
    send(res, 405, { error: "Use GET or DELETE." });
  } catch (e) {
    send(res, 500, { error: e.message });
  }
}
