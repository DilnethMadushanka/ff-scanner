const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SECTIONS = [
  ["summary", "Summary", "Forensic report"],
  ["cheats", "Cheats Found", "Findings"], ["indications", "Key Indications"], ["files", "Suspicious Files"],
  ["defender", "Defender History"], ["devices", "Devices Removed"],
  ["system", "System Information", "Context"], ["accounts", "Alt Accounts"],
];
const BLURB = {
  cheats: "Strong signs of a cheat: known hack names, programs, apps or files.",
  indications: "Running programs, run history, browser history, emulator and phone apps, and trace cleaning.",
  files: "Files, APKs, deleted items and journal entries with hack names, and programs with hack code inside.",
  defender: "What Windows Defender caught before, and folders it was told to ignore.",
  devices: "USB drives and phones that were plugged in before but not at scan time.",
  accounts: "Windows accounts on the PC and Google accounts in the emulator or phone. More than one can mean a second account.",
};
const MODE = { pc: "PC + emulator", phone: "Android phone", both: "PC + phone" };
let key = "", sessions = [], openPin = null, openReport = null, section = "summary", timer = null;

try { key = localStorage.getItem("ffscan-key") || ""; } catch (e) {}

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "x-admin-key": key, ...(opts.headers || {}) } });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { signOut("Your password was not accepted. Sign in again."); throw new Error("Wrong password."); }
  if (!r.ok) throw new Error(data.error || `Error ${r.status}`);
  return data;
}

function fmtTime(t) { if (!t) return "—"; const d = new Date(t); return isNaN(d) ? String(t) : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
function fmtUnix(t) { return t ? fmtTime(t * 1000) : "—"; }
function setMsg(text, kind) { const m = $("#msg"); m.textContent = text; m.className = kind || ""; }
const verdictOf = s => s.status === "done" ? s.verdict : "WAITING";

/* ---------- sign in ---------- */
function signOut(message) {
  key = ""; try { localStorage.removeItem("ffscan-key"); } catch (e) {}
  clearInterval(timer); $("#app").hidden = true; $("#login-view").hidden = false;
  $("#login-msg").textContent = message || "";
}
$("#login-form").addEventListener("submit", async e => {
  e.preventDefault();
  key = $("#pw").value;
  try {
    const r = await fetch("/api/login", { method: "POST", headers: { "x-admin-key": key } });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || "Sign-in failed.");
    try { localStorage.setItem("ffscan-key", key); } catch (x) {}
    start();
  } catch (err) { $("#login-msg").textContent = err.message; }
});
$("#logout").addEventListener("click", () => signOut());

/* ---------- sessions ---------- */
async function load() {
  try { sessions = (await api("/api/sessions")).sessions; renderList(); }
  catch (e) { if (key) $("#list").innerHTML = `<div class="empty"><b>Could not load sessions</b>${esc(e.message)}</div>`; }
}

$("#new-form").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const { session } = await api("/api/sessions", { method: "POST", body: JSON.stringify({ player: $("#n-player").value.trim(), game: $("#n-game").value, mode: $("#n-mode").value }) });
    const box = $("#created"); box.hidden = false;
    const phone = session.mode !== "pc" ? "<li>On the phone, turn on USB debugging and plug it into the PC.</li>" : "";
    box.innerHTML = `<div class="created"><div><div class="lbl">Session PIN</div><div class="big">${esc(session.pin)}</div>
      <div>${esc(session.player || "No name")} · ${esc(session.gameName)} · ${esc(MODE[session.mode])}</div></div>
      <ol><li>Download the scanner: <a href="/FFScanner.exe">${esc(location.origin)}/FFScanner.exe</a></li>${phone}
      <li>Right-click FFScanner.exe and choose Run as administrator.</li><li>Type the PIN when it asks. The result shows here when the scan finishes.</li></ol>
      <button type="button" id="copy-pin">Copy PIN</button></div>`;
    $("#n-player").value = ""; setMsg("");
    await load();
  } catch (err) { setMsg(err.message, "err"); }
});
$("#created").addEventListener("click", async e => {
  if (e.target.id !== "copy-pin") return;
  const pin = $("#created .big").textContent;
  try { await navigator.clipboard.writeText(pin); e.target.textContent = "Copied"; } catch (x) { e.target.textContent = pin; }
});

function renderList() {
  const q = $("#q").value.trim().toLowerCase(), fv = $("#fv").value;
  const rows = sessions.filter(s => (!fv || verdictOf(s) === fv) && (!q || [s.player, s.scannedPlayer, s.pin, s.pc, s.gameName].join(" ").toLowerCase().includes(q)));
  const t = { WAITING: 0, SUSPICIOUS: 0, REVIEW: 0, CLEAN: 0 }; sessions.forEach(s => t[verdictOf(s)] = (t[verdictOf(s)] || 0) + 1);
  $("#tally").innerHTML = `<div><b>${t.WAITING}</b>Waiting</div><div class="t-hi"><b>${t.SUSPICIOUS}</b>Suspicious</div><div class="t-me"><b>${t.REVIEW}</b>Review</div><div class="t-ok"><b>${t.CLEAN}</b>Clean</div>`;
  if (!sessions.length) { $("#list").innerHTML = `<div class="empty"><b>No sessions yet</b>Create a session PIN above for the first player.</div>`; return; }
  if (!rows.length) { $("#list").innerHTML = `<div class="empty"><b>No matching sessions</b>Try another name or PIN.</div>`; return; }
  $("#list").innerHTML = `<table><thead><tr><th>PIN</th><th>Player</th><th class="hide-sm">Game</th><th class="hide-sm">PC</th><th>Created</th><th>Result</th><th class="num">High / Med</th></tr></thead><tbody>${
    rows.map(s => `<tr class="row${s.pin === openPin ? " sel" : ""}" tabindex="0" data-pin="${esc(s.pin)}">
      <td class="pin">${esc(s.pin)}</td><td>${esc(s.player || s.scannedPlayer || "—")}</td>
      <td class="hide-sm">${esc(s.gameName)} · ${esc(MODE[s.mode] || "")}</td><td class="hide-sm">${esc(s.pc || "—")}</td>
      <td class="num">${esc(fmtTime(s.created))}</td>
      <td><span class="pill v-${esc(verdictOf(s))}">${esc(verdictOf(s))}</span></td>
      <td class="num">${s.status === "done" ? `${s.high} / ${s.medium}` : "—"}</td></tr>`).join("")
  }</tbody></table>`;
}
$("#list").addEventListener("click", e => { const r = e.target.closest(".row"); if (r) openScan(r.dataset.pin); });
$("#list").addEventListener("keydown", e => { const r = e.target.closest(".row"); if (r && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openScan(r.dataset.pin); } });
$("#q").addEventListener("input", renderList);
$("#fv").addEventListener("change", renderList);

/* ---------- report ---------- */
async function openScan(pin) {
  openPin = pin; section = "summary"; renderList();
  const d = $("#detail"); d.hidden = false;
  const s = sessions.find(x => x.pin === pin);
  if (s && s.status !== "done") {
    d.innerHTML = `<div class="list"><div class="empty"><b>Waiting for the scan</b>PIN ${esc(pin)} has not uploaded a result yet. This page checks again every 15 seconds.
      <p><button type="button" class="danger" id="del">Delete session</button></p></div></div>`;
    return;
  }
  d.innerHTML = `<div class="list"><div class="empty"><b>Opening scan ${esc(pin)}…</b></div></div>`;
  try { openReport = (await api(`/api/report?pin=${pin}`)).report; renderReport(); d.scrollIntoView({ behavior: "smooth", block: "start" }); }
  catch (e) { d.innerHTML = `<div class="list"><div class="empty"><b>Could not open the report</b>${esc(e.message)}</div></div>`; }
}

function counts(r) {
  const f = r.findings || [];
  const c = { cheats: f.filter(x => x.level === "HIGH").length };
  for (const k of ["indications", "files", "defender", "devices"]) c[k] = f.filter(x => x.section === k).length;
  c.system = (r.system_info || []).length; c.accounts = (r.accounts || []).length;
  return c;
}

function findingsTable(items, empty) {
  if (!items.length) return `<div class="list"><div class="empty">${esc(empty)}</div></div>`;
  return `<div class="tbl"><table><thead><tr><th>Level</th><th>Where</th><th>Item</th><th>Why</th></tr></thead><tbody>${
    items.map(f => `<tr><td><span class="pill l-${esc(f.level)}">${esc(f.level)}</span></td><td>${esc(f.area)}</td><td class="path">${esc(f.what)}</td><td>${esc(f.reason)}</td></tr>`).join("")
  }</tbody></table></div>`;
}

function renderReport() {
  const r = openReport, c = counts(r), f = r.findings || [];
  const rail = SECTIONS.map(([k, label, grp]) => (grp ? `<div class="grp">${grp}</div>` : "") +
    `<a href="#" data-sec="${k}" class="${k === section ? "on" : ""}">${label}${k === "summary" ? "" : `<span class="${k === "cheats" && c.cheats ? "red" : ""}">${c[k]}</span>`}</a>`).join("");
  let body = "";
  if (section === "summary") {
    const tl = f.filter(x => x.when && x.level !== "INFO").sort((a, b) => b.when - a.when);
    body = `<div class="verdict v-${esc(r.verdict)}">${esc(r.verdict)}<small>${esc(r.summary)}</small></div>
      <div class="stats">${["cheats", "indications", "files", "defender", "devices"].map(k => `<button type="button" data-sec="${k}"><b>${c[k]}</b>${SECTIONS.find(s => s[0] === k)[1]}</button>`).join("")}</div>
      <h2>Past use timeline</h2><p class="sub">When each flagged item was last run, opened, downloaded or deleted, newest first.</p>
      ${tl.length ? `<div class="tbl"><table><thead><tr><th>When</th><th>Level</th><th>Where</th><th>Item</th></tr></thead><tbody>${tl.map(x => `<tr><td class="num">${esc(fmtUnix(x.when))}</td><td><span class="pill l-${esc(x.level)}">${esc(x.level)}</span></td><td>${esc(x.area)}</td><td class="path">${esc(x.what)}</td></tr>`).join("")}</tbody></table></div>` : `<div class="list"><div class="empty">No dated hack activity in this scan.</div></div>`}
      <h2>Scanner notes</h2><ul class="notes">${(r.notes || []).map(n => `<li>${esc(n)}</li>`).join("") || "<li>None</li>"}</ul>`;
  } else if (section === "system") {
    const rows = [["Scanner version", r.version], ["Run as admin", r.admin ? "yes" : "NO (some checks skipped)"], ["Files checked", r.files_checked], ...(r.system_info || [])];
    body = `<h2>System Information</h2><div class="tbl"><table><tbody>${rows.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("")}</tbody></table></div>`;
  } else if (section === "accounts") {
    const a = r.accounts || [];
    body = `<h2>Alt Accounts</h2><p class="sub">${BLURB.accounts}</p>` + (a.length
      ? `<div class="tbl"><table><thead><tr><th>Where</th><th>Account</th><th>Detail</th></tr></thead><tbody>${a.map(([w, n, d]) => `<tr><td>${esc(w)}</td><td class="path">${esc(n)}</td><td>${esc(d)}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="list"><div class="empty">No accounts found.</div></div>`);
  } else {
    const items = section === "cheats" ? f.filter(x => x.level === "HIGH") : f.filter(x => x.section === section);
    body = `<h2>${SECTIONS.find(s => s[0] === section)[1]}</h2><p class="sub">${BLURB[section]}</p>` + findingsTable(items, section === "cheats" ? "No cheats found." : "Nothing found.");
  }
  $("#detail").innerHTML = `<div class="report"><nav class="rail" aria-label="Report sections">${rail}</nav><div class="body">
    <div class="meta">
      <div><div class="lbl">Session PIN</div><div class="big">${esc(r.pin)}</div></div>
      <div><div class="lbl">Player</div><b>${esc(r.player || "—")}</b></div>
      <div><div class="lbl">Game</div><b>${esc(r.game)}</b></div>
      <div><div class="lbl">PC</div><b>${esc(r.pc)}</b> (${esc(r.user)})</div>
      <div><div class="lbl">Scanned</div><b>${esc(fmtTime(r.time))}</b></div>
      <div class="acts" id="acts"><button type="button" id="close">Close</button><button type="button" class="danger" id="del">Delete</button></div>
    </div>${body}</div></div>`;
}

$("#detail").addEventListener("click", async e => {
  const s = e.target.closest("[data-sec]");
  if (s) { e.preventDefault(); section = s.dataset.sec; renderReport(); return; }
  if (e.target.id === "close") { openPin = null; openReport = null; $("#detail").hidden = true; renderList(); return; }
  if (e.target.id === "del") {
    e.target.outerHTML = `<span class="confirm">Delete ${esc(openPin)} for good? <button type="button" class="danger" id="del-yes">Delete</button><button type="button" id="del-no">Keep</button></span>`;
    return;
  }
  if (e.target.id === "del-no") { openReport ? renderReport() : openScan(openPin); return; }
  if (e.target.id === "del-yes") {
    try { await api(`/api/report?pin=${openPin}`, { method: "DELETE" }); openPin = null; openReport = null; $("#detail").hidden = true; await load(); }
    catch (err) { setMsg("Could not delete: " + err.message, "err"); }
  }
});

/* ---------- start ---------- */
function start() {
  $("#login-view").hidden = true; $("#app").hidden = false;
  load();
  clearInterval(timer);
  timer = setInterval(async () => {
    if (document.hidden || !key) return;
    const waiting = openPin && sessions.find(s => s.pin === openPin && s.status !== "done");
    await load();
    if (waiting && sessions.find(s => s.pin === openPin && s.status === "done")) openScan(openPin);
  }, 15000);
}
if (key) start(); else signOut();
