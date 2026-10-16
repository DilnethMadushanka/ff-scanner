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
let key = "", signup = false, owner = false, sessions = [], openPin = null, openReport = null, section = "summary", timer = null;

try { key = localStorage.getItem("ffscan-auth") || ""; } catch (e) {}

async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "x-auth": key, ...(opts.headers || {}) } });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { signOut("Please sign in again."); throw new Error("Signed out."); }
  if (!r.ok) throw new Error(data.error || `Error ${r.status}`);
  return data;
}

function fmtTime(t) { if (!t) return "—"; const d = new Date(t); return isNaN(d) ? String(t) : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
function fmtUnix(t) { return t ? fmtTime(t * 1000) : "—"; }
function setMsg(text, kind) { const m = $("#msg"); m.textContent = text; m.className = kind || ""; }
const LIVE_GAP = 90 * 1000; // no update for this long while scanning = the scanner was closed
const isLive = s => s.status === "scanning" && Date.now() - Date.parse(s.lastSeen || 0) < LIVE_GAP;
const verdictOf = s => s.status === "done" ? s.verdict : s.status === "waiting" ? "WAITING" : isLive(s) ? "LIVE" : "STOPPED";
const pillText = s => verdictOf(s) === "LIVE" && s.total ? `LIVE ${s.step}/${s.total}` : verdictOf(s);

/* ---------- sign in ---------- */
function signOut(message) {
  key = ""; try { localStorage.removeItem("ffscan-auth"); } catch (e) {}
  clearInterval(timer); $("#app").hidden = true; $("#login-view").hidden = false;
  $("#login-msg").textContent = message || "";
}
function setSignup(on) {
  signup = on;
  $("#login-title").textContent = on ? "Create an organizer account" : "Sign in";
  $("#login-go").textContent = on ? "Create account" : "Sign in";
  $("#login-switch").textContent = on ? "Already have an account? Sign in" : "New organizer? Create an account";
  $("#pw").autocomplete = on ? "new-password" : "current-password";
  $("#login-msg").textContent = "";
}
$("#login-switch").addEventListener("click", e => { e.preventDefault(); setSignup(!signup); });
$("#login-form").addEventListener("submit", async e => {
  e.preventDefault();
  try {
    const r = await fetch("/api/account", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: signup ? "signup" : "login", email: $("#email").value, password: $("#pw").value }) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || "Sign-in failed.");
    key = d.token; $("#pw").value = "";
    try { localStorage.setItem("ffscan-auth", key); } catch (x) {}
    start();
  } catch (err) { $("#login-msg").textContent = err.message; }
});
$("#logout").addEventListener("click", () => {
  fetch("/api/account", { method: "POST", headers: { "Content-Type": "application/json", "x-auth": key }, body: '{"action":"logout"}' }).catch(() => {});
  signOut();
});

/* ---------- plan ---------- */
async function loadPlan() {
  let a;
  try { a = await api("/api/account"); } catch (e) { return; }
  const p = a.plan, bar = $("#planbar"), full = p.limit != null && a.used >= p.limit;
  const buy = Object.entries(a.checkout || {}).filter(([k]) => k !== p.plan || !p.active)
    .map(([k, url]) => `<a class="btn${p.active ? "" : " primary"}" href="${esc(url)}" target="_blank" rel="noopener">${p.active ? "Switch to" : "Buy"} ${esc(a.plans[k].name)} · ${esc(a.plans[k].price)}</a>`).join("");
  const manage = a.portal ? `<a class="btn" href="${esc(a.portal)}" target="_blank" rel="noopener">Manage billing</a>` : "";
  bar.className = "planbar" + (p.active && !full ? "" : " off");
  if (!p.active) {
    bar.innerHTML = `<div><div class="lbl">${esc(a.email)}</div><div class="big">${p.plan ? `${esc(p.name)} plan ended` : "No active plan"}</div>
      <div>Choose a plan to create session PINs. Pay with the same email; your plan turns on here within a minute.</div></div>
      <div class="acts">${buy || "<span>Plans are not set up on this site yet.</span>"}${manage}</div>`;
  } else {
    const pct = p.limit ? Math.min(100, Math.round(a.used * 100 / p.limit)) : 0;
    const when = p.until ? new Date(p.until).toLocaleDateString([], { month: "short", day: "numeric" }) : "";
    const renew = p.status === "cancelled" ? `Ends ${esc(when)}` : when ? `Renews ${esc(when)}` : "";
    bar.innerHTML = `<div><div class="lbl">${esc(a.email)}</div><div class="big">${esc(p.name)}</div><div>${renew}</div></div>
      <div class="meter">${p.limit == null ? `<b>${a.used}</b> devices scanned this month` : `<b>${a.used} of ${p.limit}</b> devices scanned this month${full ? ". Upgrade to scan more." : ""}<div class="track"><i class="${full ? "full" : ""}" style="width:${pct}%"></i></div>`}</div>
      <div class="acts">${p.plan === "owner" ? "" : buy}${manage}</div>`;
  }
  $("#new-form button[type=submit]").disabled = !p.active || full;
}

/* ---------- sessions ---------- */
async function load() {
  try { const d = await api("/api/sessions"); sessions = d.sessions; owner = !!d.owner; renderList(); }
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
      <ol><li>Send the player this download link: <a href="/dl/${esc(session.pin)}">${esc(location.origin)}/dl/${esc(session.pin)}</a></li>${phone}
      <li>They right-click FFScanner-${esc(session.pin)}.exe and choose Run as administrator. Don't rename the file: the PIN is in its name.</li>
      <li>The scan starts with this session's settings and the result shows here when it finishes.</li></ol>
      <div class="topbar"><button type="button" id="copy-pin">Copy PIN</button><button type="button" id="copy-link">Copy link</button></div>
      </div>`;
    $("#n-player").value = ""; setMsg("");
    await load(); loadPlan();
  } catch (err) { setMsg(err.message, "err"); }
});
$("#created").addEventListener("click", async e => {
  if (e.target.id !== "copy-pin" && e.target.id !== "copy-link") return;
  const pin = $("#created .big").textContent;
  const text = e.target.id === "copy-pin" ? pin : `${location.origin}/dl/${pin}`;
  try { await navigator.clipboard.writeText(text); e.target.textContent = "Copied"; } catch (x) { e.target.textContent = text; }
});

function renderList() {
  const q = $("#q").value.trim().toLowerCase(), fv = $("#fv").value;
  const rows = sessions.filter(s => (!fv || verdictOf(s) === fv) && (!q || [s.player, s.scannedPlayer, s.pin, s.pc, s.gameName, s.org].join(" ").toLowerCase().includes(q)));
  const t = { WAITING: 0, LIVE: 0, STOPPED: 0, SUSPICIOUS: 0, REVIEW: 0, CLEAN: 0 }; sessions.forEach(s => t[verdictOf(s)] = (t[verdictOf(s)] || 0) + 1);
  $("#tally").innerHTML = `<div><b>${t.WAITING}</b>Waiting</div><div class="t-ok"><b>${t.LIVE}</b>Scanning now</div><div class="t-hi"><b>${t.STOPPED}</b>Stopped</div><div class="t-hi"><b>${t.SUSPICIOUS}</b>Suspicious</div><div class="t-me"><b>${t.REVIEW}</b>Review</div><div class="t-ok"><b>${t.CLEAN}</b>Clean</div>`;
  if (!sessions.length) { $("#list").innerHTML = `<div class="empty"><b>No sessions yet</b>Create a session PIN above for the first player.</div>`; return; }
  if (!rows.length) { $("#list").innerHTML = `<div class="empty"><b>No matching sessions</b>Try another name or PIN.</div>`; return; }
  $("#list").innerHTML = `<table><thead><tr><th>PIN</th><th>Player</th>${owner ? `<th class="hide-sm">Organizer</th>` : ""}<th class="hide-sm">Game</th><th class="hide-sm">PC</th><th>Created</th><th>Result</th><th class="num">High / Med</th></tr></thead><tbody>${
    rows.map(s => `<tr class="row${s.pin === openPin ? " sel" : ""}" tabindex="0" data-pin="${esc(s.pin)}">
      <td class="pin">${esc(s.pin)}</td><td>${esc(s.player || s.scannedPlayer || "—")}</td>
      ${owner ? `<td class="hide-sm">${esc(s.org || "You")}</td>` : ""}<td class="hide-sm">${esc(s.gameName)} · ${esc(MODE[s.mode] || "")}</td><td class="hide-sm">${esc(s.pc || "—")}</td>
      <td class="num">${esc(fmtTime(s.created))}</td>
      <td><span class="pill v-${esc(verdictOf(s))}">${esc(pillText(s))}</span>${s.status !== "done" && s.status !== "waiting" && s.high ? ` <span class="pill v-SUSPICIOUS">${s.high} HIGH</span>` : ""}${s.earlierHigh ? ` <span class="pill v-STOPPED" title="An earlier scan with this PIN was stopped and had HIGH findings">+${s.earlierHigh} earlier</span>` : ""}</td>
      <td class="num">${s.status !== "waiting" ? `${s.high ?? 0} / ${s.medium ?? 0}` : "—"}</td></tr>`).join("")
  }</tbody></table>`;
}
$("#list").addEventListener("click", e => { const r = e.target.closest(".row"); if (r) openScan(r.dataset.pin); });
$("#list").addEventListener("keydown", e => { const r = e.target.closest(".row"); if (r && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openScan(r.dataset.pin); } });
$("#q").addEventListener("input", renderList);
$("#fv").addEventListener("change", renderList);

/* ---------- report ---------- */
async function openScan(pin, quiet) {
  if (!quiet) { openPin = pin; section = "summary"; renderList(); }
  const d = $("#detail"); d.hidden = false;
  const s = sessions.find(x => x.pin === pin);
  if (s && s.status === "waiting") {
    d.innerHTML = `<div class="list"><div class="empty"><b>Waiting for the scan</b>PIN ${esc(pin)} has not uploaded a result yet. This page checks again every few seconds.
      <p><button type="button" class="danger" id="del">Delete session</button></p></div></div>`;
    return;
  }
  if (!quiet) d.innerHTML = `<div class="list"><div class="empty"><b>Opening scan ${esc(pin)}…</b></div></div>`;
  try {
    const r = (await api(`/api/report?pin=${pin}`)).report;
    if (openPin !== pin) return;
    openReport = r; renderReport();
    if (!quiet) d.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  catch (e) { if (quiet) return; d.innerHTML = `<div class="list"><div class="empty"><b>Could not open the report</b>${esc(e.message)}</div></div>`; }
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
  const s = sessions.find(x => x.pin === r.pin) || {};
  let banner = "";
  if (r.live) {
    const p = r.progress || {}, pct = p.total ? Math.round(p.step * 100 / p.total) : 0;
    banner = verdictOf(s) === "LIVE"
      ? `<div class="livebar"><span class="pill v-LIVE">LIVE</span> <b>Scan running, step ${esc(p.step)} of ${esc(p.total)}.</b> ${esc(p.now)}<br><small>This page updates every few seconds. The result can still change.</small><div class="track"><i style="width:${pct}%"></i></div></div>`
      : `<div class="livebar stopped"><b>The scan stopped before it finished</b> (step ${esc(p.step)} of ${esc(p.total)}${r.stopped ? ", the scanner was closed" : ", the scanner lost contact"}). Below is everything it found until then. Last update ${esc(fmtTime(s.lastSeen))}.</div>`;
  }
  const earlier = r.earlier || [];
  if (earlier.length) {
    banner += `<div class="livebar stopped"><b>${earlier.length} earlier scan${earlier.length > 1 ? "s" : ""} with this PIN did not finish.</b> ${earlier.map(e => `Run at ${esc(fmtTime(e.time))}: ${(e.findings || []).filter(f => f.level === "HIGH").length} HIGH, ${(e.findings || []).filter(f => f.level === "MEDIUM").length} MEDIUM, stopped at step ${esc((e.progress || {}).step ?? "?")} of ${esc((e.progress || {}).total ?? "?")}.`).join(" ")} Their findings are listed at the end of the Summary.</div>`;
  }
  let body = "";
  if (section === "summary") {
    const tl = f.filter(x => x.when && x.level !== "INFO").sort((a, b) => b.when - a.when);
    body = `<div class="verdict v-${esc(r.verdict)}">${esc(r.verdict)}${r.live ? " so far" : ""}<small>${esc(r.summary)}</small></div>
      <div class="stats">${["cheats", "indications", "files", "defender", "devices"].map(k => `<button type="button" data-sec="${k}"><b>${c[k]}</b>${SECTIONS.find(s => s[0] === k)[1]}</button>`).join("")}</div>
      <h2>Past use timeline</h2><p class="sub">When each flagged item was last run, opened, downloaded or deleted, newest first.</p>
      ${tl.length ? `<div class="tbl"><table><thead><tr><th>When</th><th>Level</th><th>Where</th><th>Item</th></tr></thead><tbody>${tl.map(x => `<tr><td class="num">${esc(fmtUnix(x.when))}</td><td><span class="pill l-${esc(x.level)}">${esc(x.level)}</span></td><td>${esc(x.area)}</td><td class="path">${esc(x.what)}</td></tr>`).join("")}</tbody></table></div>` : `<div class="list"><div class="empty">No dated hack activity in this scan.</div></div>`}
      ${earlier.map((e, i) => `<h2>Earlier unfinished scan ${i + 1}</h2><p class="sub">Started ${esc(fmtTime(e.time))}. The player stopped or restarted this scan.</p>${findingsTable((e.findings || []).filter(x => x.level !== "INFO"), "Nothing found before it stopped.")}`).join("")}
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
      <div class="acts" id="acts"><button type="button" id="pdf">Download PDF</button><button type="button" id="close">Close</button><button type="button" class="danger" id="del">Delete</button></div>
    </div>${banner}${body}</div></div>`;
}

/* ---------- PDF: the whole report on paper, saved with the browser's "Save as PDF" ---------- */
function printReport(r) {
  const f = r.findings || [], c = counts(r);
  const tbl = (items, empty) => items.length
    ? `<table><thead><tr><th>Level</th><th>Where</th><th>Item</th><th>Why</th></tr></thead><tbody>${items.map(x => `<tr><td><b class="lv l-${esc(x.level)}">${esc(x.level)}</b></td><td>${esc(x.area)}</td><td class="path">${esc(x.what)}</td><td>${esc(x.reason)}</td></tr>`).join("")}</tbody></table>`
    : `<p class="none">${esc(empty)}</p>`;
  const sec = (k, items, empty) => `<h2>${SECTIONS.find(s => s[0] === k)[1]} (${items.length})</h2>${BLURB[k] ? `<p class="sub">${BLURB[k]}</p>` : ""}${tbl(items, empty)}`;
  const tl = f.filter(x => x.when && x.level !== "INFO").sort((a, b) => b.when - a.when);
  const sys = [["Scanner version", r.version], ["Run as admin", r.admin ? "yes" : "NO (some checks skipped)"], ["Files checked", r.files_checked], ...(r.system_info || [])];
  const acc = r.accounts || [];
  const state = r.live ? (r.stopped || verdictOf(sessions.find(x => x.pin === r.pin) || {}) !== "LIVE"
    ? "<p class=\"warn\">This scan stopped before it finished. The report shows what was found until then.</p>"
    : "<p class=\"warn\">This scan was still running when the PDF was made. The result can still change.</p>") : "";
  const earlier = (r.earlier || []).map((e, i) => `<h2>Earlier unfinished scan ${i + 1}</h2><p class="sub">Started ${esc(fmtTime(e.time))}. The player stopped or restarted this scan.</p>${tbl((e.findings || []).filter(x => x.level !== "INFO"), "Nothing found before it stopped.")}`).join("");
  let el = $("#print");
  if (!el) { el = document.createElement("div"); el.id = "print"; document.body.appendChild(el); }
  el.innerHTML = `<h1>FF Scanner report</h1>
    <table class="kv"><tbody>
      <tr><th>Session PIN</th><td><b>${esc(r.pin)}</b></td><th>Player</th><td>${esc(r.player || "—")}</td></tr>
      <tr><th>Game</th><td>${esc(r.game)}</td><th>PC</th><td>${esc(r.pc)} (${esc(r.user)})</td></tr>
      <tr><th>Scanned</th><td>${esc(fmtTime(r.time))}</td><th>Files checked</th><td>${esc(r.files_checked)}</td></tr>
    </tbody></table>
    <div class="verdict v-${esc(r.verdict)}">${esc(r.verdict)}${r.live ? " so far" : ""}<small>${esc(r.summary)}</small></div>${state}
    <p class="sub">Cheats found ${c.cheats} · Key indications ${c.indications} · Suspicious files ${c.files} · Defender history ${c.defender} · Devices removed ${c.devices}</p>
    ${sec("cheats", f.filter(x => x.level === "HIGH"), "No cheats found.")}
    <h2>Past use timeline (${tl.length})</h2><p class="sub">When each flagged item was last run, opened, downloaded or deleted, newest first.</p>
    ${tl.length ? `<table><thead><tr><th>When</th><th>Level</th><th>Where</th><th>Item</th></tr></thead><tbody>${tl.map(x => `<tr><td class="nw">${esc(fmtUnix(x.when))}</td><td><b class="lv l-${esc(x.level)}">${esc(x.level)}</b></td><td>${esc(x.area)}</td><td class="path">${esc(x.what)}</td></tr>`).join("")}</tbody></table>` : `<p class="none">No dated hack activity in this scan.</p>`}
    ${sec("indications", f.filter(x => x.section === "indications"), "Nothing found.")}
    ${sec("files", f.filter(x => x.section === "files"), "Nothing found.")}
    ${sec("defender", f.filter(x => x.section === "defender"), "Nothing found.")}
    ${sec("devices", f.filter(x => x.section === "devices"), "Nothing found.")}
    ${earlier}
    <h2>System Information</h2><table class="kv"><tbody>${sys.map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("")}</tbody></table>
    <h2>Alt Accounts (${acc.length})</h2><p class="sub">${BLURB.accounts}</p>
    ${acc.length ? `<table><thead><tr><th>Where</th><th>Account</th><th>Detail</th></tr></thead><tbody>${acc.map(([w, n, d]) => `<tr><td>${esc(w)}</td><td class="path">${esc(n)}</td><td>${esc(d)}</td></tr>`).join("")}</tbody></table>` : `<p class="none">No accounts found.</p>`}
    <h2>Scanner notes</h2><ul>${(r.notes || []).map(n => `<li>${esc(n)}</li>`).join("") || "<li>None</li>"}</ul>
    <p class="foot">Made ${esc(fmtTime(new Date()))}. Signature checks can be bypassed (renamed or private hacks, cleaned traces), so use this report as a screening aid, not as proof.</p>`;
  const title = document.title;
  document.title = `FFScan-${r.pin}${r.player ? "-" + String(r.player).replace(/[^A-Za-z0-9_-]+/g, "_").slice(0, 30) : ""}`; // the PDF's file name
  const done = () => { document.title = title; el.innerHTML = ""; window.removeEventListener("afterprint", done); };
  window.addEventListener("afterprint", done);
  window.print();
}

$("#detail").addEventListener("click", async e => {
  const s = e.target.closest("[data-sec]");
  if (s) { e.preventDefault(); section = s.dataset.sec; renderReport(); return; }
  if (e.target.id === "pdf") { printReport(openReport); return; }
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
  load(); loadPlan();
  clearInterval(timer);
  let tick = 0;
  timer = setInterval(async () => {
    if (document.hidden || !key) return;
    tick++;
    const before = openPin && sessions.find(s => s.pin === openPin);
    const watching = before && (before.status === "scanning" || before.status === "waiting");
    if (!watching && !sessions.some(isLive) && tick % 3) return; // every 15 s when nothing is running
    await load();
    if (tick % 6 === 0) loadPlan();
    const now = openPin && sessions.find(s => s.pin === openPin);
    if (now && now.status !== "waiting" && (watching || before?.status !== now.status)) {
      if (before.status === "waiting") openScan(openPin); else openScan(openPin, true);
    }
  }, 5000);
}
if (key) start(); else signOut();
