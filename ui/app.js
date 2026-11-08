"use strict";
/* khali_FORENSEEKS front end: plain JavaScript, no build step.
   Talks to the FastAPI backend under /api. Pages are chosen by the URL hash (#/cases, #/audit ...). */

const API_BASE = window.API_BASE || "/api";
const PAGE_SIZE = 50;

// ---------- small helpers -------------------------------------------------------------
const store = {
  get(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { v === null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch (e) { /* ignore */ } },
};
const state = { token: store.get("token"), user: null, auditOffset: 0 };
let renderId = 0;

/** Build a DOM element. Text is always inserted as text (never HTML), which prevents XSS. */
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function fmtTime(iso) {
  if (!iso) return "";
  const hasZone = /[zZ]$|[+-]\d\d:?\d\d$/.test(iso);
  const d = new Date(hasZone ? iso : iso + "Z"); // server times are UTC
  return isNaN(d) ? iso : d.toLocaleString();
}
function fmtSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}
function formatDetail(d) {
  if (typeof d === "string") return d;
  if (Array.isArray(d)) return d.map((x) => (x.loc ? x.loc.slice(1).join(".") + ": " : "") + x.msg).join("; ");
  return JSON.stringify(d);
}
function badge(text) {
  const key = String(text).replace(/[^a-z_]/gi, "");
  return h("span", { class: "badge b-" + key }, String(text).replace(/_/g, " "));
}
function label(text, input) { return h("label", {}, h("span", {}, text), input); }
function who(id) { return id === null || id === undefined ? "(unknown)" : "User #" + id; }

function table(headers, rows, empty) {
  if (!rows.length) return h("p", { class: "muted" }, empty || "Nothing to show yet.");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, headers.map((x) => h("th", {}, x)))),
    h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => h("td", {}, c)))))));
}

function toast(msg, kind, ms) {
  const t = h("div", { class: "toast " + (kind || "") }, msg);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), ms || 4500);
}

/** A button that disables itself while its action runs and shows any error as a toast. */
function button(text, cls, fn) {
  const b = h("button", { class: cls || "", type: "button" }, text);
  b.addEventListener("click", async () => {
    b.disabled = true;
    try { await fn(); } catch (e) { toast(e.message, "error", 7000); } finally { b.disabled = false; }
  });
  return b;
}

function hashCell(hash) {
  const copy = button("Copy", "small", async () => {
    try { await navigator.clipboard.writeText(hash); toast("Hash copied.", "ok", 1800); }
    catch (e) { toast("Could not copy. Select the hash and copy it manually.", "error"); }
  });
  return h("div", { class: "actions" }, h("span", { class: "hash", title: hash }, hash.slice(0, 16) + "…"), copy);
}

// ---------- API -----------------------------------------------------------------------
async function api(path, opts) {
  const { method = "GET", json, form, raw = false } = opts || {};
  const headers = {};
  if (state.token) headers.Authorization = "Bearer " + state.token;
  let body;
  if (json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
  else if (form) body = form; // FormData or URLSearchParams: the browser sets the content type
  let res;
  try { res = await fetch(API_BASE + path, { method, headers, body }); }
  catch (e) { throw new Error("Cannot reach the server. Is the backend running?"); }
  if (res.status === 401 && state.token) { logout(); throw new Error("Your session has expired. Please sign in again."); }
  if (!res.ok) {
    let msg = res.statusText || "Request failed";
    try { msg = formatDetail((await res.json()).detail); } catch (e) { /* keep default */ }
    throw new Error(msg);
  }
  return raw ? res : res.json();
}

async function download(path, filename) {
  const res = await api(path, { raw: true });
  const url = URL.createObjectURL(await res.blob());
  const a = h("a", { href: url, download: filename });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// ---------- session & layout ----------------------------------------------------------
function logout() {
  store.set("token", null);
  state.token = null; state.user = null; state.auditOffset = 0;
  if (location.hash === "#/login") render(); else location.hash = "#/login";
}

function renderHeader() {
  const box = document.getElementById("header");
  box.replaceChildren();
  if (!state.user) return;
  const role = state.user.role;
  const links = [];
  if (role !== "admin") links.push(["#/cases", "Cases"]);
  if (role === "reviewer" || role === "admin") links.push(["#/audit", "Audit log"]);
  if (role === "admin") links.push(["#/users", "Users"]);
  const search = role === "admin" ? null : h("form", { class: "search no-print", onsubmit: onSearch },
    h("input", { type: "search", placeholder: "Search cases and evidence…", "aria-label": "Search", minlength: 2 }),
    h("button", { type: "submit" }, "Search"));
  box.append(h("div", { class: "bar" },
    h("div", { class: "brand" }, "🔍 khali_FORENSEEKS"),
    h("nav", {}, links.map(([href, text]) => h("a", { href, class: location.hash.startsWith(href) ? "active" : "" }, text))),
    search,
    h("div", { class: "who" }, h("span", { class: "role" }, role), h("strong", {}, state.user.username),
      h("button", { class: "link", type: "button", onclick: logout }, "Log out"))));
}

function onSearch(e) {
  e.preventDefault();
  const q = e.target.querySelector("input").value.trim();
  if (q.length < 2) { toast("Type at least 2 characters to search."); return; }
  location.hash = "#/search/" + encodeURIComponent(q);
}

// ---------- views ---------------------------------------------------------------------
async function viewLogin() {
  const user = h("input", { autocomplete: "username", required: true, autofocus: true });
  const pass = h("input", { type: "password", autocomplete: "current-password", required: true });
  const err = h("p", { class: "form-error", role: "alert" });
  const form = h("form", { class: "card login", onsubmit: async (e) => {
    e.preventDefault(); err.textContent = "";
    try {
      const data = await api("/auth/login", { method: "POST", form: new URLSearchParams({ username: user.value, password: pass.value }) });
      state.token = data.access_token; store.set("token", state.token);
      state.user = { username: data.username, role: data.role };
      location.hash = data.role === "admin" ? "#/users" : "#/cases";
    } catch (ex) { err.textContent = ex.message; }
  } },
    h("div", { class: "brand-title" }, "🔍 khali_FORENSEEKS"), h("h1", {}, "Sign in"), h("p", { class: "muted" }, "Cloud-Based Digital Forensics System"),
    label("Username", user), label("Password", pass), err, h("button", { type: "submit", class: "primary" }, "Sign in"));
  return h("div", { class: "center" }, form);
}

async function viewCases() {
  const cases = await api("/cases");
  const isInv = state.user.role === "investigator";
  const wrap = h("div", {}, h("h1", {}, "Cases"));
  if (isInv) {
    const title = h("input", { required: true, minlength: 3, maxlength: 200, placeholder: "e.g. Suspicious SSH logins" });
    const desc = h("textarea", { maxlength: 5000, placeholder: "What is this case about?" });
    wrap.append(h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      try {
        const c = await api("/cases", { method: "POST", json: { title: title.value, description: desc.value } });
        toast("Case " + c.case_reference + " created.", "ok");
        location.hash = "#/cases/" + c.case_id;
      } catch (ex) { toast(ex.message, "error", 7000); }
    } }, h("h2", {}, "New case"), label("Title", title), label("Description (optional)", desc),
      h("button", { type: "submit", class: "primary" }, "Create case")));
  }
  wrap.append(h("div", { class: "card" }, table(["Reference", "Title", "Status", "Created"],
    cases.map((c) => [h("a", { href: "#/cases/" + c.case_id }, c.case_reference), c.title, badge(c.status), fmtTime(c.created_at)]),
    isInv ? "No cases yet. Create your first case above." : "No cases have been created yet.")));
  return wrap;
}

async function doVerify(id) {
  const v = await api(`/evidence/${id}/verify`, { method: "POST" });
  if (v.result === "match") toast("Integrity verified: the hashes match.", "ok");
  else if (v.result === "mismatch") toast("INTEGRITY FAILURE: the file no longer matches its registered hash.", "error", 9000);
  else toast("Verification could not be completed (stored file unavailable).", "error", 7000);
  await render();
}

async function viewCase(id) {
  const [c, evidence] = await Promise.all([api(`/cases/${id}`), api(`/cases/${id}/evidence`)]);
  const isInv = state.user.role === "investigator";
  const wrap = h("div", {});
  const toggle = isInv ? button(c.status === "open" ? "Close case" : "Reopen case", "", async () => {
    await api(`/cases/${id}`, { method: "PATCH", json: { status: c.status === "open" ? "closed" : "open" } });
    await render();
  }) : null;
  wrap.append(h("p", {}, h("a", { href: "#/cases" }, "← All cases")),
    h("div", { class: "card" },
      h("div", { class: "row" }, h("div", {}, h("h1", {}, c.title), h("span", { class: "muted" }, c.case_reference + " · created " + fmtTime(c.created_at))),
        h("div", { class: "row-actions no-print" }, badge(c.status), h("a", { class: "btn", href: `#/cases/${id}/report` }, "Case report"), toggle)),
      c.description ? h("p", {}, c.description) : null));

  if (isInv && c.status === "open") {
    const file = h("input", { type: "file" });
    wrap.append(h("div", { class: "card" }, h("h2", {}, "Register evidence"),
      h("p", { class: "muted" }, "The SHA-256 hash is calculated on arrival and recorded in the chain of custody."), file,
      h("p", {}, button("Register evidence", "primary", async () => {
        if (!file.files[0]) throw new Error("Choose a file first.");
        const fd = new FormData(); fd.append("file", file.files[0]);
        const ev = await api(`/cases/${id}/evidence`, { method: "POST", form: fd });
        toast(`Registered ${ev.filename}. SHA-256 ${ev.sha256_hash.slice(0, 12)}…`, "ok");
        await render();
      }))));
  }
  wrap.append(h("div", { class: "card" }, h("h2", {}, "Evidence (" + evidence.length + ")"),
    table(["File", "Size", "SHA-256", "Status", "Registered", ""], evidence.map((e) => [
      h("a", { href: "#/evidence/" + e.evidence_id }, e.filename), fmtSize(e.file_size), hashCell(e.sha256_hash), badge(e.status), fmtTime(e.created_at),
      h("div", { class: "actions" },
        isInv ? button("Verify", "small", () => doVerify(e.evidence_id)) : null,
        button("Download", "small", () => download(`/evidence/${e.evidence_id}/download`, e.filename)),
        h("a", { class: "btn small", href: "#/evidence/" + e.evidence_id }, "Custody")),
    ]), "No evidence registered yet.")));
  return wrap;
}

async function viewEvidence(id) {
  const [e, custody, vers] = await Promise.all([
    api(`/evidence/${id}`), api(`/evidence/${id}/custody`), api(`/evidence/${id}/verifications`)]);
  const isInv = state.user.role === "investigator";
  return h("div", {},
    h("p", {}, h("a", { href: "#/cases/" + e.case_id }, "← Back to case")),
    h("div", { class: "card" },
      h("div", { class: "row" }, h("h1", {}, e.filename),
        h("div", { class: "row-actions" }, badge(e.status),
          isInv ? button("Verify integrity", "primary", () => doVerify(id)) : null,
          button("Download", "", () => download(`/evidence/${id}/download`, e.filename)))),
      h("dl", {}, h("dt", {}, "Evidence ID"), h("dd", {}, "#" + e.evidence_id), h("dt", {}, "File type"), h("dd", {}, e.file_type),
        h("dt", {}, "Size"), h("dd", {}, fmtSize(e.file_size) + " (" + e.file_size + " bytes)"),
        h("dt", {}, "Registered"), h("dd", {}, fmtTime(e.created_at) + " by " + who(e.submitted_by)),
        h("dt", {}, "SHA-256"), h("dd", {}, h("span", { class: "hash" }, e.sha256_hash)))),
    h("div", { class: "card" }, h("h2", {}, "Chain of custody"),
      table(["Time", "Event", "User", "Details"], custody.map((c) => [fmtTime(c.event_time), badge(c.event_type), who(c.actor_id), c.details]))),
    h("div", { class: "card" }, h("h2", {}, "Verification history"),
      table(["Time", "Result", "Calculated hash", "Requested by"], vers.map((v) => [fmtTime(v.verification_time), badge(v.result),
        h("span", { class: "hash" }, v.calculated_hash || "n/a"), who(v.requested_by)]), "This item has not been verified yet.")));
}

async function viewReport(id) {
  const r = await api(`/cases/${id}/report`);
  const wrap = h("div", {}, h("div", { class: "brand-title" }, "🔍 khali_FORENSEEKS"), h("p", { class: "no-print" }, h("a", { href: "#/cases/" + id }, "← Back to case")),
    h("div", { class: "row no-print" }, h("h1", {}, "Digital evidence report"),
      h("div", { class: "row-actions" }, button("Print / save as PDF", "primary", async () => window.print()),
        button("Download JSON", "", async () => {
          const url = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: "application/json" }));
          const a = h("a", { href: url, download: "report-" + r.case.case_reference + ".json" });
          document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
        }))),
    h("div", { class: "card" }, h("h2", {}, r.case.title),
      h("dl", {}, h("dt", {}, "Case reference"), h("dd", {}, r.case.case_reference), h("dt", {}, "Status"), h("dd", {}, r.case.status),
        h("dt", {}, "Generated"), h("dd", {}, fmtTime(r.generated_at) + " by " + r.generated_by)),
      h("div", { class: "banner " + (r.audit_chain.valid ? "ok" : "bad") },
        r.audit_chain.valid ? `Audit log integrity: VALID (${r.audit_chain.entries_checked} entries checked)`
          : `Audit log integrity: TAMPERING DETECTED at entry #${r.audit_chain.first_invalid_audit_id}`)));
  if (!r.evidence.length) wrap.append(h("div", { class: "card" }, h("p", { class: "muted" }, "No evidence has been registered for this case.")));
  for (const e of r.evidence) {
    wrap.append(h("div", { class: "card" }, h("h2", {}, e.filename + " ", badge(e.status)),
      h("dl", {}, h("dt", {}, "Size"), h("dd", {}, fmtSize(e.file_size)), h("dt", {}, "Registered"), h("dd", {}, fmtTime(e.registered_at)),
        h("dt", {}, "SHA-256"), h("dd", {}, h("span", { class: "hash" }, e.sha256_hash))),
      h("h2", {}, "Verifications"), table(["Time", "Result", "Calculated hash"], e.verifications.map((v) => [fmtTime(v.time), badge(v.result),
        h("span", { class: "hash" }, v.calculated_hash || "n/a")]), "Not verified yet."),
      h("h2", {}, "Chain of custody"), table(["Time", "Event", "User", "Details"], e.custody.map((c) => [fmtTime(c.time), badge(c.event), who(c.actor_id), c.details]))));
  }
  wrap.append(h("p", { class: "muted" }, "Note: a matching hash shows that the file is unchanged since registration. It does not by itself prove the origin or authenticity of the file, or its legal admissibility."));
  return wrap;
}

async function viewAudit() {
  const rows = await api(`/audit?limit=${PAGE_SIZE}&offset=${state.auditOffset}`);
  const result = h("div", {});
  const wrap = h("div", {}, h("h1", {}, "Audit log"));
  wrap.append(h("div", { class: "card" }, h("div", { class: "row" },
    h("p", { class: "muted" }, "Every entry is linked to the previous one by a hash. Editing or deleting history breaks the chain."),
    button("Verify audit chain", "primary", async () => {
      const r = await api("/audit/verify-chain");
      result.replaceChildren(h("div", { class: "banner " + (r.valid ? "ok" : "bad") }, r.valid
        ? `Chain intact: ${r.entries_checked} entries checked.` : `TAMPERING DETECTED at audit entry #${r.first_invalid_audit_id} (${r.entries_checked} entries were valid before it).`));
    })), result));
  wrap.append(h("div", { class: "card" }, table(["#", "Time", "User", "Action", "Resource", "Outcome"], rows.map((a) => [
    a.audit_id, fmtTime(a.event_time), a.actor_id === null ? "(none)" : who(a.actor_id), a.action,
    a.resource_type + (a.resource_id ? " " + a.resource_id : ""), badge(a.outcome)]), "No audit entries yet."),
    h("div", { class: "row-actions" },
      button("← Newer", "small", async () => { state.auditOffset = Math.max(0, state.auditOffset - PAGE_SIZE); await render(); }),
      button("Older →", "small", async () => { if (rows.length === PAGE_SIZE) { state.auditOffset += PAGE_SIZE; await render(); } else toast("No older entries."); }))));
  return wrap;
}

async function viewUsers() {
  const users = await api("/users");
  const username = h("input", { required: true, minlength: 3, maxlength: 50, pattern: "[A-Za-z0-9_.\\-]+", autocomplete: "off" });
  const password = h("input", { type: "password", required: true, minlength: 8, autocomplete: "new-password" });
  const role = h("select", {}, ["investigator", "reviewer", "admin"].map((r) => h("option", { value: r }, r)));
  const patch = async (u, body, msg) => { await api("/users/" + u.user_id, { method: "PATCH", json: body }); toast(msg, "ok"); await render(); };
  return h("div", {}, h("h1", {}, "Users"),
    h("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault();
      try {
        await api("/users", { method: "POST", json: { username: username.value, password: password.value, role: role.value } });
        toast("User " + username.value + " created.", "ok"); await render();
      } catch (ex) { toast(ex.message, "error", 7000); }
    } }, h("h2", {}, "Create user"), h("div", { class: "grid2" }, label("Username", username), label("Temporary password (min. 8 characters)", password)),
      label("Role", role), h("button", { type: "submit", class: "primary" }, "Create user")),
    h("div", { class: "card" }, table(["Username", "Role", "Status", "Created", ""], users.map((u) => {
      const self = u.username === state.user.username;
      const sel = h("select", { disabled: self, "aria-label": "Role for " + u.username },
        ["investigator", "reviewer", "admin"].map((r) => h("option", { value: r, selected: r === u.role }, r)));
      sel.addEventListener("change", async () => { try { await patch(u, { role: sel.value }, "Role updated."); } catch (ex) { toast(ex.message, "error"); await render(); } });
      return [u.username + (self ? " (you)" : ""), sel, badge(u.status), fmtTime(u.created_at), h("div", { class: "actions" },
        self ? null : button(u.status === "active" ? "Disable" : "Enable", "small", () => patch(u, { status: u.status === "active" ? "disabled" : "active" }, "Account updated.")),
        button("Reset password", "small", async () => {
          const pw = window.prompt("New temporary password for " + u.username + " (min. 8 characters):");
          if (pw) await patch(u, { password: pw }, "Password reset.");
        }))];
    }))));
}

async function viewSearch(q) {
  const term = decodeURIComponent(q);
  const r = await api("/search?q=" + encodeURIComponent(term));
  return h("div", {}, h("h1", {}, "Search results for “" + term + "”"),
    h("div", { class: "card" }, h("h2", {}, "Cases (" + r.cases.length + ")"), table(["Reference", "Title", "Status"],
      r.cases.map((c) => [h("a", { href: "#/cases/" + c.case_id }, c.case_reference), c.title, badge(c.status)]), "No matching cases.")),
    h("div", { class: "card" }, h("h2", {}, "Evidence (" + r.evidence.length + ")"), table(["File", "SHA-256", "Status", "Case"],
      r.evidence.map((e) => [h("a", { href: "#/evidence/" + e.evidence_id }, e.filename), h("span", { class: "hash" }, e.sha256_hash.slice(0, 16) + "…"),
        badge(e.status), h("a", { href: "#/cases/" + e.case_id }, "Case #" + e.case_id)]), "No matching evidence.")));
}

// ---------- router --------------------------------------------------------------------
const routes = [
  [/^#\/login$/, viewLogin], [/^#\/cases$/, viewCases], [/^#\/cases\/(\d+)$/, viewCase],
  [/^#\/cases\/(\d+)\/report$/, viewReport], [/^#\/evidence\/(\d+)$/, viewEvidence],
  [/^#\/audit$/, viewAudit], [/^#\/users$/, viewUsers], [/^#\/search\/(.+)$/, viewSearch],
];

async function render() {
  const my = ++renderId;
  const app = document.getElementById("app");
  const hash = location.hash;
  if (!state.token) {
    renderHeader();
    if (hash !== "#/login") { location.hash = "#/login"; return; }
  } else if (!state.user) {
    try { state.user = await api("/auth/me"); } catch (e) { if (state.token) logout(); return; }
    if (my !== renderId) return;
  }
  if (state.token && (hash === "" || hash === "#/" || hash === "#/login")) {
    location.hash = state.user.role === "admin" ? "#/users" : "#/cases"; return;
  }
  renderHeader();
  let found = null;
  for (const [re, view] of routes) { const m = hash.match(re); if (m) { found = [view, m.slice(1)]; break; } }
  if (!found) { app.replaceChildren(h("p", { class: "muted" }, "Page not found. ", h("a", { href: "#/cases" }, "Go to cases"))); return; }
  try {
    const node = await found[0](...found[1]);
    if (my === renderId) app.replaceChildren(node);
  } catch (e) {
    if (my === renderId) app.replaceChildren(h("div", { class: "card error" }, h("h2", {}, "Something went wrong"), h("p", {}, e.message)));
  }
}

window.addEventListener("hashchange", render);
render();
