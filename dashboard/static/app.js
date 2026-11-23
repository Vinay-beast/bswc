"use strict";

/* Software Supply Chain Guardian dashboard (vanilla JS, no build step).
 * Data comes only from the read-only API in dashboard/app.py. Values from the scanned
 * repository are untrusted, so every node is built with textContent, never innerHTML. */

const POLL_MS = 5000;
// Agent names are used only to map agents to stages and to order them.
const STAGES = [
  { id: "discover",  name: "Discover",  agents: ["source-deps", "artifact-inspector", "inventory"] },
  { id: "detect",    name: "Detect",    agents: ["detection"] },
  { id: "analyze",   name: "Analyze",   agents: ["analysis"] },
  { id: "remediate", name: "Remediate", agents: ["remediation"] },
  { id: "validate",  name: "Validate",  agents: ["validation"] },
];
const TABS = [
  ["overview", "Overview"], ["sbom", "SBOM"], ["components", "Components"],
  ["graph", "Dependency graph"], ["container", "Container"], ["ci", "CI/CD"],
];
const LABEL = { pending: "Pending", running: "Running", done: "Done", failed: "Failed", stale: "Stale" };

const state = {
  runs: [], app: null, run: null, agents: {}, stage: "discover", tab: "overview",
  panelKey: null, renderToken: 0, cache: new Map(), tables: {},
};

/* ------------------------------------------------------------------ helpers */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (id) => document.getElementById(id);
const enc = encodeURIComponent;
const fmtNum = (n) => (typeof n === "number" ? n.toLocaleString() : n ?? "–");
const dash = () => h("span", { class: "muted" }, "–");

async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} – ${url}`);
  return res.json();
}

function relTime(iso) {
  if (!iso) return "–";
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return iso;
  const s = Math.round((t - Date.now()) / 1000), a = Math.abs(s);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (a < 60) return rtf.format(s, "second");
  if (a < 3600) return rtf.format(Math.round(s / 60), "minute");
  if (a < 86400) return rtf.format(Math.round(s / 3600), "hour");
  return rtf.format(Math.round(s / 86400), "day");
}
const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : "");

function agentState(st) {
  if (!st) return "pending";
  if (st.stale && st.state !== "running") return "stale";
  return LABEL[st.state] ? st.state : "pending";
}
function badge(s, small) {
  const k = LABEL[s] ? s : "pending";
  return h("span", { class: `badge ${k}${small ? " sm" : ""}` }, LABEL[k]);
}
function stageState(statuses) {
  if (!statuses.length) return "pending";
  const s = statuses.map(agentState);
  for (const k of ["failed", "running", "stale", "pending"]) if (s.includes(k)) return k;
  return "done";
}

function api(folder, path) { return `/api/runs/${enc(state.app)}/${enc(folder)}/${path}`; }
function artifactUrl(folder, name, download) {
  return api(folder, `artifact/${enc(name)}${download ? "?download=true" : ""}`);
}

/** Cached fetch keyed by the agent's status (refetched only when the agent re-runs). */
async function load(folder, path) {
  const st = state.agents[folder];
  const key = `${state.app}|${folder}|${st && st.finished_at}|${st && st.run_id}|${path}`;
  if (!state.cache.has(key)) {
    const p = getJSON(api(folder, path));
    state.cache.set(key, p);
    p.catch(() => state.cache.delete(key));
  }
  return state.cache.get(key);
}

function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  return { app: p.get("app"), stage: p.get("stage"), tab: p.get("tab") };
}
function writeHash() {
  const p = new URLSearchParams();
  if (state.app) p.set("app", state.app);
  p.set("stage", state.stage);
  if (state.stage === "discover") p.set("tab", state.tab);
  history.replaceState(null, "", `#${p}`);
}

/* Agents: discovered from the API, matched to stages by status.stage. */
function agentsForStage(stageId) {
  const order = STAGES.find((s) => s.id === stageId).agents;
  return Object.entries(state.agents)
    .filter(([, st]) => st.stage === stageId)
    .sort(([, a], [, b]) => (order.indexOf(a.agent) + 99) % 99 - (order.indexOf(b.agent) + 99) % 99);
}
/* Find the agent folder that produced a given artifact (no hard-coded folder names). */
function folderWith(artifact) {
  const hit = Object.entries(state.agents).find(([, st]) => (st.artifacts || []).some((a) => a.name === artifact));
  return hit ? hit[0] : null;
}

/* ------------------------------------------------------------------ top bar */
function renderAppSelect() {
  const sel = $("app-select");
  const names = state.runs.map((r) => r.app_id);
  const current = [...sel.options].map((o) => o.value);
  if (names.join("|") !== current.join("|")) {
    sel.replaceChildren(...(names.length
      ? state.runs.map((r) => h("option", { value: r.app_id }, r.display_name ? `${r.display_name} (${r.app_id})` : r.app_id))
      : [h("option", { value: "" }, "No runs yet")]));
  }
  sel.disabled = !names.length;
  sel.value = state.app || "";
}

function renderRunMeta() {
  const run = state.run || {};
  const item = (label, value, title) => h("div", null, h("dt", null, label), h("dd", { title }, value));
  $("run-meta").replaceChildren(
    item("Repository", run.repo_url ? h("a", { href: run.repo_url, target: "_blank", rel: "noopener noreferrer" },
      run.repo_url.replace(/^https?:\/\//, "")) : "–", run.repo_url),
    item("Commit", run.commit_sha ? h("span", { class: "mono" }, run.commit_sha.slice(0, 7)) : "–", run.commit_sha),
    item("Run", run.run_id ? h("span", { class: "mono" }, run.run_id) : "–", run.run_id),
    item("Last run", relTime(run.updated_at), fmtDate(run.updated_at)),
  );
}

/* ----------------------------------------------------------------- pipeline */
function renderPipeline() {
  $("pipeline").replaceChildren(...STAGES.map((stage, i) => {
    const agents = agentsForStage(stage.id);
    const rows = agents.length
      ? agents.map(([, st]) => h("li", null, h("span", null, st.agent), badge(agentState(st), true)))
      : stage.agents.map((a) => h("li", null, h("span", null, a), badge("pending", true)));
    return h("button", {
      class: "stage", type: "button", "aria-current": state.stage === stage.id ? "true" : "false",
      onclick: () => selectStage(stage.id),
    },
      h("div", { class: "stage-top" }, h("span", { class: "stage-step" }, `Stage ${i + 1}`),
        badge(stageState(agents.map(([, st]) => st)))),
      h("span", { class: "stage-name" }, stage.name),
      h("ul", { class: "stage-agents" }, rows));
  }));
}

function selectStage(id) {
  if (state.stage === id) return;
  state.stage = id;
  state.panelKey = null;
  writeHash();
  renderPipeline();
  renderPanel();
}
function selectTab(id) {
  if (state.tab === id) return;
  state.tab = id;
  state.panelKey = null;
  writeHash();
  renderPanel();
}

/* -------------------------------------------------------------------- panel */
function statusKey(entries) {
  return entries.map(([f, st]) => `${f}:${st.state}:${st.finished_at}:${st.run_id}:${st.stale}`).join("|");
}

function renderPanel() {
  const stage = STAGES.find((s) => s.id === state.stage);
  const agents = agentsForStage(stage.id);
  const key = `${state.app}|${stage.id}|${state.tab}|${statusKey(agents)}`;
  if (key === state.panelKey) return;
  state.panelKey = key;
  const token = ++state.renderToken;
  const panel = $("panel");

  if (!state.app) {
    panel.replaceChildren(h("div", { class: "empty" }, h("h3", null, "No runs found in outputs/"),
      h("p", null, "Run the Discover stage first: ", h("code", null, "python -m agents.discover --repo <url>"))));
    return;
  }
  const head = h("div", { class: "panel-head" }, h("h2", null, stage.name),
    ...agents.map(([, st]) => h("span", { class: "sub" }, st.agent, " ", badge(agentState(st), true))));
  if (!agents.length) {
    panel.replaceChildren(head, h("div", { class: "empty" }, h("h3", null, "No output yet"),
      h("p", null, `No ${stage.name.toLowerCase()} agent has written results for this app.`)));
    return;
  }
  if (stage.id !== "discover") {
    panel.replaceChildren(head, h("div", { class: "stack" }, ...agents.map(([f, st]) => genericAgentCard(f, st))));
    return;
  }
  const tabs = h("div", { class: "tabs", role: "tablist" }, TABS.map(([id, label]) =>
    h("button", { class: "tab", role: "tab", type: "button", "aria-selected": state.tab === id ? "true" : "false",
                  onclick: () => selectTab(id) }, label)));
  const body = h("div", { id: "tab-body" }, h("p", { class: "muted" }, "Loading…"));
  panel.replaceChildren(head, tabs, body);
  const render = { overview: renderOverview, sbom: renderSbom, components: renderComponents,
                   graph: renderGraph, container: renderContainer, ci: renderCi }[state.tab];
  render(body, token).catch((err) => {
    if (token === state.renderToken) body.replaceChildren(h("div", { class: "error-box" },
      h("strong", null, "Could not load this view"), h("pre", null, String(err.message || err))));
  });
}
const current = (token) => token === state.renderToken;

function genericAgentCard(folder, st) {
  return h("div", { class: "card" }, h("h3", null, st.agent, " ", badge(agentState(st), true)),
    st.error ? h("div", { class: "error-box" }, h("pre", null, st.error)) : null,
    tiles(Object.entries(st.summary || {}).map(([k, v]) => [k.replace(/_/g, " "), v])),
    downloads(folder, st.artifacts || []));
}

function tiles(items) {
  return h("div", { class: "tiles" }, items.map(([label, v, title]) =>
    h("div", { class: "tile", title }, h("div", { class: "tile-value" }, typeof v === "object" && v !== null ? JSON.stringify(v) : fmtNum(v)),
      h("div", { class: "tile-label" }, label))));
}

function downloads(folder, artifacts) {
  if (!artifacts.length) return h("p", { class: "muted" }, "No artifacts listed.");
  return h("ul", { class: "downloads" }, artifacts.map((a) => h("li", null,
    h("div", null, h("div", { class: "a-name" }, a.name),
      h("div", { class: "a-meta" }, `${a.type} · ${a.path}${a.bytes ? ` · ${(a.bytes / 1024).toFixed(0)} KB` : ""}`)),
    h("a", { class: "btn", href: artifactUrl(folder, a.name, true), download: a.name }, "Download"))));
}

function needsInventory(body) {
  const inv = folderWith("graph.json");
  const st = inv && state.agents[inv];
  if (!st || st.state !== "done") {
    const agents = agentsForStage("discover");
    body.replaceChildren(h("div", { class: "empty" },
      h("h3", null, st && st.state === "failed" ? "Inventory failed" : "Inventory not available yet"),
      h("p", null, agents.map(([, s]) => `${s.agent}: ${LABEL[agentState(s)]}`).join(" · ")),
      st && st.error ? h("div", { class: "error-box" }, h("pre", null, st.error)) : null));
    return null;
  }
  return inv;
}

/* ---------------------------------------------------------------- overview */
async function renderOverview(body, token) {
  const inv = needsInventory(body);
  if (!inv) return;
  const st = state.agents[inv];
  const cov = await load(inv, "artifact/coverage.json");
  if (!current(token)) return;
  const s = st.summary || {};
  const t = tiles([
    ["Unique components", s.components], ["Direct", s.direct], ["Transitive", s.transitive],
    ["Max depth", s.max_depth], ["Edges", s.edges], ["Ecosystems", s.ecosystems],
    ["Container packages", s.container_packages], ["Workflows", s.workflows],
    ["Actions not pinned to a SHA", s.actions_not_sha_pinned],
  ]);
  const perTool = Object.entries(cov.per_tool).filter(([, d]) => d.unique_purls);
  const toolTable = h("table", null,
    h("thead", null, h("tr", null, h("th", null, "Source"), h("th", null, "Unique purls"), h("th", null, "Only this source"))),
    h("tbody", null, perTool.map(([tool, d]) => h("tr", null, h("td", null, tool),
      h("td", { class: "num" }, fmtNum(d.unique_purls)), h("td", { class: "num" }, fmtNum(d.only_this_tool))))));
  const lockRows = cov.lockfiles.map((l) => h("li", null, h("span", { class: "mono" }, l.lockfile),
    h("span", { class: "muted" }, `${fmtNum(l.in_inventory)} / ${fmtNum(l.unique_packages)} packages`),
    h("span", { class: `badge sm ${l.percent === 100 ? "done" : "failed"}`, style: "margin-left:auto" }, `${l.percent}%`)));
  const ecoRows = cov.ecosystems.map((e) => h("li", null, h("strong", null, e.ecosystem),
    h("span", { class: "tag" }, e.resolution), h("span", { class: "muted" }, (e.reasons || []).join("; "))));
  const warnings = [];
  for (const [, a] of agentsForStage("discover")) (a.warnings || []).forEach((w) => warnings.push(`[${a.agent}] ${w}`));
  body.replaceChildren(h("div", { class: "stack" }, t,
    h("div", { class: "grid-2" },
      h("div", { class: "card" }, h("h3", null, "Coverage"),
        h("h4", null, "Components per source"), h("div", { class: "table-wrap short" }, toolTable),
        h("p", { class: "note" }, `Found by Syft, cdxgen and Trivy alike: ${fmtNum(cov.tool_agreement.found_by_all_sbom_tools)} of ${fmtNum(cov.tool_agreement.components_compared)} components.`)),
      h("div", { class: "card" }, h("h3", null, "Completeness"),
        h("h4", null, "Lockfile entries present in the inventory"), h("ul", { class: "list" }, lockRows),
        h("h4", null, "Graph"),
        h("dl", { class: "kv" },
          h("dt", null, "Unreachable nodes"), h("dd", null, fmtNum(cov.unreachable_nodes.count)),
          h("dt", null, "Unresolved edges"), h("dd", null, `${fmtNum(cov.unresolved_edges.count)} `,
            h("span", { class: "muted" }, Object.entries(cov.unresolved_edges.by_reason).map(([k, v]) => `${v} ${k}`).join(", "))),
          h("dt", null, "Edges by source"), h("dd", null, Object.entries(cov.edges_by_source).map(([k, v]) => `${k} ${v}`).join(" · "))),
        h("h4", null, "Ecosystems"), h("ul", { class: "list" }, ecoRows))),
    h("div", { class: "card" }, h("h3", null, `Warnings (${warnings.length})`),
      warnings.length ? h("ul", { class: "list warnings" }, warnings.map((w) => h("li", null, w)))
                      : h("p", { class: "muted" }, "No warnings."))));
}

/* -------------------------------------------------------------------- SBOM */
async function renderSbom(body, token) {
  const inv = needsInventory(body);
  if (!inv) return;
  const [cdx, spdx, cov] = await Promise.all([
    load(inv, "sbom-summary/sbom.cdx.json"), load(inv, "sbom-summary/sbom.spdx.json"), load(inv, "artifact/coverage.json")]);
  if (!current(token)) return;
  const v = cov.sbom_validation;
  const validity = (r) => h("span", { class: `badge sm ${r.valid ? "done" : "failed"}` }, r.valid ? "Valid" : "Invalid");
  const countTable = (obj, label) => h("table", null,
    h("thead", null, h("tr", null, h("th", null, label), h("th", null, "Count"))),
    h("tbody", null, Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, n]) =>
      h("tr", null, h("td", null, k), h("td", { class: "num" }, fmtNum(n))))));
  const meta = (s, r) => h("dl", { class: "kv" },
    h("dt", null, "Format"), h("dd", null, `${s.format} ${s.spec_version}`),
    h("dt", null, "Serial / namespace"), h("dd", { class: "mono" }, s.serial_number || "–"),
    h("dt", null, "Timestamp"), h("dd", null, fmtDate(s.timestamp) || "–"),
    h("dt", null, "Tools"), h("dd", null, h("span", { class: "tags" }, (s.tools || []).map((t) =>
      h("span", { class: "tag" }, t.version ? `${t.name} ${t.version}` : t.name)))),
    h("dt", null, "Validation"), h("dd", null, validity(r), " ", h("span", { class: "muted" }, r.validator || ""),
      r.errors && r.errors.length ? h("pre", { class: "mono" }, r.errors.slice(0, 3).join("\n")) : null));

  // Every SBOM artifact of every discover agent, merged ones first.
  const sboms = [];
  for (const [folder, st] of agentsForStage("discover")) {
    for (const a of st.artifacts || []) if (a.type === "sbom" || a.type === "sbom-spdx") sboms.push([folder, a]);
  }
  sboms.sort((a, b) => (a[0] === inv ? 0 : 1) - (b[0] === inv ? 0 : 1));
  const agreement = cov.tool_agreement;
  const cmpRows = ["lockfile-parser", "npm-ls", "syft", "cdxgen", "trivy", "workflow-parser", "go-mod-graph", "pip-report"]
    .filter((t) => cov.per_tool[t] && cov.per_tool[t].unique_purls)
    .map((t) => h("tr", null, h("td", null, t), h("td", { class: "num" }, fmtNum(cov.per_tool[t].unique_purls)),
      h("td", { class: "num" }, fmtNum(cov.per_tool[t].only_this_tool)),
      h("td", { class: "num" }, t in agreement.missing_count_per_sbom_tool ? fmtNum(agreement.missing_count_per_sbom_tool[t]) : "–")));
  body.replaceChildren(h("div", { class: "stack" },
    h("div", { class: "grid-2" },
      h("div", { class: "card" }, h("h3", null, "Merged CycloneDX"), meta(cdx, v.cyclonedx),
        h("p", { class: "note" }, `${fmtNum(cdx.components)} components · ${fmtNum(cdx.dependencies)} dependency entries · ${fmtNum(cdx.dependency_edges)} edges`)),
      h("div", { class: "card" }, h("h3", null, "SPDX export"), meta(spdx, v.spdx),
        h("p", { class: "note" }, `${fmtNum(spdx.components)} packages · ` +
          Object.entries(spdx.relationships || {}).map(([k, n]) => `${fmtNum(n)} ${k}`).join(" · ")))),
    h("div", { class: "grid-2" },
      h("div", { class: "card" }, h("h3", null, "Components by type"), h("div", { class: "table-wrap short" }, countTable(cdx.by_type, "Type"))),
      h("div", { class: "card" }, h("h3", null, "Components by ecosystem"), h("div", { class: "table-wrap short" }, countTable(cdx.by_ecosystem, "Ecosystem")))),
    h("div", { class: "card" }, h("h3", null, "Per-tool comparison"),
      h("p", { class: "note", style: "margin:0 0 10px" }, `Found by all three SBOM tools: ${fmtNum(agreement.found_by_all_sbom_tools)} of ${fmtNum(agreement.components_compared)} source components.`),
      h("div", { class: "table-wrap short" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "Source"), h("th", null, "Unique purls"), h("th", null, "Only this source"),
          h("th", null, "Inventory components it missed"))),
        h("tbody", null, cmpRows)))),
    h("div", { class: "card" }, h("h3", null, "Downloads"),
      h("ul", { class: "downloads" }, sboms.map(([folder, a]) => h("li", null,
        h("div", null, h("div", { class: "a-name" }, a.name),
          h("div", { class: "a-meta" }, `${state.agents[folder].agent} · ${a.type} · ${a.path}${a.bytes ? ` · ${(a.bytes / 1024).toFixed(0)} KB` : ""}`)),
        h("a", { class: "btn", href: artifactUrl(folder, a.name, true), download: a.name }, "Download")))))));
}

/* --------------------------------------------------------------- DataTable */
class DataTable {
  constructor({ columns, rows, searchKeys, filters = [], pageSize = 50, onRow, sortKey, sortDir = 1, id }) {
    Object.assign(this, { columns, rows, searchKeys, filters, onRow, id });
    const saved = (id && state.tables[id]) || {};
    this.q = saved.q || ""; this.values = saved.values || {}; this.page = saved.page || 1;
    this.size = saved.size || pageSize; this.sortKey = saved.sortKey || sortKey || columns[0].key;
    this.sortDir = saved.sortDir || sortDir;
    this.el = h("div");
    this.build();
  }
  save() { if (this.id) state.tables[this.id] = { q: this.q, values: this.values, page: this.page, size: this.size, sortKey: this.sortKey, sortDir: this.sortDir }; }
  build() {
    let timer;
    const search = h("input", { type: "search", placeholder: "Search…", value: this.q, "aria-label": "Search",
      oninput: (e) => { clearTimeout(timer); timer = setTimeout(() => { this.q = e.target.value; this.page = 1; this.render(); }, 120); } });
    const selects = this.filters.map((f) => {
      const opts = f.options || [...new Set(this.rows.map(f.get))].filter((x) => x != null && x !== "").sort();
      return h("label", { class: "app-select" }, h("span", { class: "label" }, f.label),
        h("select", { onchange: (e) => { this.values[f.key] = e.target.value; this.page = 1; this.render(); } },
          h("option", { value: "" }, "All"),
          opts.map((o) => Array.isArray(o) ? h("option", { value: o[0], selected: this.values[f.key] === o[0] }, o[1])
                                           : h("option", { value: o, selected: this.values[f.key] === o }, o))));
    });
    this.countEl = h("span", { class: "count" });
    this.thead = h("tr");
    this.tbody = h("tbody");
    this.wrap = h("div", { class: "table-wrap" }, h("table", null, h("thead", null, this.thead), this.tbody));
    this.pager = h("div", { class: "pager" });
    this.el.replaceChildren(h("div", { class: "toolbar" }, search, selects, this.countEl), this.wrap, this.pager);
    this.render();
  }
  filtered() {
    const q = this.q.trim().toLowerCase();
    let rows = this.rows.filter((r) => this.filters.every((f) => {
      const want = this.values[f.key];
      if (!want) return true;
      return f.test ? f.test(r, want) : String(f.get(r)) === want;
    }) && (!q || this.searchKeys.some((k) => String(r[k] ?? "").toLowerCase().includes(q))));
    const col = this.columns.find((c) => c.key === this.sortKey) || this.columns[0];
    const get = col.sortValue || ((r) => r[col.key]);
    const cmp = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" }).compare;
    rows = rows.slice().sort((a, b) => {
      const av = get(a), bv = get(b);
      const ae = av == null || av === "", be = bv == null || bv === "";
      if (ae !== be) return ae ? 1 : -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * this.sortDir;
      return cmp(String(av ?? ""), String(bv ?? "")) * this.sortDir;
    });
    return rows;
  }
  render() {
    this.save();
    const rows = this.filtered();
    const pages = Math.max(1, Math.ceil(rows.length / this.size));
    this.page = Math.min(Math.max(1, this.page), pages);
    const start = (this.page - 1) * this.size;
    const pageRows = rows.slice(start, start + this.size);
    this.thead.replaceChildren(...this.columns.map((c) => {
      const active = this.sortKey === c.key;
      return h("th", { class: "sortable", scope: "col", "aria-sort": active ? (this.sortDir > 0 ? "ascending" : "descending") : null },
        h("button", { type: "button", onclick: () => {
          if (this.sortKey === c.key) this.sortDir *= -1; else { this.sortKey = c.key; this.sortDir = c.desc ? -1 : 1; }
          this.render();
        } }, c.label, h("span", { class: "arrow", "aria-hidden": "true" }, active ? (this.sortDir > 0 ? "▲" : "▼") : "↕")));
    }));
    this.tbody.replaceChildren(...(pageRows.length ? pageRows.map((r) => h("tr", {
      class: this.onRow ? "clickable" : null, tabindex: this.onRow ? "0" : null,
      onclick: this.onRow ? () => this.onRow(r) : null,
      onkeydown: this.onRow ? (e) => { if (e.key === "Enter") this.onRow(r); } : null,
    }, this.columns.map((c) => {
      const v = c.render ? c.render(r) : r[c.key];
      return h("td", { class: c.cls || null, title: c.title ? c.title(r) : null }, v == null || v === "" ? dash() : v);
    }))) : [h("tr", null, h("td", { colspan: this.columns.length, class: "muted" }, "No rows match."))]));
    this.countEl.textContent = rows.length === this.rows.length ? `${fmtNum(rows.length)} rows`
      : `${fmtNum(rows.length)} of ${fmtNum(this.rows.length)} rows`;
    const go = (p) => () => { this.page = p; this.render(); this.wrap.scrollTop = 0; };
    this.pager.replaceChildren(
      h("span", { class: "info" }, rows.length ? `Showing ${fmtNum(start + 1)}–${fmtNum(start + pageRows.length)} of ${fmtNum(rows.length)}` : "No results"),
      h("label", { class: "app-select" }, h("span", { class: "label" }, "Rows"),
        h("select", { onchange: (e) => { this.size = Number(e.target.value); this.page = 1; this.render(); } },
          [25, 50, 100, 250].map((n) => h("option", { value: n, selected: n === this.size }, n)))),
      h("button", { class: "btn", type: "button", disabled: this.page <= 1, onclick: go(1) }, "First"),
      h("button", { class: "btn", type: "button", disabled: this.page <= 1, onclick: go(this.page - 1) }, "Previous"),
      h("span", { class: "info", style: "margin:0 4px" }, `Page ${this.page} of ${pages}`),
      h("button", { class: "btn", type: "button", disabled: this.page >= pages, onclick: go(this.page + 1) }, "Next"),
      h("button", { class: "btn", type: "button", disabled: this.page >= pages, onclick: go(pages) }, "Last"));
  }
}

/* -------------------------------------------------------------- components */
const FLAG_TEXT = { "non-default-registry": "non-default registry", git: "git dependency", "tarball-url": "tarball URL",
                    file: "file: dependency", link: "link: dependency", "insecure-http": "plain HTTP" };

async function renderComponents(body, token) {
  const inv = needsInventory(body);
  if (!inv) return;
  const rows = await load(inv, "components-table");
  if (!current(token)) return;
  const table = new DataTable({
    id: `components:${state.app}`, rows, sortKey: "dependents", sortDir: -1,
    searchKeys: ["name", "version", "purl", "license", "registry"],
    filters: [
      { key: "relationship", label: "Type", get: (r) => r.relationship,
        options: [["direct", "Direct"], ["transitive", "Transitive"], ["ci", "CI"], ["container", "Container only"]] },
      { key: "ecosystem", label: "Ecosystem", get: (r) => r.ecosystem },
      { key: "scope", label: "Scope", get: (r) => r.scope, options: [["prod", "prod"], ["dev", "dev"], ["optional", "optional"], ["peer", "peer"]] },
      { key: "container", label: "In container", get: (r) => String(r.in_container), options: [["true", "Yes"], ["false", "No"]] },
    ],
    onRow: (r) => openDrawer(inv, r.purl),
    columns: [
      { key: "name", label: "Name", cls: "name" },
      { key: "version", label: "Version", cls: "mono" },
      { key: "ecosystem", label: "Ecosystem" },
      { key: "relationship", label: "Direct / transitive",
        render: (r) => r.relationship ? h("span", { class: `pill ${r.relationship === "direct" ? "direct" : ""}` }, r.relationship) : null },
      { key: "depth", label: "Depth", cls: "num" },
      { key: "scope", label: "Scope", render: (r) => r.scope ? h("span", { class: `pill ${r.scope}` }, r.scope) : null },
      { key: "dependents", label: "Dependents", cls: "num", desc: true },
      { key: "found_by", label: "Found by", sortValue: (r) => r.found_by.length,
        render: (r) => h("span", { class: "tags" }, r.found_by.map((t) => h("span", { class: "tag" }, t))) },
      { key: "registry", label: "Origin", render: (r) => h("span", null, r.registry || (r.flags.length ? "" : "–"),
          r.flags.length ? h("span", { class: "flag", title: r.flags.map((f) => FLAG_TEXT[f] || f).join(", ") }, "⚑") : null) },
      { key: "integrity", label: "Integrity", render: (r) => r.integrity ? (r.integrity_algs[0] || "yes") : "no" },
      { key: "license", label: "License", cls: "trunc", title: (r) => r.license },
      { key: "in_container", label: "In container", render: (r) => r.in_container == null ? null : r.in_container ? "yes" : "no" },
    ],
  });
  body.replaceChildren(h("div", { class: "card" },
    h("h3", null, "Components ", h("span", { class: "muted", style: "font-weight:400" }, "(one row per unique purl · click a row for details)")),
    table.el));
}

/* ------------------------------------------------------------------ drawer */
function crumbs(path, nodesById, target) {
  const out = [];
  path.forEach((id, i) => {
    const n = nodesById[id] || { name: id };
    if (i) out.push(h("span", { class: "sep" }, "›"));
    const label = id.startsWith("pkg:") ? `${n.name}@${n.version}` : n.name || id;
    out.push(h("span", { class: `crumb${i === 0 ? " root" : ""}${id === target ? " target" : ""}`, title: id }, label));
  });
  return h("div", { class: "crumbs" }, out);
}

function pathsBlock(p, target) {
  const byId = Object.fromEntries(p.nodes.map((n) => [n.id, n]));
  const entries = Object.entries(p.paths);
  if (!entries.length) return h("p", { class: "muted" }, "Not reachable from any root.");
  return h("div", null, entries.map(([root, v]) => h("div", { class: "path-block" },
    h("div", { class: "path-meta" }, `from ${byId[root] ? byId[root].name : root} · ${v.count} distinct path${v.count === 1 ? "" : "s"} · depth ${v.shortest.length - 1}`),
    crumbs(v.shortest, byId, target))));
}

async function openDrawer(inv, purl) {
  const drawer = $("drawer");
  $("drawer-title").textContent = purl;
  $("drawer-body").replaceChildren(h("p", { class: "muted" }, "Loading…"));
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  try {
    const [c, p] = await Promise.all([load(inv, `component?id=${enc(purl)}`), load(inv, `graph/path?to=${enc(purl)}`)]);
    $("drawer-title").textContent = `${c.name}@${c.version}`;
    const o = c.origin || {};
    $("drawer-body").replaceChildren(
      h("dl", { class: "kv" },
        h("dt", null, "purl"), h("dd", { class: "mono" }, c.purl),
        h("dt", null, "Ecosystem"), h("dd", null, c.ecosystem),
        h("dt", null, "Relationship"), h("dd", null, `${c.relationship || "–"} · depth ${c.depth ?? "–"} · scope ${c.scope || "–"}`),
        h("dt", null, "Dependents"), h("dd", null, `${c.dependents_count} dependents · ${c.dependencies_count} dependencies`),
        h("dt", null, "Found by"), h("dd", null, h("span", { class: "tags" }, c.found_by.map((t) => h("span", { class: "tag" }, t)))),
        h("dt", null, "Licenses"), h("dd", null, (c.licenses || []).join(", ") || "–"),
        h("dt", null, "Integrity"), h("dd", null, c.integrity.present ? `${c.integrity.algorithms.join(", ")} (${c.integrity.source})` : "none recorded"),
        h("dt", null, "In container"), h("dd", null, c.in_container == null ? "–" : c.in_container ? "yes" : "no"),
        h("dt", null, "Registry"), h("dd", null, (o.registry_hosts || []).join(", ") || "–",
          (o.flags || []).length ? h("span", { class: "tags", style: "margin-left:6px" }, o.flags.map((f) => h("span", { class: "tag strong" }, FLAG_TEXT[f] || f))) : null)),
      h("h4", null, "Dependency paths from the roots"), pathsBlock(p, purl),
      h("h4", null, "Declared in"),
      c.declared_in.length ? h("ul", { class: "list" }, c.declared_in.map((d) => h("li", null,
        h("span", { class: "mono" }, d.manifest), h("span", { class: "tag" }, d.section), h("span", { class: "mono muted" }, d.range || ""))))
        : h("p", { class: "muted" }, "Not declared directly (transitive)."),
      h("h4", null, `Occurrences (${c.occurrences.length})`),
      h("div", { class: "table-wrap short" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "Project"), h("th", null, "Lockfile / manifest"), h("th", null, "Install path"))),
        h("tbody", null, c.occurrences.map((oc) => h("tr", null, h("td", null, oc.project || "–"),
          h("td", { class: "mono" }, oc.lockfile || oc.manifest || "–"),
          h("td", { class: "mono" }, oc.install_path || oc.job || "–")))))),
      h("h4", null, "Resolved URLs"),
      (o.resolved_urls || []).length ? h("ul", { class: "list" }, o.resolved_urls.map((u) => h("li", { class: "mono" }, u)))
        : h("p", { class: "muted" }, "None recorded."),
      h("h4", null, "Tool locations"),
      h("ul", { class: "list" }, Object.entries(c.sources || {}).map(([t, locs]) => h("li", null, h("span", { class: "tag" }, t),
        h("span", { class: "mono muted" }, (locs || []).slice(0, 4).join(", ") || "–")))));
  } catch (err) {
    $("drawer-body").replaceChildren(h("div", { class: "error-box" }, h("pre", null, String(err.message || err))));
  }
}
function closeDrawer() {
  $("drawer").classList.remove("open");
  $("drawer").setAttribute("aria-hidden", "true");
}

/* ------------------------------------------------------------------- graph */
const G = { cy: null, folder: null, expanded: new Set(), info: new Map(), mode: "graph", depth: 1, selected: null };

function nodeClass(n) {
  if (n.kind && n.kind !== "component") return `root ${n.kind}`;
  if (n.relationship === "ci") return "ci";
  if (n.relationship === "container") return "container";
  if (n.scope === "dev") return "dev";
  return n.relationship === "direct" ? "direct" : "transitive";
}
function nodeEl(n) {
  G.info.set(n.id, n);
  const label = n.kind && n.kind !== "component" ? n.name : `${n.name}${n.version ? "@" + String(n.version).slice(0, 18) : ""}`;
  const size = Math.min(1, Math.log10(1 + (n.dependents_count || 0)) / 2);
  const w = Math.round(label.length * (n.kind && n.kind !== "component" ? 7.4 : 6.2)) + 14;   // monospace label width
  return { group: "nodes", data: { id: n.id, label, size, w, deps: n.dependencies_count || 0 }, classes: nodeClass(n) };
}
function edgeEl(e) {
  return { group: "edges", data: { id: `${e.from}→${e.to}`, source: e.from, target: e.to }, classes: e.type };
}

function cyStyle() {
  return [
    { selector: "node", style: {
      shape: "round-rectangle", label: "data(label)", "font-size": 10, "font-family": "ui-monospace, Menlo, monospace",
      "text-valign": "center", "text-halign": "center", width: "data(w)", height: "mapData(size, 0, 1, 18, 38)", "background-color": "#e9eef0", color: "#1c2329", "border-width": 1, "border-color": "#cdd2d7" } },
    { selector: "node.root", style: { "background-color": "#0a524f", color: "#fff", "border-color": "#0a524f", "font-weight": 700, "font-size": 12 } },
    { selector: "node.direct", style: { "background-color": "#cfe7e4", "border-color": "#5fa8a3" } },
    { selector: "node.transitive", style: { "background-color": "#f1f3f4", "border-color": "#cdd2d7" } },
    { selector: "node.dev", style: { "background-color": "#ffffff", "border-style": "dashed", "border-color": "#8a949d", color: "#5f6b76" } },
    { selector: "node.ci, node.container", style: { "background-color": "#eef0f2", "border-color": "#8a949d" } },
    { selector: "node.has-more", style: { "border-width": 2 } },
    { selector: "node.expanded", style: { "border-width": 2, "border-color": "#0f6e6a" } },
    { selector: "node:selected", style: { "border-width": 3, "border-color": "#0f6e6a", "overlay-opacity": 0 } },
    { selector: "node.hl", style: { "border-width": 3, "border-color": "#0f6e6a", "background-color": "#bfe0dc" } },
    { selector: "edge", style: { width: 1.2, "line-color": "#aab3ba", "target-arrow-color": "#aab3ba",
      "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier" } },
    { selector: "edge.dev", style: { "line-style": "dashed" } },
    { selector: "edge.optional, edge.peer", style: { "line-style": "dotted" } },
    { selector: "edge.fan", style: { "curve-style": "straight", opacity: 0.25, "target-arrow-shape": "none" } },
    { selector: "edge.hl", style: { width: 2.5, "line-color": "#0f6e6a", "target-arrow-color": "#0f6e6a" } },
  ];
}

function layout(fit = true) {
  G.cy.layout({ name: "dagre", rankDir: "LR", nodeSep: 6, rankSep: 70, edgeSep: 4, animate: false, fit, padding: 20 }).run();
}
function addElements(nodes, edges) {
  const add = [];
  for (const n of nodes) if (G.cy.getElementById(n.id).empty()) add.push(nodeEl(n)); else G.info.set(n.id, { ...G.info.get(n.id), ...n });
  for (const e of edges) if (G.cy.getElementById(`${e.from}→${e.to}`).empty()) add.push(edgeEl(e));
  G.cy.add(add.filter((x) => x.group === "nodes"));
  G.cy.add(add.filter((x) => x.group === "edges" && !G.cy.getElementById(x.data.source).empty() && !G.cy.getElementById(x.data.target).empty()));
  G.cy.nodes().forEach((n) => n.toggleClass("has-more", n.data("deps") > n.outgoers("node").length && !G.expanded.has(n.id())));
}

/* Default view: one horizontal band per root, its direct dependencies in name-sorted columns.
 * A single dagre column of 200+ siblings is unreadable, so this view uses preset positions;
 * expanding a node switches to the dagre layout centred on that node. */
async function defaultView() {
  G.cy.elements().remove();
  G.expanded.clear();
  const summary = await load(G.folder, "graph/summary");
  const parts = await Promise.all(summary.roots.map((r) => load(G.folder, `graph/node?id=${enc(r.id)}&depth=1`)));
  const positions = {};
  const viewW = (G.cy.width() || 900) / 0.85;
  let top = 0;
  for (const p of parts) {
    const rootId = p.center.id;
    const kids = p.edges.filter((e) => e.from === rootId).map((e) => p.nodes.find((n) => n.id === e.to)).filter(Boolean)
      .filter((n) => !(n.id in positions))
      .sort((a, b) => (a.name || "").localeCompare(b.name || ""));
    addElements(p.nodes.filter((n) => n.id === rootId || kids.some((k) => k.id === n.id)), p.edges.filter((e) => e.from === rootId));
    G.expanded.add(rootId);
    const colW = Math.min(260, Math.max(...kids.map((k) => G.cy.getElementById(k.id).data("w") || 120), 120) + 18);
    const cols = Math.max(1, Math.min(kids.length, Math.floor((viewW - 260) / colW)));
    positions[rootId] = { x: 90, y: top + 20 };
    kids.forEach((k, i) => { positions[k.id] = { x: 260 + (i % cols) * colW + colW / 2, y: top + 20 + Math.floor(i / cols) * 30 }; });
    top += Math.max(1, Math.ceil(kids.length / cols)) * 30 + 70;
  }
  addElements([], []);
  G.cy.edges().addClass("fan");
  G.grid = true;
  G.cy.layout({ name: "preset", positions: (n) => positions[n.id()] || { x: 0, y: top }, fit: false }).run();
  G.cy.zoom(0.85);
  G.cy.pan({ x: 16, y: 16 });
  updateGraphCount("Default view: roots and their direct dependencies (drag to pan, scroll to zoom)");
}

async function expand(id) {
  const p = await load(G.folder, `graph/node?id=${enc(id)}&depth=${G.depth}`);
  const keep = new Set([id]);
  const q = [id];
  while (q.length) {                              // only descendants (not the parents the API also returns)
    const u = q.shift();
    for (const e of p.edges) if (e.from === u && !keep.has(e.to)) { keep.add(e.to); q.push(e.to); }
  }
  addElements(p.nodes.filter((n) => keep.has(n.id)), p.edges.filter((e) => keep.has(e.from) && keep.has(e.to)));
  for (const n of keep) if (G.depth > 1 || n === id) G.expanded.add(n);
  G.expanded.add(id);
  G.cy.getElementById(id).addClass("expanded");
  addElements([], []);
  G.cy.edges().removeClass("fan");
  G.grid = false;
  layout(false);
  G.cy.zoom(0.9);
  G.cy.center(G.cy.getElementById(id));
  updateGraphCount(p.truncated ? "Expansion truncated at 400 nodes" : null);
}
function collapse(id) {
  const node = G.cy.getElementById(id);
  const remove = (n) => {
    n.outgoers("edge").forEach((e) => {
      const child = e.target();
      e.remove();
      if (!child.hasClass("root") && child.incomers("edge").length === 0) { remove(child); G.expanded.delete(child.id()); child.remove(); }
    });
  };
  remove(node);
  G.expanded.delete(id);
  node.removeClass("expanded");
  addElements([], []);
  layout(false);
  updateGraphCount(null);
}

async function pathView(id) {
  const p = await load(G.folder, `graph/path?to=${enc(id)}`);
  G.cy.elements().remove();
  G.expanded.clear();
  addElements(p.nodes, p.edges);
  G.grid = false;
  G.cy.elements().addClass("hl");
  layout();
  const target = G.cy.getElementById(id);
  target.select();
  await selectNode(id);
  updateGraphCount(`Path view: shortest path${Object.keys(p.paths).length === 1 ? "" : "s"} from every root to ${G.info.get(id)?.name || id}`);
}

function updateGraphCount(note) {
  const el = $("graph-count");
  if (el) el.textContent = `${G.cy.nodes().length} nodes · ${G.cy.edges().length} edges shown${note ? " · " + note : ""}`;
}

async function selectNode(id) {
  G.selected = id;
  const side = $("graph-side");
  if (!side) return;
  const info = G.info.get(id) || { id, name: id };
  const isRoot = info.kind && info.kind !== "component";
  const card = h("div", { class: "card" }, h("h3", null, isRoot ? info.name : `${info.name}@${info.version}`), h("p", { class: "muted" }, "Loading…"));
  side.firstChild.replaceWith(card);
  if (isRoot) {
    card.replaceChildren(h("h3", null, info.name), h("dl", { class: "kv" },
      h("dt", null, "Root"), h("dd", { class: "mono" }, id), h("dt", null, "Kind"), h("dd", null, info.kind),
      h("dt", null, "Version"), h("dd", null, info.version || "–"),
      h("dt", null, "Dependencies"), h("dd", null, fmtNum(info.dependencies_count))));
    return;
  }
  try {
    const [c, p] = await Promise.all([load(G.folder, `component?id=${enc(id)}`), load(G.folder, `graph/path?to=${enc(id)}`)]);
    if (G.selected !== id) return;
    const o = c.origin || {};
    card.replaceChildren(h("h3", null, `${c.name}@${c.version}`),
      h("dl", { class: "kv" },
        h("dt", null, "purl"), h("dd", { class: "mono" }, c.purl),
        h("dt", null, "Depth"), h("dd", null, `${c.depth ?? "–"} (${c.relationship || "–"})`),
        h("dt", null, "Scope"), h("dd", null, c.scope || "–"),
        h("dt", null, "Dependents"), h("dd", null, fmtNum(c.dependents_count)),
        h("dt", null, "Dependencies"), h("dd", null, fmtNum(c.dependencies_count)),
        h("dt", null, "Found by"), h("dd", null, h("span", { class: "tags" }, c.found_by.map((t) => h("span", { class: "tag" }, t)))),
        h("dt", null, "Origin"), h("dd", null, (o.registry_hosts || []).join(", ") || "–", (o.flags || []).length ? ` (${o.flags.join(", ")})` : "")),
      h("h4", null, "Paths from the roots"), pathsBlock(p, id),
      h("div", { style: "display:flex;gap:8px;margin-top:12px;flex-wrap:wrap" },
        h("button", { class: "btn", type: "button", onclick: () => pathView(id) }, "Show paths in graph"),
        h("button", { class: "btn", type: "button", onclick: () => openDrawer(G.folder, id) }, "All details")));
  } catch (err) {
    card.replaceChildren(h("div", { class: "error-box" }, h("pre", null, String(err.message || err))));
  }
}

function treeItem(n) {
  const hasKids = (n.dependencies_count || 0) > 0;
  const kids = h("ul", { hidden: true });
  const tw = h("button", { class: "tw", type: "button", "aria-expanded": "false", "aria-label": "Expand" }, hasKids ? "▸" : "·");
  if (hasKids) tw.addEventListener("click", async () => {
    const open = tw.getAttribute("aria-expanded") === "true";
    tw.setAttribute("aria-expanded", String(!open));
    tw.textContent = open ? "▸" : "▾";
    kids.hidden = open;
    if (!open && !kids.childElementCount) {
      const res = await load(G.folder, `graph/children?id=${enc(n.id)}`);
      kids.replaceChildren(...res.children.map((c) => treeItem(c)));
    }
  });
  const isRoot = n.kind && n.kind !== "component";
  const label = isRoot ? n.name : `${n.name}@${n.version}`;
  return h("li", null, h("div", { class: "row" }, tw,
    h("span", { class: "nm", onclick: () => { G.info.set(n.id, n); selectNode(n.id); } }, label),
    n.edge_type && n.edge_type !== "prod" ? h("span", { class: "tag" }, n.edge_type) : null,
    !isRoot && n.scope === "dev" ? h("span", { class: "pill dev" }, "dev") : null,
    hasKids ? h("span", { class: "muted", style: "font-size:12px" }, `(${n.dependencies_count})`) : null), kids);
}

async function renderGraph(body, token) {
  const inv = needsInventory(body);
  if (!inv) return;
  G.folder = inv;
  const summary = await load(inv, "graph/summary");
  if (!current(token)) return;
  if (typeof cytoscape === "undefined") throw new Error("Cytoscape failed to load (dashboard/static/vendor)");
  if (window.cytoscapeDagre && !G.registered) { cytoscape.use(window.cytoscapeDagre); G.registered = true; }

  let timer;
  const suggest = h("ul", { class: "suggest", hidden: true, role: "listbox" });
  const search = h("input", { type: "search", placeholder: "Find a package → show its path from the roots", "aria-label": "Find a package",
    oninput: (e) => {
      clearTimeout(timer);
      const q = e.target.value.trim();
      if (!q) { suggest.hidden = true; return; }
      timer = setTimeout(async () => {
        const hits = await getJSON(api(inv, `graph/search?q=${enc(q)}&limit=15`));
        suggest.replaceChildren(...hits.map((n) => h("li", { role: "option", onclick: () => { suggest.hidden = true; search.value = n.name; pathView(n.id); } },
          h("span", null, `${n.name}@${n.version}`), h("span", { class: "muted" }, `depth ${n.depth ?? "–"}`))));
        suggest.hidden = !hits.length;
      }, 150);
    } });
  const depthSel = h("select", { "aria-label": "Expand depth", onchange: (e) => { G.depth = Number(e.target.value); } },
    [1, 2, 3].map((d) => h("option", { value: d, selected: d === G.depth }, `Expand ${d} level${d > 1 ? "s" : ""}`)));
  const graphBtn = h("button", { class: "btn", type: "button", "aria-pressed": G.mode === "graph" ? "true" : "false" }, "Graph");
  const treeBtn = h("button", { class: "btn", type: "button", "aria-pressed": G.mode === "tree" ? "true" : "false" }, "Tree");
  const cyEl = h("div", { id: "cy", hidden: G.mode !== "graph" });
  const treeEl = h("div", { class: "tree-wrap", hidden: G.mode !== "tree" },
    h("ul", { class: "tree" }, summary.roots.map((r) => treeItem(r))));
  const setMode = (m) => {
    G.mode = m; cyEl.hidden = m !== "graph"; treeEl.hidden = m !== "tree";
    graphBtn.setAttribute("aria-pressed", String(m === "graph")); treeBtn.setAttribute("aria-pressed", String(m === "tree"));
    if (m === "graph" && G.cy) { G.cy.resize(); G.cy.fit(undefined, 20); }
  };
  graphBtn.onclick = () => setMode("graph");
  treeBtn.onclick = () => setMode("tree");
  const st = summary.stats || {};
  const top = h("ol", { class: "top-list" }, (st.top_dependents || []).map((t) => h("li", null,
    h("button", { type: "button", onclick: () => { setMode("graph"); pathView(t.id); } }, `${t.name}@${t.version}`),
    h("span", { class: "n" }, fmtNum(t.dependents_count)))));
  const side = h("div", { class: "side", id: "graph-side" },
    h("div", { class: "card" }, h("h3", null, "Selected node"), h("p", { class: "muted" }, "Click a node to select it and expand or collapse its children.")),
    h("div", { class: "card" }, h("h3", null, "Most depended-on packages"), top));
  body.replaceChildren(h("div", { class: "graph-layout" },
    h("div", null,
      h("div", { class: "graph-toolbar" }, h("div", { class: "search-wrap" }, search, suggest), depthSel,
        h("button", { class: "btn", type: "button", onclick: () => defaultView() }, "Reset view"),
        h("button", { class: "btn", type: "button", onclick: () => G.cy && G.cy.fit(undefined, 20) }, "Fit"),
        h("span", { class: "seg" }, graphBtn, treeBtn)),
      cyEl, treeEl,
      h("div", { class: "legend" },
        h("span", null, h("span", { class: "sw", style: "background:#0a524f" }), "root"),
        h("span", null, h("span", { class: "sw", style: "background:#cfe7e4;border-color:#5fa8a3" }), "direct"),
        h("span", null, h("span", { class: "sw", style: "background:#f1f3f4;border-color:#cdd2d7" }), "transitive"),
        h("span", null, h("span", { class: "sw", style: "background:#fff;border:1px dashed #8a949d" }), "dev-only"),
        h("span", null, h("span", { class: "sw", style: "background:#eef0f2;border-color:#8a949d" }), "CI / container"),
        h("span", null, h("span", { class: "ln" }), "prod"), h("span", null, h("span", { class: "ln dashed" }), "dev"),
        h("span", null, h("span", { class: "ln dotted" }), "optional / peer"),
        h("span", null, "size = number of dependents · thick border = more children to expand"),
        h("span", { id: "graph-count", style: "margin-left:auto" }))),
    side));
  if (G.cy) G.cy.destroy();
  G.cy = cytoscape({ container: cyEl, style: cyStyle(), minZoom: 0.05, maxZoom: 3, boxSelectionEnabled: false });
  G.info.clear();
  G.cy.on("tap", "node", async (evt) => {
    const id = evt.target.id();
    await selectNode(id);
    if (evt.target.hasClass("expanded")) collapse(id);
    else if ((evt.target.data("deps") || 0) > 0) await expand(id);
  });
  await defaultView();
  if (!current(token)) return;
}

/* --------------------------------------------------------------- container */
async function renderContainer(body, token) {
  const art = folderWith("container.json");
  if (!art || state.agents[art].state !== "done") {
    body.replaceChildren(h("div", { class: "empty" }, h("h3", null, "No container data yet"),
      h("p", null, art ? `artifact-inspector: ${LABEL[agentState(state.agents[art])]}` : "The artifact-inspector agent has not run.")));
    return;
  }
  const [c, df] = await Promise.all([load(art, "artifact/container.json"), load(art, "artifact/dockerfile_analysis.json")]);
  if (!current(token)) return;
  const dfCards = (df.dockerfiles || []).map((d) => h("div", { class: "card" }, h("h3", null, d.path),
    h("div", { class: "table-wrap short" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Stage"), h("th", null, "Base image"), h("th", null, "Pinning"), h("th", null, "USER"))),
      h("tbody", null, d.stages.map((s) => h("tr", null, h("td", null, s.name || `#${s.index}`), h("td", { class: "mono" }, s.image),
        h("td", null, h("span", { class: `tag ${s.pinning === "digest" ? "accent" : "strong"}` }, s.pinning)), h("td", null, s.user || "–")))))),
    h("h4", null, `Findings (${d.findings.length})`),
    d.findings.length ? h("ul", { class: "list" }, d.findings.map((f) => h("li", null, h("span", { class: "tag strong" }, f.type),
      h("span", { class: "muted" }, `line ${f.line}`), h("span", { class: "mono" }, f.text)))) : h("p", { class: "muted" }, "None.")));
  const composeCard = (df.compose || []).length ? h("div", { class: "card" }, h("h3", null, "Compose files"),
    h("div", { class: "table-wrap short" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "File"), h("th", null, "Service"), h("th", null, "Image"), h("th", null, "Pinning"))),
      h("tbody", null, df.compose.flatMap((cf) => cf.services.map((s) => h("tr", null, h("td", { class: "mono" }, cf.path),
        h("td", null, s.service), h("td", { class: "mono" }, s.image || (s.build ? `build: ${s.build}` : "–")), h("td", null, s.pinning || "–")))))))) : null;
  if (!c.inspected) {
    body.replaceChildren(h("div", { class: "stack" }, h("div", { class: "empty" }, h("h3", null, "Container image not inspected"),
      h("p", null, c.reason || "")), ...dfCards, composeCard));
    return;
  }
  const sel = c.selection || {};
  const pkgTable = new DataTable({
    id: `container:${state.app}`, rows: c.packages, sortKey: "kind", searchKeys: ["name", "version", "purl"],
    filters: [{ key: "kind", label: "Kind", get: (r) => r.kind }, { key: "ecosystem", label: "Ecosystem", get: (r) => r.ecosystem }],
    columns: [
      { key: "name", label: "Name", cls: "name" }, { key: "version", label: "Version", cls: "mono" },
      { key: "ecosystem", label: "Ecosystem" }, { key: "kind", label: "Kind" },
      { key: "found_by", label: "Found by", render: (r) => h("span", { class: "tags" }, r.found_by.map((t) => h("span", { class: "tag" }, t))) },
      { key: "licenses", label: "Licenses", cls: "trunc", render: (r) => r.licenses.join(", ") },
      { key: "purl", label: "purl", cls: "mono trunc", title: (r) => r.purl },
    ],
  });
  body.replaceChildren(h("div", { class: "stack" },
    tiles([["Packages", c.counts.total], ["OS packages", c.counts.os], ["Application packages", c.counts.application],
           ["Layers", c.layers], ["Syft", c.counts.per_tool.syft], ["Trivy", c.counts.per_tool.trivy]]),
    h("div", { class: "grid-2" },
      h("div", { class: "card" }, h("h3", null, "Image"), h("dl", { class: "kv" },
        h("dt", null, "Reference"), h("dd", { class: "mono" }, c.ref),
        h("dt", null, "Digest"), h("dd", { class: "mono" }, c.digest || "–"),
        h("dt", null, "Chosen by"), h("dd", null, `${sel.method || "–"}${sel.name_source ? ` (${sel.name_source})` : ""}`),
        h("dt", null, "Why"), h("dd", null, sel.reason || "–"),
        h("dt", null, "Scanned"), h("dd", { class: "mono" }, `${c.scanned_ref} (${c.mode})`),
        h("dt", null, "Platform"), h("dd", null, [c.image_os, c.architecture].filter(Boolean).join("/") || "–"),
        h("dt", null, "Runs as"), h("dd", null, c.user || "root (no USER)"),
        h("dt", null, "Created"), h("dd", null, fmtDate(c.created) || "–"))),
      h("div", { class: "card" }, h("h3", null, "Base image and OS"), h("dl", { class: "kv" },
        h("dt", null, "OS / distro"), h("dd", null, c.os ? `${c.os.name} ${c.os.version}${c.os.description ? ` (${c.os.description})` : ""}` : "–"),
        h("dt", null, "Declared base"), h("dd", { class: "mono" }, c.declared_base_image || "–"),
        h("dt", null, "Base pinning"), h("dd", null, c.declared_base_pinning ? h("span", { class: `tag ${c.declared_base_pinning === "digest" ? "accent" : "strong"}` }, c.declared_base_pinning) : "–")),
        c.base_image_note ? h("p", { class: "note" }, c.base_image_note) : null,
        h("h4", null, "Packages by ecosystem"),
        h("p", null, Object.entries(c.counts.by_ecosystem).map(([k, n]) => `${k} ${n}`).join(" · ")))),
    h("div", { class: "card" }, h("h3", null, "Packages in the image"), pkgTable.el),
    ...dfCards, composeCard));
}

/* -------------------------------------------------------------------- CI/CD */
const PATTERN_TEXT = {
  "pull-request-target-checkout-head": "pull_request_target + checkout of the PR head",
  "pipe-to-shell": "curl | sh in a run step",
  "secrets-in-pr-workflow": "secrets used in a PR-triggered workflow",
  "default-token-permissions": "no permissions: block (default token permissions)",
};

async function renderCi(body, token) {
  const art = folderWith("ci_inventory.json");
  if (!art || state.agents[art].state !== "done") {
    body.replaceChildren(h("div", { class: "empty" }, h("h3", null, "No CI/CD data yet")));
    return;
  }
  const ci = await load(art, "artifact/ci_inventory.json");
  if (!current(token)) return;
  const s = ci.summary;
  const actions = new DataTable({
    id: `actions:${state.app}`, rows: ci.actions.map((a) => ({ ...a, used: a.used_in.length })), sortKey: "pin_type",
    searchKeys: ["uses", "action"],
    filters: [{ key: "pin_type", label: "Pin", get: (r) => r.pin_type }, { key: "publisher", label: "Publisher", get: (r) => r.publisher }],
    columns: [
      { key: "action", label: "Action", cls: "name" },
      { key: "ref", label: "Ref", cls: "mono trunc", title: (r) => `${r.ref || ""}${r.ref_comment ? "  # " + r.ref_comment : ""}`,
        render: (r) => r.ref ? `${r.ref.length > 14 ? r.ref.slice(0, 12) + "…" : r.ref}${r.ref_comment ? " # " + r.ref_comment : ""}` : null },
      { key: "pin_type", label: "Pinned to", render: (r) => h("span", { class: `tag ${r.pin_type === "sha" ? "accent" : "strong"}`, title: `determined by ${r.pin_source}` }, r.pin_type) },
      { key: "publisher", label: "Publisher" },
      { key: "used", label: "Used in", cls: "num", title: (r) => r.used_in.map((u) => `${u.workflow} (${u.job})`).join("\n"),
        render: (r) => `${r.used} job${r.used === 1 ? "" : "s"}` },
    ],
  });
  body.replaceChildren(h("div", { class: "stack" },
    tiles([["Workflows", s.workflows], ["Action references", s.action_references], ["Unique actions", s.unique_actions],
           ["Pinned to SHA", s.pinned_sha], ["Pinned to tag", s.pinned_tag], ["Pinned to branch", s.pinned_branch],
           ["Third-party actions", s.third_party_actions], ["Workflows without permissions", s.workflows_without_permissions]]),
    h("div", { class: "card" }, h("h3", null, "Workflows"), h("div", { class: "table-wrap short" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Workflow"), h("th", null, "File"), h("th", null, "Triggers"),
        h("th", null, "Permissions set"), h("th", null, "Jobs"), h("th", null, "uses:"))),
      h("tbody", null, ci.workflows.map((w) => h("tr", null, h("td", { class: "name" }, w.name || "–"), h("td", { class: "mono" }, w.path),
        h("td", null, h("span", { class: "tags" }, w.triggers.map((t) => h("span", { class: "tag" }, t)))),
        h("td", null, w.permissions_set ? "yes" : h("span", { class: "tag strong" }, "no (default)")),
        h("td", { class: "num" }, w.jobs.length), h("td", { class: "num" }, w.uses_count))))))),
    h("div", { class: "card" }, h("h3", null, "Actions (deduplicated)"), actions.el),
    h("div", { class: "card" }, h("h3", null, `Patterns found (${ci.patterns.length})`),
      h("p", { class: "note", style: "margin:0 0 10px" }, "Facts for the Detect stage. Nothing is scored here; `job if` shows conditions that may limit when a job runs."),
      ci.patterns.length ? h("div", { class: "table-wrap short" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "Pattern"), h("th", null, "Workflow"), h("th", null, "Job"), h("th", null, "Detail"), h("th", null, "Job if"))),
        h("tbody", null, ci.patterns.map((p) => h("tr", null, h("td", null, PATTERN_TEXT[p.type] || p.type),
          h("td", { class: "mono" }, p.workflow), h("td", null, p.job || "–"), h("td", { class: "mono" }, p.text),
          h("td", { class: "mono trunc", title: p.job_if || "" }, p.job_if || "–"))))))
        : h("p", { class: "muted" }, "None.")),
    ci.other_ci.length ? h("div", { class: "card" }, h("h3", null, "Other CI systems (detected, not parsed)"),
      h("ul", { class: "list" }, ci.other_ci.map((o) => h("li", null, h("span", { class: "mono" }, o.path), h("span", { class: "tag" }, o.system))))) : null));
}

/* ------------------------------------------------------------------ polling */
let polling = false;
async function refresh() {
  if (polling) return;
  polling = true;
  try {
    state.runs = await getJSON("/api/runs");
    const names = state.runs.map((r) => r.app_id);
    if (!names.includes(state.app)) state.app = names[0] || null;
    renderAppSelect();
    if (state.app) {
      const data = await getJSON(`/api/runs/${enc(state.app)}`);
      state.run = data.run;
      state.agents = data.agents || {};
    } else { state.run = null; state.agents = {}; }
    renderRunMeta();
    renderPipeline();
    renderPanel();
    $("poll-status").textContent = `Refreshing every 5 s · last checked ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    $("poll-status").textContent = `Could not reach the API (${err.message}). Retrying…`;
  } finally {
    polling = false;
  }
}

function init() {
  const hash = readHash();
  if (hash.stage && STAGES.some((s) => s.id === hash.stage)) state.stage = hash.stage;
  if (hash.tab && TABS.some(([id]) => id === hash.tab)) state.tab = hash.tab;
  state.app = hash.app;
  $("app-select").addEventListener("change", (e) => {
    state.app = e.target.value || null;
    state.panelKey = null;
    writeHash();
    refresh();
  });
  $("drawer-close").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  refresh().then(writeHash);
  setInterval(refresh, POLL_MS);
}

init();
