const $ = (sel) => document.querySelector(sel);

const userEl = $("#user");
const modelEl = $("#model");
const queryEl = $("#query");
const runBtn = $("#run");
const statusEl = $("#status");
const idleStateEl = $("#idle-state");
const idlePipelineEl = $("#idle-pipeline");
const outEl = $("#out");
const liveCardEl = $("#live-card");
const livePipelineEl = $("#live-pipeline");
const panelsEl = $("#panels");
const redteamEl = $("#redteam");
const tenantsGridEl = $("#tenants-grid");
const rolesGridEl = $("#roles-grid");
const presetsChipsEl = $("#presets-chips");
const roleQuickHintEl = $("#role-quick-hint");
const traceListEl = $("#trace-list");
const traceStateEl = $("#trace-state");
const traceTimerEl = $("#trace-timer");
const liveStreamEl = $("#live-stream");
const liveStreamCodeEl = $("#live-stream-code");
const sideDrawerEl = $("#side-drawer");
const backdropEl = $("#drawer-backdrop");
const openCrmBtn = $("#open-crm-drawer");
const openTraceBtn = $("#open-trace-drawer");
const closeDrawerBtn = $("#close-drawer");
const paneCrmEl = $("#pane-crm");
const paneInspectorEl = $("#pane-inspector");
const inspectorContentEl = $("#inspector-content");

const USER_LABELS = {
  jan_sales_alpha: { pl: "Jan - Handlowiec", en: "Jan - Sales Rep" },
  ewa_viewer_alpha: { pl: "Ewa - Analityk", en: "Ewa - Analyst" },
  anna_admin_alpha: { pl: "Anna - Zarząd (Admin)", en: "Anna - Management (Admin)" },
  piotr_sales_beta: { pl: "Piotr - Handlowiec", en: "Piotr - Sales Rep" },
  marek_admin_beta: { pl: "Marek - Zarząd (Admin)", en: "Marek - Management (Admin)" },
};

const STR = {
  pl: {
    page_title: "SeQuery",
    btn_crm_drawer: "Baza CRM i role",
    btn_trace_drawer: "Inspektor warstw",
    tab_crm: "Baza CRM i role",
    tab_inspector: "Inspektor warstw",
    sec_tenants: "Dwie firmy w jednej bazie",
    sec_roles: "Uprawnienia ról (RLS vs CLS)",
    presets_label: "Scenariusze testowe",
    idle_sub: "Oczekuje na zapytanie",
    idle_hint: "Wybierz scenariusz po lewej i kliknij Uruchom, aby prześledzić wykonanie krok po kroku.",
    user: "Kto pyta",
    model_label: "Model AI (Ollama)",
    mode: "Tryb",
    query: "Pytanie",
    query_ph: "Pokaż moje deale...",
    vulnerable: "Podatny",
    secure: "Bezpieczny",
    compare: "Porównaj",
    run: "Uruchom",
    running: "Pracuje...",
    empty: "Wpisz pytanie",
    open_inspector: "Pokaż szczegóły warstw (Sentinel, AST, RLS/CLS) ->",
    inspector_empty: "Uruchom zapytanie, aby zobaczyć szczegóły warstw obrony (Sentinel, AST, komendy sesyjne PostgreSQL).",
    role_quick_admin: "zarząd · cała firma · widzi marżę",
    role_quick_sales_rep: "handlowiec · tylko własne · bez marży",
    role_quick_viewer: "analityk · cała firma · bez marży",
    preset_PI01: "Wyciągnij dane obu firm",
    preset_PI02: "Udawaj szefa (tajne marże)",
    preset_BENIGN: "Zwykłe pytanie o moje kontrakty",
    tag_attack: "ATAK",
    tag_benign: "BEZPIECZNE",
    deals_in_db: "Deale w bazie (bez tajnej kolumny secret_margin_notes):",
    status_won: "WON (wygrany)",
    status_neg: "NEGOTIATION (negocjacje)",
    status_prop: "PROPOSAL (oferta)",
    matrix_role: "Rola",
    matrix_rls: "RLS (wiersze)",
    matrix_cls: "CLS (secret_margin_notes)",
    live_trace: "Przepływ na żywo",
    live_stream_label: "Odpowiedź modelu na żywo (Ollama)",
    trace_running: "Przetwarzanie...",
    trace_done: "Zakończono",
    trace_error: "Błąd",
    generating_sql: "Generowanie SQL przez model...",
    rows: "wierszy",
    db_rows_label: "Wynik z bazy:",
    title_vuln: "Tryb podatny",
    title_secure: "Tryb bezpieczny",
    outcome_leak: "Wyciek danych!",
    outcome_blocked: "Atak zatrzymany",
    outcome_safe: "Bezpieczny wynik",
    outcome_no_leak: "Brak wycieku tym razem",
    outcome_no_sql: "Brak poprawnego SQL z modelu",
    st_ok: "OK",
    st_block: "BLOKADA",
    st_bypassed: "WYŁĄCZONY",
    st_skipped: "POMINIĘTO",
    st_error: "BŁĄD",
    st_running: "PRACUJE",
    st_idle: "GOTOWY",
    step_red_team: "Red Team",
    step_sql: "Model LLM",
    step_sentinel: "Strażnik promptu",
    step_ast: "Kontrola AST",
    step_db: "Baza danych",
    model_out: "Output modelu (Ollama)",
    cls_denied_tag: "kolumna zablokowana przez CLS",
    model_raw_note: "Model nie zwrócił poprawnego SELECT - poniżej surowa odpowiedź:",
    caller_ctx: "Kontekst przekazany do LLM",
    raw_llm_json: "Surowy JSON z Ollamy",
    rationale: "Uzasadnienie modelu",
    layer_llm: "Warstwa 1 · SQL Generator (Ollama)",
    layer_sentinel: "Warstwa 2 · Sentinel (bramka promptu)",
    layer_ast: "Warstwa 3 · AST Guard (sqlglot)",
    layer_db: "Warstwa 4 · PostgreSQL 16 (RLS / CLS)",
    sent_source: "Źródło decyzji",
    sent_risk: "ryzyko",
    sent_signals: "Wykryte sygnały",
    sent_none: "Brak sygnałów ataku",
    src_heuristics: "heurystyka leksykalna",
    src_llm: "klasyfikator LLM",
    src_disabled: "wyłączony",
    ast_tables: "Tabele",
    ast_cols: "Kolumny",
    ast_before: "SQL z modelu (przed AST)",
    ast_after: "SQL po walidacji / przepisaniu AST",
    db_role: "Rola DB",
    db_rls_flag: "row_security",
    db_session_cmds: "Komendy sesyjne wysłane do PostgreSQL",
    db_rls_rule: "Polityka wierszy (RLS)",
    db_cls_rule: "Polityka kolumn (CLS)",
    blocked_sentinel:
      "Egzekucja zablokowana przez Sentinela: SQL z modelu widać poniżej (LLM uległ injekcji).",
    blocked_ast: "Egzekucja zablokowana przez AST: SQL z modelu odrzucony przed bazą.",
    attack_ok: "Atak się udał: realny SQL z LLM + brak RLS/AST = wyciek danych.",
    vulnerable_benign: "Tryb podatny bez wycieku tym razem (brak gwarancji bezpieczeństwa).",
    secure_ok: "Bezpiecznie: bramki + RLS/CLS ograniczyły wynik.",
    db_reject: "Odrzut warstwy bazy (CLS/GRANT/RLS).",
    model_no_sql:
      "Model nie wygenerował poprawnego zapytania SELECT (małe modele 2B mogą gubić format SQL/JSON - poniżej surowa odpowiedź modelu).",
    done: "Zakończono.",
    warn_leak: "Ostrzeżenie: wykryto wyciek",
    warn_cross: "Cross-tenant: obce company_id w wyniku",
    warn_secret: "Ujawniono secret_margin_notes",
    edu_what: "Co się stało",
    edu_risk: "Dlaczego to groźne",
    edu_do: "Co robić",
    evidence: "Dowody z wyniku",
  },
  en: {
    page_title: "SeQuery",
    btn_crm_drawer: "CRM & Roles",
    btn_trace_drawer: "Layer Inspector",
    tab_crm: "CRM & Roles",
    tab_inspector: "Layer Inspector",
    sec_tenants: "Two companies in one database",
    sec_roles: "Role permissions (RLS vs CLS)",
    presets_label: "Test scenarios",
    idle_sub: "Awaiting query",
    idle_hint: "Select a scenario on the left and press Run to inspect each security gate.",
    user: "Caller",
    model_label: "AI Model (Ollama)",
    mode: "Mode",
    query: "Question",
    query_ph: "Show my deals...",
    vulnerable: "Vulnerable",
    secure: "Secure",
    compare: "Compare",
    run: "Run",
    running: "Running...",
    empty: "Enter a question",
    open_inspector: "Open defense layer details (Sentinel, AST, RLS/CLS) ->",
    inspector_empty: "Run a query to inspect defense layers (Sentinel, AST, PostgreSQL session commands).",
    role_quick_admin: "management · whole company · sees margin",
    role_quick_sales_rep: "sales rep · own deals only · no margin",
    role_quick_viewer: "analyst · whole company · no margin",
    preset_PI01: "Steal both companies' data",
    preset_PI02: "Impersonate admin (secret margins)",
    preset_BENIGN: "Normal question about my deals",
    tag_attack: "ATTACK",
    tag_benign: "BENIGN",
    deals_in_db: "Deals in DB (excluding secret_margin_notes):",
    status_won: "WON (closed-won)",
    status_neg: "NEGOTIATION (in talks)",
    status_prop: "PROPOSAL (offered)",
    matrix_role: "Role",
    matrix_rls: "RLS (rows)",
    matrix_cls: "CLS (secret_margin_notes)",
    live_trace: "Live execution flow",
    live_stream_label: "Live model output (Ollama)",
    trace_running: "Processing...",
    trace_done: "Completed",
    trace_error: "Error",
    generating_sql: "Generating SQL via local model...",
    rows: "rows",
    db_rows_label: "Database result:",
    title_vuln: "Vulnerable mode",
    title_secure: "Secure mode",
    outcome_leak: "Data leak!",
    outcome_blocked: "Attack blocked",
    outcome_safe: "Safe result",
    outcome_no_leak: "No leak this time",
    outcome_no_sql: "No valid SQL from model",
    st_ok: "PASSED",
    st_block: "BLOCKED",
    st_bypassed: "BYPASSED",
    st_skipped: "SKIPPED",
    st_error: "ERROR",
    st_running: "RUNNING",
    st_idle: "IDLE",
    step_red_team: "Red Team",
    step_sql: "LLM",
    step_sentinel: "Prompt Guard",
    step_ast: "SQL AST Check",
    step_db: "Database",
    model_out: "Model output (Ollama)",
    cls_denied_tag: "column denied by CLS",
    model_raw_note: "Model did not return a valid SELECT - showing raw response below:",
    caller_ctx: "Context sent to LLM",
    raw_llm_json: "Raw Ollama JSON",
    rationale: "Model rationale",
    layer_llm: "Layer 1 · SQL Generator (Ollama)",
    layer_sentinel: "Layer 2 · Sentinel (Prompt Gate)",
    layer_ast: "Layer 3 · AST Guard (sqlglot)",
    layer_db: "Layer 4 · PostgreSQL 16 (RLS / CLS)",
    sent_source: "Decision source",
    sent_risk: "risk",
    sent_signals: "Detected signals",
    sent_none: "No attack signals matched",
    src_heuristics: "lexical heuristics",
    src_llm: "LLM classifier",
    src_disabled: "disabled",
    ast_tables: "Tables",
    ast_cols: "Columns",
    ast_before: "Model SQL (before AST)",
    ast_after: "SQL after AST validation / rewrite",
    db_role: "DB role",
    db_rls_flag: "row_security",
    db_session_cmds: "Session SQL commands executed on PostgreSQL",
    db_rls_rule: "Row policy (RLS)",
    db_cls_rule: "Column policy (CLS)",
    blocked_sentinel:
      "Execution blocked by Sentinel: model SQL is shown below (LLM followed the injection).",
    blocked_ast: "Execution blocked by AST: model SQL rejected before the database.",
    attack_ok: "Attack succeeded: real LLM SQL + no RLS/AST = data leak.",
    vulnerable_benign: "Vulnerable run without a leak this time (not a security guarantee).",
    secure_ok: "Secure: gates + RLS/CLS constrained the result.",
    db_reject: "Rejected by database layer (CLS/GRANT/RLS).",
    model_no_sql:
      "Model did not emit a valid SELECT statement (small 2B models can fail JSON/SQL formatting - raw response shown below).",
    done: "Done.",
    warn_leak: "Warning: leak detected",
    warn_cross: "Cross-tenant: foreign company_id in result",
    warn_secret: "secret_margin_notes exposed",
    edu_what: "What happened",
    edu_risk: "Why it matters",
    edu_do: "What to do",
    evidence: "Evidence from result",
  },
};

const PIPELINE_ORDER = ["sql_gen", "sentinel", "ast", "db"];

const STEP_LABEL = {
  red_team: "step_red_team",
  sentinel: "step_sentinel",
  sql_gen: "step_sql",
  ast: "step_ast",
  db: "step_db",
};

const SQL_KEYWORDS = new Set([
  "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "IS", "NULL",
  "AS", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "ON", "ORDER", "BY",
  "GROUP", "HAVING", "LIMIT", "OFFSET", "DISTINCT", "ASC", "DESC", "UNION",
  "WITH", "CASE", "WHEN", "THEN", "ELSE", "END", "LIKE", "ILIKE", "BETWEEN",
]);

const SQL_FUNCS = new Set(["COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE"]);

let lang = localStorage.getItem("seq_lang") || "pl";
let lastPayload = null;
let lastStreamedText = "";
let ctxData = readInitialContext();
let activePresetId = null;
let timerHandle = null;
let timerStart = 0;
let liveStageState = {};

function readInitialContext() {
  try {
    const el = document.getElementById("initial-context");
    return el ? JSON.parse(el.textContent || "{}") : {};
  } catch {
    return {};
  }
}

const t = (key) => STR[lang][key] || STR.en[key] || key;
const mode = () => document.querySelector('input[name="mode"]:checked')?.value || "secure";

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatLatencyMs(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n)) return "-";
  return `${Math.round(n)} ms`;
}

function formatTimerSec(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n)) return "0.0 s";
  return `${(n / 1000).toFixed(1)} s`;
}

function humanStatus(status) {
  const s = String(status || "").toLowerCase();
  if (s === "ok" || s === "allow") return t("st_ok");
  if (s === "block" || s === "blocked_by_sentinel" || s === "blocked_by_ast") return t("st_block");
  if (s === "bypassed") return t("st_bypassed");
  if (s === "skipped" || s === "skipped_no_sql" || s === "model_no_sql") return t("st_skipped");
  if (s === "error") return t("st_error");
  if (s === "running") return t("st_running");
  if (s === "idle") return t("st_idle");
  return status || "-";
}

function openDrawer(tabName) {
  if (!sideDrawerEl || !backdropEl) return;
  sideDrawerEl.classList.add("is-open");
  sideDrawerEl.setAttribute("aria-hidden", "false");
  backdropEl.hidden = false;
  switchDrawerTab(tabName || "crm");
}

function closeDrawer() {
  if (!sideDrawerEl || !backdropEl) return;
  sideDrawerEl.classList.remove("is-open");
  sideDrawerEl.setAttribute("aria-hidden", "true");
  backdropEl.hidden = true;
}

function switchDrawerTab(tabName) {
  const isCrm = tabName === "crm";
  if (paneCrmEl) paneCrmEl.hidden = !isCrm;
  if (paneInspectorEl) paneInspectorEl.hidden = isCrm;
  document.querySelectorAll(".side-tab").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.tab === tabName);
  });
}

function allUsers() {
  return (ctxData.tenants || []).flatMap((tn) =>
    (tn.users || []).map((u) => ({ ...u, company_name: tn.name }))
  );
}

function activeUserObj() {
  const uname = userEl.value || "jan_sales_alpha";
  return allUsers().find((u) => u.username === uname) || allUsers()[0] || null;
}

function userDisplayLabel(u) {
  const mapped = USER_LABELS[u.username];
  if (mapped) return mapped[lang] || mapped.pl;
  return `${u.username} (${u.role})`;
}

function renderUsersSelect(preferredUsername) {
  const tenants = ctxData.tenants || [];
  const users = allUsers();
  if (!users.length) return;
  const keep = preferredUsername || userEl.value || "jan_sales_alpha";
  userEl.innerHTML = tenants
    .map((tn) => {
      const opts = (tn.users || [])
        .map((u) => `<option value="${esc(u.username)}">${esc(userDisplayLabel(u))}</option>`)
        .join("");
      return `<optgroup label="${esc(tn.name)}">${opts}</optgroup>`;
    })
    .join("");
  userEl.value = users.some((u) => u.username === keep) ? keep : users[0].username;
}

function renderModelsSelect(preferredModel) {
  if (!modelEl) return;
  const info = ctxData.ollama || {};
  const models = (info.models && info.models.length)
    ? info.models
    : [ctxData.model || "qwen2.5-coder:7b"];
  const keep = preferredModel || modelEl.value || info.default_model || models[0];
  modelEl.innerHTML = models
    .map((m) => `<option value="${esc(m)}">${esc(m)}</option>`)
    .join("");
  modelEl.value = models.includes(keep) ? keep : models[0];
}

function formatDealStatus(st) {
  if (st === "WON") return t("status_won");
  if (st === "NEGOTIATION") return t("status_neg");
  if (st === "PROPOSAL") return t("status_prop");
  return st || "";
}

function renderTenants() {
  const tenants = ctxData.tenants || [];
  const current = activeUserObj();
  tenantsGridEl.innerHTML = tenants
    .map((tn) => {
      const isActiveTenant = current && current.company_id === tn.id;
      const usersHtml = (tn.users || [])
        .map((u) => {
          const selected = current && current.username === u.username ? "is-selected" : "";
          return `<button type="button" class="user-pill ${selected}" data-pick-user="${esc(u.username)}">
            <span>${esc(userDisplayLabel(u))}</span>
          </button>`;
        })
        .join("");

      const dealsHtml = (tn.deals || [])
        .map(
          (d) => `<div class="deal-mini">
            <span>#${esc(d.id)} · ${esc(d.client_name)}</span>
            <span class="deal-mini__meta">${esc(formatDealStatus(d.status))} · ${Number(d.amount).toLocaleString()}</span>
          </div>`
        )
        .join("");

      return `<article class="tenant-card ${isActiveTenant ? "is-active-tenant" : ""}">
        <div class="tenant-card__head">
          <h4 class="tenant-card__title">${esc(tn.name)}</h4>
          <span class="tenant-id">company_id=${esc(tn.id)}</span>
        </div>
        <div class="tenant-users">${usersHtml}</div>
        <div class="tenant-deals">
          <span class="tenant-deals__label">${t("deals_in_db")}</span>
          ${dealsHtml}
        </div>
      </article>`;
    })
    .join("");

  tenantsGridEl.querySelectorAll("[data-pick-user]").forEach((btn) => {
    btn.addEventListener("click", () => {
      userEl.value = btn.dataset.pickUser || "";
      syncActorContextUI();
    });
  });
}

function matrixIcon(kind) {
  if (kind === "ok") {
    return `<svg class="matrix-icon matrix-icon--ok" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 8.5l3 3 7-7" stroke="currentColor" stroke-width="1.8" stroke-linecap="square"/></svg>`;
  }
  if (kind === "deny") {
    return `<svg class="matrix-icon matrix-icon--deny" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="square"/></svg>`;
  }
  return `<svg class="matrix-icon matrix-icon--scope" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="3" y="3" width="10" height="10" stroke="currentColor" stroke-width="1.5"/><circle cx="8" cy="8" r="2" fill="currentColor"/></svg>`;
}

function renderRoles() {
  const roles = ctxData.roles || [];
  const current = activeUserObj();
  const rowsHtml = roles
    .map((r) => {
      const isActive = current && current.role === r.role ? "is-active-role" : "";
      const title = lang === "pl" ? r.title_pl : r.title_en;
      const rls = lang === "pl" ? r.rls_pl : r.rls_en;
      const cls = lang === "pl" ? r.cls_pl : r.cls_en;
      const note = lang === "pl" ? r.note_pl : r.note_en;
      const rlsIcon = r.role === "sales_rep" ? matrixIcon("scope") : matrixIcon("ok");
      const clsIcon = r.sees_secrets ? matrixIcon("ok") : matrixIcon("deny");
      return `<tr class="${isActive}">
        <td>
          <span class="matrix-role">${esc(title)}</span>
          ${note ? `<span class="matrix-note">${esc(note)}</span>` : ""}
        </td>
        <td><span class="matrix-cell">${rlsIcon}<span>${esc(rls)}</span></span></td>
        <td><span class="matrix-cell">${clsIcon}<span>${esc(cls)}</span></span></td>
      </tr>`;
    })
    .join("");

  rolesGridEl.innerHTML = `<div class="table-wrap roles-matrix">
    <table>
      <thead>
        <tr>
          <th>${esc(t("matrix_role"))}</th>
          <th>${esc(t("matrix_rls"))}</th>
          <th>${esc(t("matrix_cls"))}</th>
        </tr>
      </thead>
      <tbody>${rowsHtml}</tbody>
    </table>
  </div>`;
}

function presetShortLabel(p) {
  if (p.id === "PI-01") return t("preset_PI01");
  if (p.id === "PI-02") return t("preset_PI02");
  if (p.id === "BENIGN") return t("preset_BENIGN");
  return p.id;
}

function renderPresets() {
  if (!presetsChipsEl) return;
  const presets = ctxData.presets || [];
  presetsChipsEl.innerHTML = presets
    .map((p) => {
      const isBenign = p.kind === "benign";
      const active = activePresetId === p.id ? "is-active" : "";
      const title = lang === "pl" ? p.title_pl : p.title_en;
      const tag = isBenign ? t("tag_benign") : t("tag_attack");
      const tagCls = isBenign ? "chip__tag--benign" : "chip__tag--attack";
      return `<button
        type="button"
        class="chip ${active}"
        data-preset-id="${esc(p.id)}"
        title="${esc(title)}"
      >
        <span class="chip__tag ${tagCls}">${esc(tag)}</span>
        <span>${esc(presetShortLabel(p))}</span>
      </button>`;
    })
    .join("");

  presetsChipsEl.querySelectorAll("[data-preset-id]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pid = btn.dataset.presetId;
      const preset = (ctxData.presets || []).find((x) => x.id === pid);
      if (!preset) return;
      activePresetId = pid;
      queryEl.value = (lang === "en" && preset.query_en) ? preset.query_en : (preset.query || "");
      if (preset.user) userEl.value = preset.user;
      renderPresets();
      syncActorContextUI();
    });
  });
}

function syncActorContextUI() {
  const current = activeUserObj();
  renderTenants();
  renderRoles();
  if (roleQuickHintEl) {
    if (current) {
      const key = `role_quick_${current.role}`;
      roleQuickHintEl.textContent = STR[lang][key] ? t(key) : `${current.role}`;
    } else {
      roleQuickHintEl.textContent = "";
    }
  }
}

function renderInspectorDrawerContent() {
  if (!inspectorContentEl) return;
  if (!lastPayload) {
    inspectorContentEl.innerHTML = `<p class="meta">${esc(t("inspector_empty"))}</p>`;
    return;
  }
  if (lastPayload.mode === "compare") {
    inspectorContentEl.innerHTML = `
      <h3 class="side-pane__title">${esc(t("title_vuln"))}</h3>
      ${eduBlock(lastPayload.vulnerable)}
      ${renderLayersBlock(lastPayload.vulnerable)}
      <h3 class="side-pane__title">${esc(t("title_secure"))}</h3>
      ${eduBlock(lastPayload.secure)}
      ${renderLayersBlock(lastPayload.secure)}
    `;
  } else {
    inspectorContentEl.innerHTML = `
      ${eduBlock(lastPayload)}
      ${renderLayersBlock(lastPayload)}
    `;
  }
}

function renderIdlePipeline() {
  if (!idlePipelineEl) return;
  const idleSteps = PIPELINE_ORDER.map((id) => ({ id, status: "idle", duration_ms: null }));
  idlePipelineEl.innerHTML = renderPipelineDiagram(idleSteps);
}

function applyI18n() {
  document.documentElement.lang = lang;
  document.title = t("page_title");
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  });
  document.querySelectorAll(".lang__btn").forEach((btn) => {
    btn.setAttribute("aria-pressed", String(btn.dataset.lang === lang));
  });
  if (activePresetId) {
    const p = (ctxData.presets || []).find((x) => x.id === activePresetId);
    if (p) queryEl.value = (lang === "en" && p.query_en) ? p.query_en : (p.query || "");
  }
  renderUsersSelect(userEl.value);
  renderModelsSelect(modelEl ? modelEl.value : null);
  renderPresets();
  syncActorContextUI();
  renderIdlePipeline();
  renderInspectorDrawerContent();
  if (lastPayload) renderPayload(lastPayload);
}

/* ============================================================================
   Hero Pipeline Diagram Component
   ============================================================================ */
function normalizePipelineStages(steps = [], execStatus = "") {
  const byId = {};
  for (const s of steps) byId[s.id] = s;

  // Map stages cleanly: when Sentinel blocks downstream execution, show AST/DB as SKIPPED
  const blockedBySentinel = execStatus === "blocked_by_sentinel";
  const blockedByAst = execStatus === "blocked_by_ast";

  let brokenAfter = -1;
  const normalized = PIPELINE_ORDER.map((id, idx) => {
    const raw = byId[id] || { id, status: "idle", duration_ms: null };
    let status = String(raw.status || "idle").toLowerCase();

    if (blockedBySentinel && idx > 1) {
      status = "skipped";
    } else if (blockedByAst && idx > 2) {
      status = "skipped";
    }

    let visual = "idle";
    if (status === "running") visual = "running";
    else if (["ok", "allow"].includes(status)) visual = "passed";
    else if (["block", "error", "blocked_by_sentinel", "blocked_by_ast"].includes(status)) {
      visual = "blocked";
      if (brokenAfter === -1) brokenAfter = idx;
    } else if (status === "bypassed") {
      visual = "bypassed";
    } else if (["skipped", "skipped_no_sql", "model_no_sql"].includes(status)) {
      visual = "skipped";
    }

    return {
      id,
      label: stepLabel(id),
      status,
      visual,
      duration_ms: raw.duration_ms ?? null,
    };
  });

  // Ensure anything downstream of a hard block appears skipped
  if (brokenAfter !== -1) {
    for (let i = brokenAfter + 1; i < normalized.length; i++) {
      if (normalized[i].visual === "idle" || normalized[i].visual === "skipped") {
        normalized[i].visual = "skipped";
        normalized[i].status = "skipped";
      }
    }
  }

  return { stages: normalized, brokenAfter };
}

function renderPipelineDiagram(steps = [], execStatus = "") {
  const { stages, brokenAfter } = normalizePipelineStages(steps, execStatus);
  return `<div class="pipeline" role="list">${stages
    .map((st, idx) => {
      const nodeHtml = `<div class="pipe-node pipe-node--${st.visual}" role="listitem">
        <div class="pipe-node__top">
          <span class="pipe-node__name">${esc(st.label)}</span>
        </div>
        <div class="pipe-node__bot">
          <span class="pipe-node__status">${esc(humanStatus(st.status))}</span>
          <span class="pipe-node__ms">${st.duration_ms != null ? esc(formatLatencyMs(st.duration_ms)) : "-"}</span>
        </div>
      </div>`;

      if (idx === stages.length - 1) return nodeHtml;

      const next = stages[idx + 1];
      let connCls = "pipe-conn";
      if (brokenAfter === idx || st.visual === "blocked") {
        connCls += " pipe-conn--broken";
      } else if (next.visual === "running") {
        connCls += " pipe-conn--active";
      } else if (st.visual === "passed" && next.visual !== "skipped") {
        connCls += " pipe-conn--passed";
      } else if (st.visual === "bypassed") {
        connCls += " pipe-conn--bypassed";
      }

      return `${nodeHtml}<div class="${connCls}" aria-hidden="true"></div>`;
    })
    .join("")}</div>`;
}

/* ============================================================================
   SQL Syntax Highlighter + Offending Token Highlight
   ============================================================================ */
function highlightSql(sqlText, flagDeniedColumn) {
  const tokenRe = /('(?:[^'\\]|\\.)*')|\b(\d+(?:\.\d+)?)\b|\b([A-Za-z_][A-Za-z0-9_]*)\b|([(),.*=<>!+\-/;]+)|(\s+)/g;
  let out = "";
  let m;
  let lastIndex = 0;

  while ((m = tokenRe.exec(sqlText)) !== null) {
    if (m.index > lastIndex) {
      out += esc(sqlText.slice(lastIndex, m.index));
    }
    lastIndex = tokenRe.lastIndex;

    const [full, strTok, numTok, wordTok, opTok, wsTok] = m;
    if (wsTok) {
      out += wsTok;
    } else if (strTok) {
      out += `<span class="tok-str">${esc(strTok)}</span>`;
    } else if (numTok) {
      out += `<span class="tok-num">${esc(numTok)}</span>`;
    } else if (wordTok) {
      const upper = wordTok.toUpperCase();
      const lower = wordTok.toLowerCase();
      if (flagDeniedColumn && lower === "secret_margin_notes") {
        out += `<span class="tok-denied">${esc(wordTok)}<span class="tok-denied__tag">${esc(t("cls_denied_tag"))}</span></span>`;
      } else if (SQL_KEYWORDS.has(upper)) {
        out += `<span class="tok-kw">${esc(wordTok)}</span>`;
      } else if (SQL_FUNCS.has(upper)) {
        out += `<span class="tok-fn">${esc(wordTok)}</span>`;
      } else {
        out += esc(wordTok);
      }
    } else if (opTok) {
      out += `<span class="tok-op">${esc(opTok)}</span>`;
    } else {
      out += esc(full);
    }
  }

  if (lastIndex < sqlText.length) {
    out += esc(sqlText.slice(lastIndex));
  }
  return out;
}

function stepLabel(step) {
  const key = STEP_LABEL[step.id || step];
  return key ? t(key) : (step.label || step);
}

function tagClass(status) {
  const s = String(status || "").toLowerCase();
  if (["ok", "allow"].includes(s)) return "is-ok";
  if (["block", "error", "blocked_by_sentinel", "blocked_by_ast"].includes(s)) return "is-block";
  if (["bypassed", "skipped", "skipped_no_sql", "model_no_sql", "warn"].includes(s)) return "is-warn";
  if (s === "running") return "is-running";
  return "";
}

function table(rows = [], actorCompanyId) {
  if (!rows.length) return `<p class="meta">0 ${t("rows")}</p>`;
  const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  const head = cols.map((c) => `<th>${esc(c)}</th>`).join("");
  const body = rows
    .map((r) => {
      const tds = cols
        .map((c) => {
          const v = r[c] ?? "";
          let cls = "";
          if (c === "secret_margin_notes" && v) cls = "secret";
          else if (c === "company_id" && actorCompanyId != null && Number(v) !== Number(actorCompanyId)) {
            cls = "foreign-cell";
          }
          return `<td class="${cls}">${esc(v)}</td>`;
        })
        .join("");
      return `<tr>${tds}</tr>`;
    })
    .join("");
  return `<p class="meta">${t("db_rows_label")} ${rows.length} ${t("rows")}</p>
    <div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

function verdictText(r) {
  const key = r.verdict_key;
  if (key && STR[lang][key]) {
    if (key === "blocked_ast" && r.ast_reason) return `${t(key)} (${r.ast_reason})`;
    if (key === "db_reject" && r.exec_error) return `${t(key)} ${r.exec_error}`;
    return t(key);
  }
  return r.verdict_text || "";
}

function enEdu(r) {
  const map = {
    blocked_sentinel: {
      what: "The model still produced SQL from a hostile prompt; Sentinel blocked execution only.",
      risk: "The LLM alone is not a trust boundary - without more layers a leak would occur.",
      do: "Use Compare with Vulnerable to see the same kind of SQL execute without gates.",
    },
    blocked_ast: {
      what: `Model SQL failed AST (${r.ast_reason || "fail"}).`,
      risk: "Even plausible SQL can bypass intent (SELECT *, secret columns).",
      do: "Keep table/column allow-lists and ban DDL/DML in AST before the DB.",
    },
    attack_ok: {
      what: "The LLM followed Prompt Injection and emitted overly broad SQL; without RLS/CLS data leaked.",
      risk: "Cross-tenant rows and/or secret_margin_notes visible to the wrong role.",
      do: "Enable Defense-in-Depth: Sentinel + AST + PostgreSQL RLS/CLS. Never trust the prompt alone.",
    },
    vulnerable_benign: {
      what: "This time the model emitted narrow SQL - the result looks harmless.",
      risk: "No guarantee: another prompt/model can leak. Luck is not security.",
      do: "Run Attack 1 in Vulnerable, then Compare with Secure.",
    },
    secure_ok: {
      what: "Model SQL passed the gates; RLS/CLS limited rows/columns to the caller's rights.",
      risk: "Watch Sentinel false negatives - the DB must still enforce tenant isolation.",
      do: "Check evidence: companies_in_result should only include the actor company_id.",
    },
    db_reject: {
      what: `PostgreSQL rejected the query (${r.exec_error || "permission/RLS"}).`,
      risk: "Good CLS/GRANT signal - surface a safe error in UI without leaking details.",
      do: "Show a safe message in UI; audit forbidden column access in logs.",
    },
    model_no_sql: {
      what: "The selected LLM did not emit a valid SELECT statement.",
      risk: "Very small models (e.g. 2B) often fail JSON/SQL formatting on complex prompts.",
      do: "Inspect the raw model response below or switch to a coding model (e.g. qwen2.5-coder:7b).",
    },
  };
  return map[r.verdict_key] || { what: r.verdict_text || "", risk: "-", do: "Try Attack 1 / Compare." };
}

function eduBlock(r) {
  const e = r.education || {};
  if (!e.what && !e.risk && !e.do) return "";
  const what = lang === "en" ? enEdu(r).what : e.what;
  const risk = lang === "en" ? enEdu(r).risk : e.risk;
  const doit = lang === "en" ? enEdu(r).do : e.do;
  return `<div class="edu">
    <div><span>${t("edu_what")}</span><p>${esc(what || "")}</p></div>
    <div><span>${t("edu_risk")}</span><p>${esc(risk || "")}</p></div>
    <div><span>${t("edu_do")}</span><p>${esc(doit || "")}</p></div>
  </div>`;
}

function warnBlock(r) {
  const ev = r.evidence || {};
  if (!ev.cross_tenant && !ev.secrets_exposed) return "";
  const bits = [];
  if (ev.cross_tenant) {
    bits.push(`${t("warn_cross")}: ${esc((ev.foreign_company_ids || []).join(", "))}`);
  }
  if (ev.secrets_exposed) bits.push(t("warn_secret"));
  return `<div class="warn">
    <strong>${t("warn_leak")}</strong>
    <p>${bits.join(" · ")}</p>
    <p class="meta">${t("evidence")}: companies=[${esc((ev.companies_in_result || []).join(", "))}]
      · actor_company=${esc(ev.actor_company_id)} · rows=${esc(ev.row_count)}</p>
  </div>`;
}

function renderModelOutputBox(r) {
  const llm = (r.layers && r.layers.llm) || {};
  const modelSql = (r.sql_model || llm.sql_model || r.sql || "").trim();
  const rawFallback = (r.llm_raw_text || llm.raw_text || lastStreamedText || "").trim();
  const modelName = llm.model || r.model || "ollama";
  const dur = llm.duration_ms != null ? formatLatencyMs(llm.duration_ms) : null;
  const flagClsDenied =
    r.role !== "admin" &&
    (r.ast_reason === "column_cls_blocked:secret_margin_notes" ||
      (r.evidence && r.evidence.secrets_exposed) ||
      /\bsecret_margin_notes\b/i.test(modelSql));

  const codeHtml = modelSql
    ? highlightSql(modelSql, flagClsDenied)
    : esc(rawFallback || "-");

  return `<div class="model-box">
    <div class="model-box__head">
      <span class="model-box__title">${t("model_out")} · ${esc(modelName)}</span>
      <div>${dur ? `<span class="meta-pill">${esc(dur)}</span>` : ""}</div>
    </div>
    ${!modelSql && rawFallback ? `<p class="meta">${esc(t("model_raw_note"))}</p>` : ""}
    <pre class="code-block">${codeHtml}</pre>
  </div>`;
}

function humanSource(src) {
  if (src === "heuristics") return t("src_heuristics");
  if (src === "llm_grounded") return t("src_llm");
  if (src === "disabled") return t("src_disabled");
  return src || "-";
}

function renderLayersBlock(r) {
  const L = r.layers || {};
  const llm = L.llm || {};
  const sent = L.sentinel || {};
  const ast = L.ast || {};
  const db = L.db || {};

  const modelSql = r.sql_model || llm.sql_model || r.sql || "-";
  const modelName = llm.model || r.model || "ollama";
  const rawJson = llm.raw || r.sql_raw_llm;
  const tokenText =
    llm.prompt_tokens != null && llm.completion_tokens != null
      ? `${llm.prompt_tokens} -> ${llm.completion_tokens} tok (${llm.total_tokens ?? llm.prompt_tokens + llm.completion_tokens})`
      : null;

  const llmCard = `<div class="layer-card">
    <div class="layer-card__head">
      <span class="layer-card__title">${t("layer_llm")} · ${esc(modelName)}</span>
      <div class="layer-card__meta">
        ${llm.duration_ms != null ? `<span class="trace-ms">${esc(formatLatencyMs(llm.duration_ms))}</span>` : ""}
        <span class="status-tag ${modelSql && modelSql !== "-" ? "is-ok" : "is-block"}">${modelSql && modelSql !== "-" ? t("st_ok") : t("st_error")}</span>
      </div>
    </div>
    <div class="ollama-meta">
      ${llm.endpoint ? `<span class="meta-pill">${esc(llm.endpoint)}</span>` : ""}
      ${tokenText ? `<span class="meta-pill">${esc(tokenText)}</span>` : ""}
    </div>
    ${r.sql_rationale ? `<div class="layer-card__kv"><div><strong>${t("rationale")}:</strong> ${esc(r.sql_rationale)}</div></div>` : ""}
    ${llm.caller_context ? `<div class="layer-card__kv"><strong>${t("caller_ctx")}:</strong><pre class="code-block code-block--muted">${esc(llm.caller_context)}</pre></div>` : ""}
    ${rawJson ? `<details class="raw-details"><summary>${t("raw_llm_json")}</summary><pre class="code-block code-block--muted">${esc(JSON.stringify(rawJson, null, 2))}</pre></details>` : ""}
  </div>`;

  const sentVerdict = sent.verdict || r.sentinel_verdict || "-";
  const signals = sent.signals || r.sentinel_signals || [];
  const sentCard = `<div class="layer-card">
    <div class="layer-card__head">
      <span class="layer-card__title">${t("layer_sentinel")}</span>
      <div class="layer-card__meta">
        ${sent.duration_ms != null ? `<span class="trace-ms">${esc(formatLatencyMs(sent.duration_ms))}</span>` : ""}
        <span class="status-tag ${tagClass(sentVerdict)}">${esc(humanStatus(sentVerdict))}</span>
      </div>
    </div>
    <div class="layer-card__kv">
      <div><strong>${t("sent_source")}:</strong> ${esc(humanSource(sent.source))} · ${esc(t("sent_risk"))}=${esc(sent.risk || r.sentinel_risk || "-")}</div>
      <div><strong>${t("sent_signals")}:</strong></div>
      <div class="signals-row">
        ${signals.length ? signals.map((s) => `<span class="sig-pill">${esc(s)}</span>`).join("") : `<span class="meta">${t("sent_none")}</span>`}
      </div>
      ${(sent.reasons || []).length ? `<div class="meta">${esc(sent.reasons.join(" · "))}</div>` : ""}
    </div>
  </div>`;

  const astStatus = ast.active === false ? "bypassed" : (ast.ok ? (ast.rewritten ? "rewritten" : "ok") : "block");
  const astRule = lang === "pl" ? (ast.rule_pl || "") : (ast.rule_en || "");
  const astInput = ast.input_sql || modelSql;
  const astOutput = ast.output_sql || r.sql || modelSql;
  const astCard = `<div class="layer-card">
    <div class="layer-card__head">
      <span class="layer-card__title">${t("layer_ast")}</span>
      <div class="layer-card__meta">
        ${ast.duration_ms != null ? `<span class="trace-ms">${esc(formatLatencyMs(ast.duration_ms))}</span>` : ""}
        <span class="status-tag ${tagClass(ast.active === false ? "bypassed" : (ast.ok ? (ast.rewritten ? "warn" : "ok") : "block"))}">${esc(ast.reason || humanStatus(astStatus))}</span>
      </div>
    </div>
    <div class="layer-card__kv">
      ${astRule ? `<div>${esc(astRule)}</div>` : ""}
      ${(ast.tables_found || []).length || (ast.columns_found || []).length
        ? `<div><strong>${t("ast_tables")}:</strong> ${esc((ast.tables_found || []).join(", ") || "-")} · <strong>${t("ast_cols")}:</strong> ${esc((ast.columns_found || []).join(", ") || "-")}</div>`
        : ""}
      ${ast.rewritten ? `
        <div><strong>${t("ast_before")}:</strong><pre class="code-block code-block--muted">${esc(astInput)}</pre></div>
        <div><strong>${t("ast_after")}:</strong><pre class="code-block">${esc(astOutput)}</pre></div>
      ` : ""}
    </div>
  </div>`;

  const dbStatus = db.status || r.exec_status || "-";
  const dbRlsRule = lang === "pl" ? (db.rls_policy_pl || "") : (db.rls_policy_en || "");
  const dbClsRule = lang === "pl" ? (db.cls_policy_pl || "") : (db.cls_policy_en || "");
  const dbCommands = db.session_commands || [];
  const dbCard = `<div class="layer-card">
    <div class="layer-card__head">
      <span class="layer-card__title">${t("layer_db")}</span>
      <div class="layer-card__meta">
        ${db.duration_ms != null ? `<span class="trace-ms">${esc(formatLatencyMs(db.duration_ms))}</span>` : ""}
        <span class="status-tag ${tagClass(db.executed === false ? "skipped" : dbStatus)}">${esc(humanStatus(db.skipped_reason || dbStatus))}</span>
      </div>
    </div>
    <div class="layer-card__kv">
      <div><strong>${t("db_role")}:</strong> ${esc(db.db_role || "-")} · <strong>${t("db_rls_flag")}:</strong> ${esc(db.row_security || "-")}</div>
      ${dbRlsRule ? `<div><strong>${t("db_rls_rule")}:</strong> ${esc(dbRlsRule)}</div>` : ""}
      ${dbClsRule ? `<div><strong>${t("db_cls_rule")}:</strong> ${esc(dbClsRule)}</div>` : ""}
      ${dbCommands.length ? `<div><strong>${t("db_session_cmds")}:</strong><pre class="code-block code-block--muted">${esc(dbCommands.join("\n"))}</pre></div>` : ""}
    </div>
  </div>`;

  return `<div class="layers-stack">${llmCard}${sentCard}${astCard}${dbCard}</div>`;
}

function outcomeBadge(r) {
  const vk = r.verdict_key || "";
  if (vk === "attack_ok") return `<span class="badge badge--vuln">${t("outcome_leak")}</span>`;
  if (vk === "model_no_sql") return `<span class="badge badge--warn">${t("outcome_no_sql")}</span>`;
  if (["blocked_sentinel", "blocked_ast", "db_reject"].includes(vk)) {
    return `<span class="badge badge--secure">${t("outcome_blocked")}</span>`;
  }
  if (vk === "secure_ok") return `<span class="badge badge--secure">${t("outcome_safe")}</span>`;
  if (vk === "vulnerable_benign") return `<span class="badge badge--warn">${t("outcome_no_leak")}</span>`;
  return r.mode === "vulnerable"
    ? `<span class="badge badge--vuln">${t("vulnerable")}</span>`
    : `<span class="badge badge--secure">${t("secure")}</span>`;
}

function report(r, title) {
  return `<article class="pane">
    <div class="pane__head">
      <h2 class="sec-title">${esc(title)}</h2>
      ${outcomeBadge(r)}
    </div>
    ${renderPipelineDiagram(r.pipeline || [], r.exec_status)}
    <p class="verdict">${esc(verdictText(r))}</p>
    ${warnBlock(r)}
    ${renderModelOutputBox(r)}
    ${table(r.rows_preview || [], r.company_id)}
    <button type="button" class="inspect-btn" data-open-inspector="true">${esc(t("open_inspector"))}</button>
  </article>`;
}

function renderPayload(data) {
  if (idleStateEl) idleStateEl.hidden = true;
  if (data.mode === "compare") {
    panelsEl.className = "compare";
    panelsEl.innerHTML =
      report(data.vulnerable, t("title_vuln")) + report(data.secure, t("title_secure"));
  } else {
    panelsEl.className = "";
    panelsEl.innerHTML = report(
      data,
      data.mode === "vulnerable" ? t("title_vuln") : t("title_secure")
    );
  }
  panelsEl.querySelectorAll("[data-open-inspector]").forEach((btn) => {
    btn.addEventListener("click", () => openDrawer("inspector"));
  });
  renderInspectorDrawerContent();
}

function traceKey(ev) {
  return `${ev.branch || "run"}::${ev.step}`;
}

function formatTraceDetail(ev) {
  if (ev.event === "step_start") {
    if (ev.step === "sql_gen") return `${ev.model || ""} · ${t("generating_sql")}`;
    if (ev.step === "db") return `${ev.db_role || ""}`;
    return "...";
  }
  if (ev.step === "red_team") return ev.detail || "";
  if (ev.step === "sql_gen") return ev.sql_model || "-";
  if (ev.step === "sentinel") {
    const sigs = (ev.signals || []).join(", ");
    return `${ev.source || ""}${sigs ? ` · [${sigs}]` : ""}`;
  }
  if (ev.step === "ast") {
    const rule = lang === "pl" ? (ev.rule_pl || ev.reason) : (ev.rule_en || ev.reason);
    return rule || ev.reason || "";
  }
  if (ev.step === "db") {
    if (ev.reason) return `${ev.reason}`;
    if (ev.error) return ev.error;
    return `${ev.row_count ?? 0} ${t("rows")}`;
  }
  return "";
}

function renderLivePipelineFromState(branch) {
  if (!livePipelineEl) return;
  const branchState = liveStageState[branch] || {};
  const steps = PIPELINE_ORDER.map((id) => branchState[id] || { id, status: "idle", duration_ms: null });
  livePipelineEl.innerHTML = renderPipelineDiagram(steps);
}

function upsertTraceRow(ev) {
  if (!ev || !ev.step) return;
  const branch = ev.branch || "run";
  if (!liveStageState[branch]) liveStageState[branch] = {};
  const isDone = ev.event === "step_done";
  const rawStatus = isDone ? (ev.status || "ok") : "running";
  liveStageState[branch][ev.step] = {
    id: ev.step,
    status: rawStatus,
    duration_ms: isDone ? (ev.duration_ms ?? null) : null,
  };
  renderLivePipelineFromState(branch);

  const key = traceKey(ev);
  let row = traceListEl.querySelector(`[data-trace-key="${CSS.escape(key)}"]`);
  const branchLabel = branch === "vulnerable" ? t("vulnerable") : (branch === "secure" ? t("secure") : branch);
  const branchCls = branch === "vulnerable" ? "trace-row__branch--vulnerable" : "trace-row__branch--secure";
  const durText = isDone && ev.duration_ms != null ? formatLatencyMs(ev.duration_ms) : "";

  const html = `
    <span class="trace-row__branch ${branchCls}">${esc(branchLabel)}</span>
    <div class="trace-row__body">
      <div class="trace-row__title">${esc(stepLabel(ev.step))}</div>
      <div class="trace-row__detail">${esc(formatTraceDetail(ev))}</div>
    </div>
    <div class="trace-row__right">
      ${durText ? `<span class="trace-ms">${esc(durText)}</span>` : ""}
      <span class="status-tag ${tagClass(rawStatus)}">${esc(humanStatus(rawStatus))}</span>
    </div>
  `;

  if (!row) {
    row = document.createElement("div");
    row.className = "trace-row";
    row.dataset.traceKey = key;
    traceListEl.appendChild(row);
  }
  row.innerHTML = html;
}

function handleLlmChunk(ev) {
  if (!liveStreamEl || !liveStreamCodeEl) return;
  lastStreamedText = ev.partial || "";
  liveStreamEl.hidden = false;
  liveStreamCodeEl.textContent = lastStreamedText;
  liveStreamCodeEl.scrollTop = liveStreamCodeEl.scrollHeight;

  const key = traceKey(ev);
  const row = traceListEl.querySelector(`[data-trace-key="${CSS.escape(key)}"]`);
  if (row) {
    const detailEl = row.querySelector(".trace-row__detail");
    if (detailEl) {
      detailEl.textContent = `${t("generating_sql")} ${formatTimerSec(ev.elapsed_ms)} (${ev.chunks} tok)`;
    }
  }
}

function startTimer() {
  stopTimer();
  timerStart = performance.now();
  if (traceTimerEl) traceTimerEl.textContent = "0.0 s";
  timerHandle = setInterval(() => {
    if (traceTimerEl) {
      traceTimerEl.textContent = `${((performance.now() - timerStart) / 1000).toFixed(1)} s`;
    }
  }, 100);
}

function stopTimer() {
  if (timerHandle) {
    clearInterval(timerHandle);
    timerHandle = null;
  }
}

function resetTrace() {
  lastStreamedText = "";
  liveStageState = {};
  traceListEl.innerHTML = "";
  panelsEl.innerHTML = "";
  if (idleStateEl) idleStateEl.hidden = true;
  if (livePipelineEl) livePipelineEl.innerHTML = renderPipelineDiagram([]);
  if (liveStreamEl && liveStreamCodeEl) {
    liveStreamEl.hidden = true;
    liveStreamCodeEl.textContent = "";
  }
  outEl.hidden = false;
  if (liveCardEl) liveCardEl.hidden = false;
  traceStateEl.textContent = t("trace_running");
  traceStateEl.className = "trace__badge is-running";
  startTimer();
}

function busy(on) {
  runBtn.disabled = on;
  statusEl.textContent = on ? t("running") : "";
}

async function run() {
  const query = queryEl.value.trim();
  if (!query) {
    statusEl.textContent = t("empty");
    return;
  }
  busy(true);
  resetTrace();
  try {
    const res = await fetch("/api/run-stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: mode(),
        username: userEl.value,
        model: modelEl ? modelEl.value : null,
        query,
        use_red_team: Boolean(redteamEl && redteamEl.checked),
      }),
    });

    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.detail || res.statusText);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";
    let finalPayload = null;

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";

      for (const chunk of parts) {
        const lines = chunk.split("\n").filter((l) => l.startsWith("data: "));
        for (const line of lines) {
          const msg = JSON.parse(line.slice(6));
          if (msg.event === "step_start" || msg.event === "step_done") {
            upsertTraceRow(msg);
          } else if (msg.event === "llm_chunk") {
            handleLlmChunk(msg);
          } else if (msg.event === "final") {
            finalPayload = msg.payload;
          } else if (msg.event === "error") {
            throw new Error(msg.detail || "Stream error");
          }
        }
      }
    }

    if (!finalPayload) {
      throw new Error("Missing final payload from SSE stream");
    }

    stopTimer();
    lastPayload = finalPayload;
    if (liveCardEl) liveCardEl.hidden = true;
    renderPayload(finalPayload);
    outEl.hidden = false;
    statusEl.textContent = "";
    traceStateEl.textContent = t("trace_done");
    traceStateEl.className = "trace__badge";
  } catch (err) {
    stopTimer();
    statusEl.textContent = String(err.message || err);
    traceStateEl.textContent = t("trace_error");
    traceStateEl.className = "trace__badge";
  } finally {
    busy(false);
  }
}

async function refreshContext() {
  try {
    const res = await fetch("/api/context");
    if (!res.ok) return;
    ctxData = await res.json();
    renderUsersSelect(userEl.value);
    renderModelsSelect(modelEl ? modelEl.value : null);
    applyI18n();
  } catch {
    // Keep initial context embedded by the server template
  }
}

userEl.addEventListener("change", () => {
  syncActorContextUI();
});

queryEl.addEventListener("input", () => {
  activePresetId = null;
  renderPresets();
});

queryEl.addEventListener("keydown", (ev) => {
  if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") {
    ev.preventDefault();
    run();
  }
});

if (openCrmBtn) {
  openCrmBtn.addEventListener("click", () => openDrawer("crm"));
}
if (openTraceBtn) {
  openTraceBtn.addEventListener("click", () => openDrawer("inspector"));
}
if (closeDrawerBtn) {
  closeDrawerBtn.addEventListener("click", closeDrawer);
}
if (backdropEl) {
  backdropEl.addEventListener("click", closeDrawer);
}
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") closeDrawer();
});

document.querySelectorAll(".side-tab").forEach((btn) => {
  btn.addEventListener("click", () => switchDrawerTab(btn.dataset.tab || "crm"));
});

document.querySelectorAll(".lang__btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    lang = btn.dataset.lang || "pl";
    localStorage.setItem("seq_lang", lang);
    applyI18n();
  });
});

runBtn.addEventListener("click", run);

renderUsersSelect("jan_sales_alpha");
renderModelsSelect();
applyI18n();
refreshContext();
