/* app.js - HT Scanner GUI (v2)
Maneja el SSE del backend, dashboard en tiempo real, crawler/recon,
sugerencias IA y descarga de reportes en multiples formatos.
*/
(function () {
  const $ = (id) => document.getElementById(id);
  const startBtn = $("startBtn"), targetInput = $("target"), authCheck = $("authCheck");
  const control = $("control"), log = $("log"), findings = $("findings");
  const status = $("status");
  let es = null, scanId = null, currentModule = "";
  let sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let reportBase = null; // nombre base del reporte (sin extension)
  let allFindings = []; // historico de hallazgos del scan actual (para filtrar/buscar)
  let filterState = { sev: "all", mod: "all", q: "" };

  authCheck.addEventListener("change", () => {
    control.style.opacity = authCheck.checked ? "1" : ".4";
    control.style.pointerEvents = authCheck.checked ? "auto" : "none";
  });

  $("conc").addEventListener("input", (e) => { $("concVal").textContent = e.target.value; });

  function reset() {
    log.innerHTML = ""; findings.innerHTML = "";
    sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    allFindings = []; filterState = { sev: "all", mod: "all", q: "" };
    updateDash(); $("bargraph").innerHTML = "";
    ["dashPanel","graphPanel","progressPanel","aiPanel","logPanel","findPanel","reportPanel","comparePanel"]
      .forEach(id => $(id).style.display = "none");
    $("reconList").innerHTML = ""; $("aiList").innerHTML = "";
    $("chainList").innerHTML = ""; $("diffInfo").innerHTML = "";
    $("cmpA").innerHTML = ""; $("cmpB").innerHTML = ""; $("cmpOut").innerHTML = "";
    reportBase = null;
  }

  function addLog(msg, cls) {
    const d = document.createElement("div");
    d.className = "litem " + (cls || "");
    d.textContent = msg;
    log.appendChild(d);
    log.scrollTop = log.scrollHeight;
  }

  function addFinding(f) {
    const s = (f.severity || "low").toLowerCase();
    sev[s] = (sev[s] || 0) + 1;
    allFindings.push(f);
    updateDash();
    renderFindings();
  }

  function renderFindings() {
    const q = filterState.q.trim().toLowerCase();
    const list = allFindings.filter(f => {
      if (filterState.sev !== "all" && (f.severity || "low").toLowerCase() !== filterState.sev) return false;
      if (filterState.mod !== "all" && (f.module || "") !== filterState.mod) return false;
      if (q) {
        const hay = ((f.detail || "") + " " + (f.module || "") + " " + (f.evidence && JSON.stringify(f.evidence) || "")).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    findings.innerHTML = "";
    if (!list.length) {
      findings.innerHTML = `<div class="fitem info">Sin hallazgos que coincidan con el filtro.</div>`;
      return;
    }
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    list.sort((a, b) => (order[(a.severity || "low").toLowerCase()] || 9) - (order[(b.severity || "low").toLowerCase()] || 9));
    for (const f of list) {
      const s = (f.severity || "low").toLowerCase();
      const conf = f.confidence ? `<span class="conf ${f.confidence}">${f.confidence}</span>` : "";
      const d = document.createElement("div");
      d.className = "fitem " + s;
      d.innerHTML = `<b>[${s.toUpperCase()}] ${escapeHtml(f.module || "")}</b> ${conf}<br>${escapeHtml(f.detail || "")}`;
      findings.appendChild(d);
    }
    $("findCount").textContent = `${list.length} / ${allFindings.length}`;
  }

  function updateDash() {
    $("mCrit").textContent = sev.critical;
    $("mHigh").textContent = sev.high;
    $("mMed").textContent = sev.medium;
    $("mLow").textContent = sev.low;
    $("mInfo").textContent = sev.info;
    const total = sev.critical + sev.high + sev.medium + sev.low + sev.info || 1;
    const colors = { critical: "#e74c3c", high: "#e67e22", medium: "#f1c40f", low: "#2ecc71", info: "#3498db" };
    let bars = "";
    for (const k of ["critical", "high", "medium", "low", "info"]) {
      const pct = (sev[k] / total) * 100;
      if (sev[k] > 0)
        bars += `<div class='barrow'><span class='blbl'>${k.toUpperCase()}</span>` +
                `<span class='bval' style='width:${pct}%;background:${colors[k]}'>${sev[k]}</span></div>`;
    }
    $("bargraph").innerHTML = bars;
  }

  function escapeHtml(s) {
    return (s || "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function sendControl(action, module) {
    if (!scanId) return;
    fetch(`/api/control?scan_id=${scanId}&action=${action}` + (module ? `&module=${module}` : ""));
  }

  $("pauseBtn").addEventListener("click", () => {
    const b = $("pauseBtn");
    if (b.dataset.state === "paused") { sendControl("resume"); b.textContent = "⏸ PAUSAR"; b.dataset.state = ""; }
    else { sendControl("pause"); b.textContent = "▶ REANUDAR"; b.dataset.state = "paused"; }
  });
  $("skipBtn").addEventListener("click", () => sendControl("skip", currentModule));
  $("stopBtn").addEventListener("click", () => sendControl("stop"));

  // --- Filtros y busqueda de hallazgos ---
  function bindFilter(id, key) {
    const el = $(id);
    if (!el) return;
    el.addEventListener("input", (e) => {
      filterState[key] = e.target.value || "all";
      renderFindings();
    });
    el.addEventListener("change", (e) => {
      filterState[key] = e.target.value || "all";
      renderFindings();
    });
  }
  bindFilter("fSev", "sev");
  bindFilter("fMod", "mod");
  const fSearch = $("fSearch");
  if (fSearch) fSearch.addEventListener("input", (e) => { filterState.q = e.target.value; renderFindings(); });

  // --- Comparador de escaneos ---
  async function loadScans() {
    try {
      const r = await fetch("/api/scans");
      const data = await r.json();
      const scans = (data.scans || []).slice().reverse(); // mas recientes primero
      const opts = scans.map(s => `<option value="${s.id}">${escapeHtml(s.id)} · ${escapeHtml(s.target)} · ${escapeHtml(s.fecha || "")}</option>`).join("");
      $("cmpA").innerHTML = opts;
      $("cmpB").innerHTML = opts;
      if (scans.length > 1) $("cmpB").selectedIndex = 1;
      if (scanId) { $("cmpA").value = scanId; }
    } catch (e) { $("cmpOut").innerHTML = `<div class="fitem info">Error cargando escaneos: ${escapeHtml(e.message)}</div>`; }
  }
  $("cmpBtn").addEventListener("click", async () => {
    const a = $("cmpA").value, b = $("cmpB").value;
    if (!a || !b) { $("cmpOut").innerHTML = `<div class="fitem info">Elige dos escaneos.</div>`; return; }
    if (a === b) { $("cmpOut").innerHTML = `<div class="fitem info">Elige dos escaneos distintos.</div>`; return; }
    try {
      const r = await fetch(`/api/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
      const d = await r.json();
      let html = `<div class="cmphead">Comparando <code>${escapeHtml(a)}</code> → <code>${escapeHtml(b)}</code></div>`;
      const nuevos = d.nuevos_en_b || [], resueltos = d.ya_no_en_b || [];
      html += `<div class="cmpstat"><span class="badge new">NUEVOS: ${nuevos.length}</span> <span class="badge fixed">RESUELTOS: ${resueltos.length}</span></div>`;
      if (nuevos.length) {
        html += `<div class="cmpsub">🔺 Nuevos en B</div>`;
        for (const f of nuevos) html += `<div class="fitem ${(f.severidad||"low").toLowerCase()}">[${escapeHtml((f.severidad||"").toUpperCase())}] ${escapeHtml(f.modulo||"")} — ${escapeHtml(f.detalle||"")}</div>`;
      }
      if (resueltos.length) {
        html += `<div class="cmpsub">🔻 Ya no en B (resueltos)</div>`;
        for (const f of resueltos) html += `<div class="fitem info">[${escapeHtml((f.severidad||"").toUpperCase())}] ${escapeHtml(f.modulo||"")} — ${escapeHtml(f.detalle||"")}</div>`;
      }
      if (!nuevos.length && !resueltos.length) html += `<div class="fitem info">Sin diferencias entre ambos escaneos.</div>`;
      $("cmpOut").innerHTML = html;
    } catch (e) { $("cmpOut").innerHTML = `<div class="fitem info">Error: ${escapeHtml(e.message)}</div>`; }
  });
  $("cmpOpen").addEventListener("click", () => { loadScans(); $("comparePanel").style.display = "block"; });

  function buildAuthParam() {
    const url = $("authUrl").value.trim();
    if (!url) return "";
    const a = {
      url, user_field: $("authUserField").value || "username",
      pass_field: $("authPassField").value || "password",
      user: $("authUser").value, password: $("authPass").value
    };
    return "&auth=" + encodeURIComponent(JSON.stringify(a));
  }

  async function readFileB64(id) {
    const f = $(id).files[0];
    if (!f) return "";
    return await new Promise(res => {
      const r = new FileReader();
      r.onload = () => res(btoa(unescape(encodeURIComponent(r.result))));
      r.readAsText(f);
    });
  }

  startBtn.addEventListener("click", async () => {
    const target = targetInput.value.trim();
    if (!target) { status.textContent = "pon un objetivo"; return; }
    if (!authCheck.checked) { status.textContent = "marca la autorizacion"; return; }
    reset();
    ["dashPanel","graphPanel","progressPanel","aiPanel","logPanel","findPanel","reportPanel"]
      .forEach(id => $(id).style.display = "block");
    addLog("▶ Iniciando escaneo de " + target, "hi");

    let extra = "";
    const yaml = await readFileB64("yamlFile"); if (yaml) extra += "&templates=" + encodeURIComponent(yaml);
    const pl = await readFileB64("payloadsFile"); if (pl) extra += "&payloads=" + encodeURIComponent(pl);
    const conc = $("conc").value;
    const auth = buildAuthParam();
    const mode = $("modeSel").value;
    const profile = $("profileSel").value;
    const url = `/api/scan?target=${encodeURIComponent(target)}&mode=${mode}&profile=${profile}&concurrency=${conc}${auth}${extra}`;

    es = new EventSource(url);
    es.onmessage = (ev) => {
      let data; try { data = JSON.parse(ev.data); } catch (e) { return; }
      handleEvent(data);
    };
    es.onerror = () => { status.textContent = "conexion cerrada"; es.close(); };
  });

  function handleEvent(ev) {
    switch (ev.type) {
      case "scan_id":
        scanId = ev.scan_id;
        addLog("scan_id: " + scanId, "hi");
        break;
      case "mode":
        addLog("Modo: " + ev.mode, "info");
        break;
      case "module":
        currentModule = ev.name;
        if (ev.status === "running") {
          addLog("▶ " + ev.name + " ...", "run");
        } else {
          addLog("✓ " + ev.name + ": " + (ev.msg || ""), "ok");
        }
        break;
      case "finding":
        addFinding(ev);
        break;
      case "recon":
        if (ev.kind === "crawler") {
          const urls = (ev.data.urls || []).slice(0, 12);
          const apis = ev.data.apis || [];
          let html = "<b>URLs:</b> " + urls.map(u => `<code>${escapeHtml(u)}</code>`).join(" ") + "<br>";
          html += "<b>APIs:</b> " + apis.map(a => `<code>${escapeHtml(a)}</code>`).join(" ");
          const div = document.createElement("div"); div.className = "reconitem"; div.innerHTML = html;
          $("reconList").appendChild(div);
        } else if (ev.kind === "fingerprint") {
          const d = ev.data;
          let html = "<b>Tech:</b> " + (d.tech || []).join(", ") + "<br>";
          if (d.waf && d.waf.length) html += "<b>WAF:</b> " + d.waf.join(", ") + "<br>";
          if (d.cert && d.cert.subject_cn) html += "<b>Cert CN:</b> " + escapeHtml(d.cert.subject_cn) + "<br>";
          const div = document.createElement("div"); div.className = "reconitem"; div.innerHTML = html;
          $("reconList").appendChild(div);
        }
        break;
      case "ai":
        (ev.suggestions || []).forEach(s => {
          const d = document.createElement("div"); d.className = "aiitem";
          d.innerHTML = `<b>${escapeHtml(s.trigger)}</b> → ${escapeHtml(s.advice)}`;
          $("aiList").appendChild(d);
        });
        break;
      case "progress":
        const pct = ev.total ? Math.round((ev.done / ev.total) * 100) : 0;
        $("bar").style.width = pct + "%"; $("barpct").textContent = pct + "%";
        break;
      case "report":
        reportBase = ev.path.replace(/\.pdf$/, "");
        const fmts = ev.formats || ["pdf"];
        let links = "";
        for (const f of fmts) {
          const ext = f === "pdf" ? "pdf" : f;
          links += `<a href="/api/report?scan_id=${scanId}&fmt=${ext}" download>⬇ ${ext.toUpperCase()}</a> `;
        }
        links += `<br><a href="/api/report?scan_id=${scanId}&fmt=burp" download>⬇ BURP (requests)</a>`;
        $("reportLinks").innerHTML = links;
        addLog("📄 Reporte listo: " + (ev.msg || ""), "hi");
        break;
      case "profile":
        addLog(`⚙ Perfil: ${ev.name} (${ev.mode}) — recon: ${ev.recon.join(",")} | ataque: ${ev.attack.join(",")}`, "hi");
        break;
      case "chain":
        (ev.chains || []).forEach(ch => {
          const d = document.createElement("div");
          d.className = "aiitem chain";
          d.innerHTML = `🔗 ${escapeHtml(ch)}`;
          $("chainList").appendChild(d);
        });
        addLog(`🔗 ${ev.chains.length} cadena(s) de ataque detectada(s)`, "warn");
        break;
      case "diff": {
        const dd = ev.data || {};
        if (dd.previo) {
          let html = `📊 vs escaneo previo (<code>${escapeHtml(dd.previo)}</code>, ${escapeHtml(dd.fecha_previo)}): `;
          html += `riesgo ${escapeHtml(dd.riesgo_anterior)} → <b>${escapeHtml(dd.riesgo_actual)}</b>. `;
          html += `Nuevos: ${dd.nuevos.length} | Resueltos: ${dd.resueltos.length}`;
          $("diffInfo").innerHTML = html;
        } else {
          $("diffInfo").innerHTML = `📊 ${escapeHtml(dd.mensaje || "Sin escaneos previos de este objetivo")}`;
        }
        break;
      }
      case "done":
        addLog("✔ " + ev.summary, "ok");
        status.textContent = "escaneo completado";
        break;
      case "error":
        addLog("⚠ " + ev.msg, "warn");
        break;
      case "log":
        addLog(ev.msg, ev.level || "info");
        break;
    }
  }

  window.addEventListener("beforeunload", () => { if (es) es.close(); });
})();
