/* app.js - HT Scanner GUI
Maneja el SSE del backend, dashboard en tiempo real, crawler/recon,
sugerencias IA y descarga de reportes en multiples formatos.
*/
(function () {
  const $ = (id) => document.getElementById(id);
  const startBtn = $("startBtn"), targetInput = $("target"), authCheck = $("authCheck");
  const control = $("control"), log = $("log"), findings = $("findings");
  const status = $("status");
  let es = null, scanId = null, currentModule = "";
  let completedModules = 0, totalModules = 0;
  let sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let reportBase = null;
  let allFindings = [];
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
    completedModules = 0; totalModules = 0;
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
      d.className = `fitem ${s}`;
      const mod = escapeHtml(f.module || "");
      const det = escapeHtml(f.detail || "");
      const ev = f.evidence || {};
      let evHtml = "";
      if (ev.url || ev.param || ev.method || ev.type) {
        evHtml = `<div class="finding-evidence">
          ${ev.url ? `<div><b>URL:</b> <code>${escapeHtml(ev.url)}</code></div>` : ""}
          ${ev.param ? `<div><b>Parámetro:</b> ${escapeHtml(ev.param)}</div>` : ""}
          ${ev.method ? `<div><b>Método:</b> ${escapeHtml(ev.method)}</div>` : ""}
          ${ev.type ? `<div><b>Tipo:</b> ${escapeHtml(ev.type)}</div>` : ""}
          ${ev.confidence ? `<div><b>Confidence:</b> ${escapeHtml(ev.confidence)}</div>` : ""}
          ${ev.detail ? `<div><b>Evidence:</b> ${escapeHtml(ev.detail)}</div>` : ""}
          ${ev.template ? `<div><b>Template/rule:</b> ${escapeHtml(ev.template)}</div>` : ""}
          ${ev.request ? `<div><b>Request de verificación:</b> <code>${escapeHtml(ev.request)}</code></div>` : ""}
        </div>`;
      }
      d.innerHTML = `<b>[${s.toUpperCase()}] ${conf} ${mod}</b><br>${det}${evHtml}`;
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
    const colors = { critical: "#cc0000", high: "#b58900", medium: "#d4a017", low: "#0a7d00", info: "#0066cc" };
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
    return (s || "").replace(/[&<>"']/g, function(c) {
      return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
    });
  }

  function sendControl(action, module) {
    if (!scanId) return;
    fetch(`/api/control?scan_id=${scanId}&action=${action}` + (module ? `&module=${module}` : ""));
  }

  $("pauseBtn").addEventListener("click", () => {
    const b = $("pauseBtn");
    if (b.dataset.state === "paused") { sendControl("resume"); b.textContent = "PAUSAR"; b.dataset.state = ""; }
    else { sendControl("pause"); b.textContent = "REANUDAR"; b.dataset.state = "paused"; }
  });
  $("skipBtn").addEventListener("click", () => sendControl("skip", currentModule));
  $("stopBtn").addEventListener("click", () => sendControl("stop"));

  // === Medidor OOKLA (gauge circular animado) ===
  const GAUGE_CIRC = 2 * Math.PI * 86;
  const gaugeArc = $("gaugeArc");
  if (gaugeArc) { gaugeArc.style.strokeDasharray = GAUGE_CIRC; gaugeArc.style.strokeDashoffset = GAUGE_CIRC; }
  let ooklaTarget = 0, ooklaShown = 0, ooklaRAF = null;
  let ooklaReqStart = 0, ooklaReqCount = 0;
  function ooklaSetTarget(pct) { ooklaTarget = Math.max(0, Math.min(100, pct)); }
  function ooklaTick() {
    const diff = ooklaTarget - ooklaShown;
    if (Math.abs(diff) < 0.05) ooklaShown = ooklaTarget;
    else ooklaShown += diff * 0.18;
    const off = GAUGE_CIRC * (1 - ooklaShown / 100);
    if (gaugeArc) gaugeArc.style.strokeDashoffset = off;
    const pctTxt = Math.round(ooklaShown) + "%";
    const pctEl = $("ooklaPct"); if (pctEl) pctEl.textContent = pctTxt;
    const bp = $("barpct"); if (bp) bp.textContent = pctTxt;
    const bw = $("bar"); if (bw) bw.style.width = ooklaShown + "%";
    const spd = $("ooklaSpd");
    if (spd) { const dt = (Date.now() - ooklaReqStart) / 1000; spd.textContent = dt > 0 ? (ooklaReqCount / dt).toFixed(1) : "0.0"; }
    if (ooklaShown < 100 && ooklaTarget < 100) ooklaRAF = requestAnimationFrame(ooklaTick);
    else ooklaRAF = null;
  }
  function ooklaStart(sub) { ooklaTarget = 0; ooklaShown = 0; ooklaReqStart = Date.now(); ooklaReqCount = 0;
    const s = $("ooklaSub"); if (s) s.textContent = sub || "analizando…"; if (!ooklaRAF) ooklaRAF = requestAnimationFrame(ooklaTick); }
  function ooklaDone() { ooklaTarget = 100; ooklaShown = 100; if (gaugeArc) gaugeArc.style.strokeDashoffset = 0;
    const pctEl = $("ooklaPct"); if (pctEl) pctEl.textContent = "100%";
    const s = $("ooklaSub"); if (s) s.textContent = "completado"; const bw = $("bar"); if (bw) bw.style.width = "100%";
    const bp = $("barpct"); if (bp) bp.textContent = "100%"; }
  function ooklaCountReq() { ooklaReqCount++; }

  function bindFilter(id, key) {
    const el = $(id);
    if (!el) return;
    el.addEventListener("input", (e) => { filterState[key] = e.target.value || "all"; renderFindings(); });
    el.addEventListener("change", (e) => { filterState[key] = e.target.value || "all"; renderFindings(); });
  }
  bindFilter("fSev", "sev");
  bindFilter("fMod", "mod");
  const fSearch = $("fSearch");
  if (fSearch) fSearch.addEventListener("input", (e) => { filterState.q = e.target.value; renderFindings(); });

  async function readFileB64(id) {
    const f = $(id).files[0];
    if (!f) return "";
    return await new Promise(res => {
      const r = new FileReader();
      r.onload = () => res(btoa(unescape(encodeURIComponent(r.result))));
      r.readAsText(f);
    });
  }

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

  // --- Notificaciones Telegram (solo estado; config se hace con telegram_setup.py) ---
  const tgEnable = $("tgEnable"), tgStatus = $("tgStatus");
  async function tgRefreshStatus() {
    try {
      const r = await fetch("/api/telegram");
      const d = await r.json();
      if (d.configured) {
        tgStatus.textContent = "Estado: configurado" + (d.two_factor ? " (2FA activo)" : "");
        tgStatus.style.color = "#0a7d00";
      } else {
        tgStatus.textContent = "Estado: sin configurar (usa python3 telegram_setup.py)";
        tgStatus.style.color = "#b58900";
      }
    } catch (e) {
      tgStatus.textContent = "Estado: no disponible";
    }
  }
  tgRefreshStatus();

  startBtn.addEventListener("click", async () => {
    const target = targetInput.value.trim();
    if (!target) { status.textContent = "pon un objetivo"; return; }
    if (!authCheck.checked) { status.textContent = "marca la autorizacion"; return; }
    reset();
    ["dashPanel","graphPanel","progressPanel","aiPanel","logPanel","findPanel","reportPanel"]
      .forEach(id => $(id).style.display = "block");
    addLog("Iniciando escaneo de " + target, "hi");
    ooklaStart("analizando objetivo…");
    $("ooklaMod").textContent = "0"; $("ooklaFnd").textContent = "0";

    let extra = "";
    try {
      const yaml = await readFileB64("yamlFile"); if (yaml) extra += "&templates=" + encodeURIComponent(yaml);
      const pl = await readFileB64("payloadsFile"); if (pl) extra += "&payloads=" + encodeURIComponent(pl);
    } catch (e) { /* sin archivos opcionales */ }

    const conc = $("conc").value;
    const auth = buildAuthParam();
    const mode = $("modeSel").value;
    const profile = $("profileSel").value;

    let telegram = "";
    if (tgEnable.checked) { telegram = "&telegram=1"; }

    const url = `/api/scan?target=${encodeURIComponent(target)}&mode=${mode}&profile=${profile}&concurrency=${conc}${auth}${extra}${telegram}`;
    status.textContent = "escaneando...";

    es = new EventSource(url);
    es.onmessage = (ev) => {
      let data; try { data = JSON.parse(ev.data); } catch (e) { return; }
      handleEvent(data);
    };
    es.onerror = () => { status.textContent = "conexion cerrada"; if (es) es.close(); };
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
          addLog("> " + ev.name + " ...", "run");
          $("ooklaCurrent").innerHTML = "módulo: <b>" + escapeHtml(ev.name) + "</b>";
          ooklaCountReq();
        } else {
          addLog("OK " + ev.name + ": " + (ev.msg || ""), "ok");
        }
        break;
      case "finding":
        addFinding(ev);
        $("ooklaFnd").textContent = allFindings.length;
        break;
      case "recon":
        if (ev.kind === "crawler") {
          const urls = (ev.data.urls || []).slice(0, 12);
          const apis = ev.data.apis || [];
          let html = "<b>URLs:</b> " + urls.map(u => `<code>${escapeHtml(u)}</code>`).join(" ") + "<br>";
          html += "<b>APIs:</b> " + apis.map(a => `<code>${escapeHtml(a)}</code>`).join("");
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
      case "progress": {
        completedModules = Number(ev.done || 0);
        totalModules = Number(ev.total || 0);
        const pct = totalModules ? Math.round((completedModules / totalModules) * 100) : 0;
        ooklaSetTarget(pct);
        $("ooklaMod").textContent = completedModules + (totalModules ? "/" + totalModules : "");
        if (!ooklaRAF) ooklaRAF = requestAnimationFrame(ooklaTick);
        break;
      }
      case "progress_tick": {
        if (totalModules > 0 && completedModules < totalModules) {
          const basePct = (completedModules / totalModules) * 100;
          const cell = 100 / totalModules;
          const sub = Math.min(cell * 0.95, (ev.n % 30) / 30 * cell * 0.95);
          const p = Math.min(99.4, basePct + sub);
          ooklaSetTarget(p);
          if (!ooklaRAF) ooklaRAF = requestAnimationFrame(ooklaTick);
        }
        break;
      }
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
        addLog("Reporte listo: " + (ev.msg || ""), "hi");
        break;
      case "profile":
        addLog(`Perfil: ${ev.name} (${ev.mode}) — recon: ${ev.recon.join(",")} | ataque: ${ev.attack.join(",")}`, "hi");
        break;
      case "chain":
        (ev.chains || []).forEach(ch => {
          const d = document.createElement("div"); d.className = "aiitem chain";
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
        ooklaDone();
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

/* ---- Panel de dispositivos ---- */
function refreshDevices() {
  fetch('/api/devices').then(r => r.json()).then(data => {
    const body = document.getElementById('devicesBody');
    if (!body) return;
    const list = (data && data.devices) || [];
    body.innerHTML = '';
    for (const d of list) {
      const tr = document.createElement('tr');
      const state = (d.state || 'unknown').toLowerCase();
      const cls = state === 'active' ? 'active' : (state === 'offline' ? 'offline' : 'unknown');
      const cap = (typeof d.capacity_percent === 'number') ? d.capacity_percent + '%' : '—';
      tr.innerHTML = `<td>${escapeHtml(d.hostname || d.installation_id || '—')}</td>
        <td>${escapeHtml(d.os || '—')}</td>
        <td><span class="dev-badge ${cls}">${state}</span></td>
        <td>${escapeHtml(d.last_seen || '—')}</td>
        <td>${escapeHtml(cap)}</td>`;
      body.appendChild(tr);
    }
  }).catch(() => {});
}
if (document.getElementById('devicesPanel')) {
  refreshDevices();
  setInterval(refreshDevices, 3000);
}
