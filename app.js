// ht_scanner frontend - hacking team
const authCheck = document.getElementById('authCheck');
const control = document.getElementById('control');
const targetInput = document.getElementById('target');
const startBtn = document.getElementById('startBtn');
const yamlFile = document.getElementById('yamlFile');
const payloadsFile = document.getElementById('payloadsFile');
const modeSel = document.getElementById('modeSel');
const pauseBtn = document.getElementById('pauseBtn');
const skipBtn = document.getElementById('skipBtn');
const stopBtn = document.getElementById('stopBtn');
const progressPanel = document.getElementById('progressPanel');
const graphPanel = document.getElementById('graphPanel');
const logPanel = document.getElementById('logPanel');
const findPanel = document.getElementById('findPanel');
const bar = document.getElementById('bar');
const barpct = document.getElementById('barpct');
const nodes = document.getElementById('nodes');
const log = document.getElementById('log');
const findings = document.getElementById('findings');
const status = document.getElementById('status');

const MODS = ["headers","archivos","rutas","sqli","idor","xss","lfi","traversal","rfi","rce","xxe","tech","nuclei"];
const MOD_ICONS = { headers:'🛡', archivos:'📁', rutas:'🗺', sqli:'💉', idor:'🔓', xss:'🔥', lfi:'📂', traversal:'📂', rfi:'🌐', rce:'💀', xxe:'📜', tech:'🔎', nuclei:'🧬' };
const MOD_LABEL = { headers:'HEADERS', archivos:'ARCHIVOS', rutas:'RUTAS', sqli:'SQLi', idor:'IDOR', xss:'XSS', lfi:'LFI', traversal:'TRAVERSAL', rfi:'RFI', rce:'RCE', xxe:'XXE', tech:'TECH', nuclei:'NUCLEI' };

let CURRENT_SCAN = null;
let currentModule = null;
let paused = false;

authCheck.addEventListener('change', () => {
  if (authCheck.checked) {
    control.style.opacity = 1; control.style.pointerEvents = 'auto';
    status.textContent = 'autorizado';
  } else {
    control.style.opacity = .4; control.style.pointerEvents = 'none';
    status.textContent = 'pendiente autorizacion';
  }
});

function addLog(msg, cls='') {
  const d = document.createElement('div');
  d.className = 'line ' + cls;
  d.textContent = '> ' + msg;
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}

function setNode(name, state) {
  const el = document.querySelector(`.node[data-m="${name}"]`);
  if (!el) return;
  el.classList.remove('running','done');
  if (state) el.classList.add(state);
}
function setCtrlBtns(enabled) {
  pauseBtn.disabled = !enabled; skipBtn.disabled = !enabled; stopBtn.disabled = !enabled;
}

function buildNodes() {
  const passive = modeSel.value === 'passive';
  nodes.innerHTML = '';
  MODS.forEach(m => {
    const d = document.createElement('div');
    d.className = 'node'; d.dataset.m = m;
    d.innerHTML = `<span class="nicon">${MOD_ICONS[m]}</span>${MOD_LABEL[m]}`;
    if (m === 'nuclei' && !yamlFile.files.length) d.style.display = 'none';
    if (passive && ['sqli','idor','xss'].includes(m)) d.style.display = 'none';
    nodes.appendChild(d);
  });
}

// --- GRAFO SVG ---
function buildGraph() {
  const svg = document.getElementById('graph');
  svg.innerHTML = '';
  const W = 900, cx = W/2, cy = 80, R = 340;
  const c = document.createElementNS('http://www.w3.org/2000/svg','circle');
  c.setAttribute('cx', cx); c.setAttribute('cy', cy); c.setAttribute('r', 28);
  c.setAttribute('class', 'gcenter'); svg.appendChild(c);
  // HACKING TEAM en mayusculas (H y T resaltadas)
  const ct = document.createElementNS('http://www.w3.org/2000/svg','text');
  ct.setAttribute('x', cx); ct.setAttribute('y', cy+4); ct.setAttribute('class','center-label');
  ct.innerHTML = '<tspan fill="#39ff14">H</tspan>ACKING <tspan fill="#39ff14">T</tspan>EAM';
  svg.appendChild(ct);

  const active = MODS.filter(m => !(m === 'nuclei' && !yamlFile.files.length));
  const visible = active.filter(m => !(modeSel.value === 'passive' && ['sqli','idor','xss'].includes(m)));
  const n = visible.length;
  visible.forEach((m, i) => {
    const ang = (Math.PI*2*i/n) - Math.PI/2;
    const x = cx + R*Math.cos(ang);
    const y = cy + R*Math.sin(ang) * 0.62;
    const line = document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1', cx); line.setAttribute('y1', cy);
    line.setAttribute('x2', x); line.setAttribute('y2', y);
    line.setAttribute('class', 'gedge'); line.dataset.m = m;
    svg.appendChild(line);
    const node = document.createElementNS('http://www.w3.org/2000/svg','circle');
    node.setAttribute('cx', x); node.setAttribute('cy', y); node.setAttribute('r', 20);
    node.setAttribute('class', 'gnode'); node.dataset.m = m;
    svg.appendChild(node);
    const t = document.createElementNS('http://www.w3.org/2000/svg','text');
    t.setAttribute('x', x); t.setAttribute('y', y+4); t.setAttribute('class','glabel');
    t.textContent = MOD_LABEL[m]; svg.appendChild(t);
  });
}
function setGraphNode(name, state) {
  const node = document.querySelector(`#graph .gnode[data-m="${name}"]`);
  const edge = document.querySelector(`#graph .gedge[data-m="${name}"]`);
  if (node) { node.classList.remove('running','done'); if (state) node.classList.add(state); }
  if (edge && state) { edge.style.opacity = state === 'done' ? '1' : '.7';
    edge.style.stroke = state === 'done' ? 'var(--neon)' : 'var(--warn)'; }
}

let typeTimer = null;
function typeHeader(text) {
  const el = status;
  if (typeTimer) clearInterval(typeTimer);
  let i = 0; el.textContent = '';
  typeTimer = setInterval(() => {
    el.textContent = text.slice(0, i) + (i < text.length ? '▋' : '');
    if (i++ >= text.length) clearInterval(typeTimer);
  }, 25);
}

// --- control del escaneo ---
function sendControl(action, module) {
  if (!CURRENT_SCAN) return;
  let url = `/api/control?scan_id=${CURRENT_SCAN}&action=${action}`;
  if (module) url += `&module=${module}`;
  fetch(url).catch(()=>{});
}

pauseBtn.addEventListener('click', () => {
  if (paused) {
    sendControl('resume'); pauseBtn.textContent = '⏸ PAUSAR'; paused = false; typeHeader('reanudando...');
  } else {
    sendControl('pause'); pauseBtn.textContent = '▶ REANUDAR'; paused = true; typeHeader('en pausa');
  }
});
skipBtn.addEventListener('click', () => { if (currentModule) sendControl('skip', currentModule); });
stopBtn.addEventListener('click', () => { sendControl('stop'); typeHeader('deteniendo...'); setCtrlBtns(false); });

startBtn.addEventListener('click', () => {
  const target = targetInput.value.trim();
  if (!target) { alert('Escribe un objetivo'); return; }
  if (!authCheck.checked) { alert('Debes confirmar la autorizacion'); return; }

  buildNodes(); buildGraph();
  log.innerHTML = ''; findings.innerHTML = '';
  progressPanel.style.display = 'block';
  graphPanel.style.display = 'block';
  logPanel.style.display = 'block';
  findPanel.style.display = 'block';
  bar.style.width = '0%'; barpct.textContent = '0%';
  setCtrlBtns(true); paused = false; pauseBtn.textContent = '⏸ PAUSAR';
  typeHeader('escaneando...');
  addLog('Iniciando recon de ' + target, 'hi');

  // Enviar YAML (plantilla + payloads) y modo por GET
  const runScan = (templatesParam, payloadsParam) => {
    let url = '/api/scan?target=' + encodeURIComponent(target) +
              '&mode=' + encodeURIComponent(modeSel.value);
    if (templatesParam) url += '&templates=' + encodeURIComponent(templatesParam);
    if (payloadsParam) url += '&payloads=' + encodeURIComponent(payloadsParam);
    const es = new EventSource(url);
    es.onmessage = (e) => { let ev; try { ev = JSON.parse(e.data); } catch { return; } handleEvent(ev); };
    es.addEventListener('end', () => { es.close(); typeHeader('completado ✓'); addLog('=== ESCANEO FINALIZADO ===', 'hi'); setCtrlBtns(false); });
    es.onerror = () => { if (status.textContent.indexOf('completado') === -1) addLog('Conexion cerrada', 'warn'); };
  };

  const readFiles = (cb) => {
    let tpl = null, pay = null, pending = 0;
    const done = () => { if (pending === 0) cb(tpl, pay); };
    if (yamlFile.files.length) {
      pending++;
      const r = new FileReader();
      r.onload = () => { tpl = r.result; pending--; done(); };
      r.readAsText(yamlFile.files[0]);
    }
    if (payloadsFile.files.length) {
      pending++;
      const r = new FileReader();
      r.onload = () => { pay = r.result; pending--; done(); };
      r.readAsText(payloadsFile.files[0]);
    }
    if (pending === 0) done();
  };

  readFiles((tpl, pay) => runScan(tpl, pay));
});

function handleEvent(ev) {
  switch (ev.type) {
    case 'scan_id':
      CURRENT_SCAN = ev.scan_id;
      addLog(`Scan ID: ${ev.scan_id}`, 'warn');
      break;
    case 'start':
      addLog(`Target: ${ev.target} | modulos: ${ev.total}`, 'hi');
      break;
    case 'mode':
      addLog(`Modo: ${ev.mode === 'passive' ? '👁 PASIVO (solo recon)' : '⚡ ACTIVO (con payloads)'}`, 'warn');
      break;
    case 'module':
      currentModule = ev.name;
      if (ev.status === 'running') {
        setNode(ev.name, 'running'); setGraphNode(ev.name, 'running');
        addLog(`[${MOD_LABEL[ev.name]}] ${ev.msg}`, 'warn');
      } else {
        setNode(ev.name, 'done'); setGraphNode(ev.name, 'done');
        addLog(`[${MOD_LABEL[ev.name]}] OK -> ${ev.msg}`, 'hi');
      }
      break;
    case 'progress': {
      const pct = Math.round((ev.done / ev.total) * 100);
      bar.style.width = pct + '%'; barpct.textContent = pct + '%';
      break;
    }
    case 'finding': {
      const d = document.createElement('div');
      d.className = 'fitem ' + (ev.severity || 'low');
      d.innerHTML = `<b>[${ev.severity?.toUpperCase()}] ${ev.module}</b> — ${ev.detail}`;
      findings.appendChild(d);
      addLog(`  ⚠ HALLAZGO (${ev.severity}) ${ev.module}: ${ev.detail}`, 'warn');
      break;
    }
    case 'done':
      addLog(ev.summary, 'hi');
      break;
    case 'error':
      addLog('ERROR: ' + ev.msg, 'warn');
      break;
  }
}
