<img width="1920" height="1080" alt="Screenshot_2026-07-28_21_26_35" src="https://github.com/user-attachments/assets/6ec961c9-6183-417b-a8e8-a737ba4f3e17" />
# ⚡ HT Scanner — hacking team 1.0

Plataforma de **reconocimiento y evaluación de seguridad web** con interfaz
gráfica web estilo neón, hecha por y para la comunidad **hacking team**.

Busca de forma **REAL** (no simulada) y reúne toda la información en un único
informe, en la línea de herramientas modernas como **Katana + Httpx + Nuclei**
o **Web-Check**: cabeceras, fingerprinting, crawler, descubrimiento de archivos,
extracción de secretos, y detección de vulnerabilidades
(**SQLi**, **IDOR**, **XSS**, **LFI**, **Path Traversal**, **RFI**, **RCE**, **XXE**,
**CORS**, **JWT**, **GraphQL**, **CSRF**).

Todo hallazgo lleva **`confidence: confirmed | sospechoso`** para separar lo
que se verificó de verdad (petición real) de lo que es solo heurística.

> ⚠️ **SOLO para fines educativos / CTF / laboratorios locales.**
> Úsalo únicamente contra sistemas propios o con **autorización explícita por
> escrito**. El escaneo no autorizado contra sistemas de terceros es ilegal.
> La propia GUI exige marcar el checkbox de autorización antes de escanear.

---

## 🚀 Puesta en marcha (local)

```bash
pip install pyyaml          # solo si quieres el módulo Nuclei/YAML
cd ht_scanner
python3 server.py            # servidor de la herramienta (puerto 8777)
python3 demo_target.py      # lab vulnerable de prueba (puerto 9090) - OPCIONAL
```

Abre en el navegador: **http://127.0.0.1:8777/index.html**

Escribe el objetivo (ej. `http://127.0.0.1:9090` o tu dominio autorizado),
marca la autorización y pulsa **▶ INICIAR SCAN**.

---

## 🧩 Capacidades (roadmap completo)

### 🔌 Sistema de Plugins
Cualquier archivo `.py` en `plugins/` con `PLUGIN_NAME` y `run(ctx)` se carga
**automáticamente** al arrancar. Incluidos: `sqli`, `idor`, `xss`, `lfi`,
`rce`, `cors`, `jwt`, `graphql`, `csrf`. Añade el tuyo sin tocar el core.

### 🕷️ Crawler profundo
Descubre enlaces, formularios **GET/POST**, parámetros y **endpoints embebidos
en archivos JS** (incluidos bundles de SPAs React/Vue/Angular, analizados de
forma estática). Sigue **redirecciones 3xx**, extrae **rutas de router SPA**
(React Router/Vue `<Route path>`), **imports de otros bundles .js** y llamadas
`fetch`/`axios`/`$.post`. Detecta APIs REST/GraphQL/swagger. Toda la superficie
descubierta alimenta automáticamente a los plugins de ataque.

### 🔎 Fingerprinting avanzado (estilo WhatWeb/Wappalyzer)
Detecta servidor, versiones (**Apache, Nginx, PHP, Laravel, jQuery, WordPress,
React, Next.js, Vercel, Netlify…**), **WAF/CDN** (Cloudflare, Akamai,
Imperva…), CMS, frameworks y **librerías JS vulnerables** (moment <2.29.2,
lodash <4.17.21, handlebars, marked, dompurify…). Además: **TLS/certificados,
DNS, HTTP/2, HTTP/3** y cabeceras de seguridad (HSTS, CSP, X-Frame, cookies).
Las reglas viven en `signatures/tech.json` (tech/cloud/admin_panels/js_libs).

### 📂 Descubrimiento de archivos
Wordlist ampliada: `.env`, `.git`, `composer.lock`, `package.json`, backups
(`.zip`, `.sql`), `robots.txt`, `security.txt`, `wp-config.php`, paneles, etc.

### 🔑 Analizador de JavaScript
Extrae **secretos** de los `.js`: AWS keys, Google Maps, Firebase, Stripe,
Twilio, JWT, private keys y tokens genéricos.

### 🛡️ Detección de APIs
Encuentra `/api`, `/graphql` (con prueba de **introspection**), `/swagger`,
`/openapi.json`, `/redoc`.

### ⚡ Concurrencia
Los módulos se ejecutan en **hilos paralelos** (semaforo configurable vía slider
de concurrencia). Un escaneo completo de 17 módulos tarda **~5-7s** en local.

### 🔐 Sesión / Auth
Soporte opcional de **login** (POST a URL con credenciales) para escanear
aplicaciones detrás de autenticación; la cookie de sesión se reutiliza.

### 🎯 Priorización + Correlación + IA local
Los hallazgos se **ordenan por riesgo** (CRITICAL→INFO) y se **correlacionan**
(ej. XSS + cookie sin HttpOnly ⇒ robo de sesión; LFI/XXE + RCE ⇒ compromiso
total). Un motor de reglas local (sin API externa) **sugiere siguientes pasos**
según la tecnología y los hallazgos (estilo "IA").

### 🤖 Dashboard tipo SOC
Contadores en tiempo real por severidad con gráfico de barras, mapa de recon
y panel de sugerencias.

### 🎚 Perfiles de escaneo
Selecciona el conjunto de módulos sin tocar el código:
`full`, `recon`, `passive`, `bugbounty`, `api`, `cms`, `wordpress`.
Cada perfil define recon + ataque + modo. El frontend tiene un selector.

### 🧾 Sistema de firmas (JSON)
Las detecciones de tecnología/cloud/paneles/librerías JS viven en
`signatures/tech.json` (reglas `header`/`body`/`url`/`js`). Añadir una
detección = editar un JSON, sin tocar Python. `signatures/findings.json`
tiene reglas de hallazgos (ej. "Laravel Debug", "CORS wildcard").

### 🔗 Grafo de correlación (cadenas de ataque)
`risk.attack_chains()` cruza módulos en un grafo y levanta cadenas como
**JWT → API admin → CORS → CSRF = toma de control**, o
**LFI/XXE → RCE = compromiso total**. Se muestran en el panel de análisis.

### 🎯 Confirmacion real (reducir falsos positivos)
Cada hallazgo lleva `confidence`:
- **`confirmed`** — se verificó con una petición real: CORS (envía `Origin`
  externo y comprueba la respuesta), CSRF (reenvía el POST sin token y mira si
  el servidor lo acepta), XSS (la carga se refleja sin escapar), JWT
  (`alg=none` aceptado por el endpoint), Traversal/LFI/RCE (firma de éxito).
- **`sospechoso`** — solo heurística (paneles expuestos, librerías JS
  vulnerables, fingerprints por cabecera). Útil para priorizar revisión manual
  sin disparar falsas alertas críticas.

Los informes (JSON/Markdown/HTML/Nuclei/Burp) muestran la confianza para que
sepas qué hallazgos son sólidos.

### 📊 Historial y comparación (SQLite)
Cada escaneo se persiste en `ht_scanner.db` (objetivo, fecha, tecnologías,
hallazgos, duración). La API `/api/scans` lista el historial y el evento
`diff` compara con el escaneo previo del **mismo objetivo** (nuevos/resueltos).

### 🎛 Filtros y búsqueda en hallazgos
En el panel de hallazgos puedes filtrar por **severidad** (critical→info) y
por **módulo**, y **buscar texto** en cualquier hallazgo (detalle, módulo o
evidencia). Cada hallazgo muestra su `confidence` (confirmed/sospechoso).

### 🔬 Comparador visual de escaneos
Botón **COMPARAR** en el panel de hallazgos: elige dos escaneos guardados
(A/B) y el dashboard resalta los **nuevos** (en rojo) y los **resueltos**
(en verde), usando `GET /api/compare?a=<id>&b=<id>`. Ideal para ver la
evolución tras un arreglo.

### 🔌 API REST de lectura
- `GET /api/scans` — lista de escaneos guardados (`{"scans":[...]}`).
- `GET /api/scan/<id>` — detalle (hallazgos, techs, duración).
- `GET /api/compare?a=<id>&b=<id>` — diferencias entre dos escaneos.

---

## 🎮 Controles en vivo

Debajo del objetivo hay 3 botones mientras escanea:

- **⏸ PAUSAR / ▶ REANUDAR** — congela y continúa el escaneo.
- **⏭ SALTAR** — salta el módulo actual (responde al instante).
- **⏹ DETENER** — aborta el escaneo.


## 🧱 Arquitectura desacoplada (core/)

HTScanner v2 separa el **núcleo** del **servidor** y del **frontend**. Nada en
`core/` importa `server.py`; los módulos nunca se llaman entre sí, solo pasan
por la capa de red común.

```
core/
  http.py        -> request(): unica funcion de red (todos usan esta)
  control.py      -> ControlStore: estado de escaneos (pause/skip/stop)
  oob.py          -> servidor Out-Of-Band (RFI/XXE) por scan_id
  eventbus.py     -> EventBus pub/sub (scanner/plugins/GUI/API/logs)
  plugin.py       -> Plugin + PluginManager (carga dinamica)
  context.py      -> ScanContext (une http/oob/control/eventbus)
  db.py           -> persistencia SQLite (comparar escaneos)

server.py  -> solo HTTP server + API + SSE (delega en core/)
engine.py  -> fachada: re-exporta core.* + confirmadores + run_modules
plugins/   -> 10 modulos cargados por PluginManager (copiar = anadir)
```

Flujo: `HTTP server -> API -> EventBus + Context -> PluginManager -> Plugins -> EventBus -> GUI/API/DB/logs`.

La base de datos SQLite guarda objetivo, fecha, tecnologías, hallazgos y riesgo,
permitiendo **comparar escaneos** (estado, nuevo vs viejo).

---

## 📁 Estructura

```
ht_scanner/
├── server.py        # HTTP server + API SSE (delega en core/)
├── engine.py        # fachada: re-exporta core.* + confirmadores + run_modules
├── core/            # nucleo DESACOPLADO (no importa server.py)
│   ├── http.py      # capa de red unica
│   ├── control.py   # estado de escaneos (pause/skip/stop)
│   ├── oob.py       # servidor Out-Of-Band (RFI/XXE)
│   ├── eventbus.py  # bus de eventos pub/sub
│   ├── plugin.py    # Plugin + PluginManager (carga dinamica)
│   ├── context.py   # ScanContext
│   └── db.py        # persistencia SQLite (comparar escaneos)
├── crawler.py       # crawler de reconocimiento
├── fingerprint.py   # fingerprinting + TLS/DNS/headers
├── discovery.py     # descubrimiento de archivos
├── jsecret.py       # analizador de secretos en JS
├── risk.py          # priorización, correlación, sugerencias IA
├── exporters.py     # PDF/JSON/MD/HTML/Nuclei/Burp
├── pdfgen.py        # generador de PDF en stdlib puro
├── plugins/         # 10 módulos cargados por PluginManager
│   ├── sqli.py  idor.py  xss.py  lfi.py  rce.py  traversal.py
│   ├── cors.py  jwt.py  graphql.py  csrf.py
├── demo_target.py   # lab vulnerable autorizado (puerto 9090)
├── index.html  app.js  style.css
└── logo.png         # escudo oficial hacking team
```

Todo en **Python stdlib** (salvo `pyyaml` opcional para Nuclei). Sin `pip install`
obligatorio.

---

## ⚖️ Alcance y honestidad

HT Scanner es una **plataforma de reconocimiento y detección** de nivel intermedio
orientada a acelerar el recon inicial y encontrar vulnerabilidades comunes en
apps pequeñas/medianas, labs y formación. No sustituye el análisis manual ni
herramientas de referencia (Burp Suite Pro, sqlmap, Amass) en auditorías
profesionales o bug bounty de gran escala, pero su arquitectura de plugins,
concurrencia, crawler y reportes lo hacen una base sólida y extensible.

La versión headless (ejecutar JS de SPAs en Chromium) y la integración con
subfinder/Amass/Wayback quedan como **hooks opcionales** (se usan si los binarios
están instalados; si no, hay fallback en stdlib).
