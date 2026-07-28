# ⚡ HT Scanner — hacking team ESTEN Pendientes A Actualizaciones 
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_51_40" src="https://github.com/user-attachments/assets/077b2c6a-9cc3-4ecf-b676-6ccd8f06c70e" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_52_03" src="https://github.com/user-attachments/assets/fb16cad5-3be4-4904-8569-9a7579ba1fc3" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_52_27" src="https://github.com/user-attachments/assets/234d7f57-474b-4c4b-97b9-c4f34a8715a3" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_52_44" src="https://github.com/user-attachments/assets/867a0cc8-9084-4231-b43f-c925976a7e13" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_53_06" src="https://github.com/user-attachments/assets/2a88f5ae-0af1-4d1b-ae25-c88c4759f12f" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_53_17" src="https://github.com/user-attachments/assets/8d0319aa-85da-4087-8455-011d00fd7097" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_53_26" src="https://github.com/user-attachments/assets/eb8ad780-4522-41ee-b086-3e42f1708de9" />




Scanner de recon y vulnerabilidades con **interfaz gráfica web** estilo neón,
hecho por y para la comunidad **hacking team**.

Busca de forma **REAL** (no simulada): cabeceras, archivos sensibles, rutas,
**SQLi**, **IDOR**, **XSS**, **LFI**, **Path Traversal**, **RFI**, **RCE**, **XXE**,
detección de tecnología y **plantillas YAML tipo Nuclei**.

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

> 💡 Atajo: `bash launch.sh` arranca el servidor de la herramienta en un comando.

---

## 🧩 Módulos (13)

| Módulo | Severidad | Qué busca |
|---|---|---|
| 🛡️ HEADERS | — | HSTS, CSP, X-Frame-Options faltantes |
| 📁 ARCHIVOS | — | `.git/config`, `robots.txt`, `wp-config.php`, etc. expuestos |
| 🗺️ RUTAS | — | Enumeración de endpoints comunes (`/admin`, `/login`, `/api`...) |
| 💉 SQLi | HIGH | Inyección SQL en parámetros GET (error-based + diferencial) |
| 🔓 IDOR | MEDIUM | Objetos accesibles por `id` sin control de acceso |
| 🔥 XSS | HIGH | XSS reflejado en parámetros GET |
| 📂 LFI | HIGH | Inclusión de archivos locales (`/etc/passwd`, `php://filter`) |
| 📂 TRAVERSAL | HIGH | Path Traversal (`../../etc/passwd` y variantes codificadas) |
| 🌐 RFI | HIGH | Inclusión remota vía **callback OOB local** |
| 💀 RCE | CRITICAL | Inyección de comandos (`;id`, `$(id)`, `\| whoami`) |
| 📜 XXE | HIGH | XML External Entity vía **callback OOB local** |
| 🔎 TECH | — | Detección de server, CMS y frameworks (WordPress, Next.js, Laravel...) |
| 🧬 NUCLEI | varía | Ejecuta tus **plantillas YAML** (formato compatible con Nuclei) |


## 🎯 Lista de payloads (`.txt`)

Sube un archivo `.txt` con tus payloads personalizadas. Una por línea, con
secciones opcionales para separar por tipo:

```
# Comentarios con #
[SQLi]
'
' OR '1'='1
[XSS]
<script>alert(1)</script>
[IDOR]
1
999
```

## 🔘 Modo activo / pasivo

- ⚡ **ACTIVO** (por defecto): ejecuta todos los módulos, incluyendo el envío de
  payloads de ataque (SQLi / XSS / IDOR / LFI / TRAVERSAL / RFI / RCE / XXE).
- 👁 **PASIVO**: solo hace recon de superficie (headers, archivos, rutas,
  tecnología) **sin enviar payloads**. Ideal para una primera pasada sigilosa
  o contra objetivos sensibles.

---

## 📄 Reporte PDF automático (firmado por hacking team)

Al **terminar cada escaneo**, HT Scanner genera un **reporte PDF profesional**
con el logo oficial de hacking team, que incluye:

- **Portada** con objetivo, fecha, modo y número de hallazgos.
- **Resumen del sistema**: host, servidor, tecnología detectada y puertos.
- **Tabla de vulnerabilidades** por severidad (CRITICAL / HIGH / MEDIUM / LOW) con módulo y detalle.
- **Módulos ejecutados** con su resultado.
- **Firma** de hacking team al final.

El PDF se guarda en `reports/<scan_id>.pdf` y aparece un enlace de descarga
en la interfaz al concluir el escaneo. El generador es **stdlib puro**
(`pdfgen.py`) — no requiere `pip install`.

---

## 🎮 Controles en vivo

Debajo del objetivo hay 3 botones mientras escanea:

- **⏸ PAUSAR / ▶ REANUDAR** — congela y retoma el escaneo.
- **⏭ SALTAR** — salta el módulo que se está ejecutando ahora.
- **⏹ DETENER** — aborta el escaneo completo.

---

## 📄 Plantillas YAML (estilo Nuclei)

Sube un `.yaml` con el botón "Plantilla YAML (Nuclei)" antes de escanear.
Formato simplificado compatible:

```yaml
id: exposed-git-config
severity: high
requests:
  - method: GET
    path: /.git/config
    matchers:
      - type: word
        words: ["repositoryformatversion"]
        part: body
      - type: status
        status: [200]
```

El módulo NUCLEI ejecuta cada plantilla contra el objetivo y reporta
coincidencias como hallazgos.

---

## 🖥️ Interfaz

- **Mapa de recon**: grafo SVG con nodo central **HACKING TEAM** y los módulos alrededor.
- **Barra de progreso** en tiempo real + nodos que se iluminan al escanear.
- **Log de actividad** estilo terminal (efecto máquina escribiendo en el estado).
- **Panel de hallazgos** por severidad (HIGH / MEDIUM / LOW / CRITICAL).
- **Controles** de pausa / salto / detención en vivo.

---

## 📦 Estructura del proyecto

```
ht_scanner/
├── server.py             # backend (motor de escaneo + SSE + control + YAML + OOB)
├── index.html            # interfaz web
├── style.css             # tema neón hacking team
├── app.js                # lógica frontend (grafo, progreso, log, control, YAML)
├── demo_target.py        # lab vulnerable para probar (autorizado, puerto 9090)
├── payloads_example.txt  # ejemplo de lista de payloads (.txt)
├── launch.sh             # arranque en un comando
├── README.md
└── PRESENTACION_HTSCANNER.md  # presentación para la comunidad
```

## ✅ Probado contra el demo (lab autorizado)

El escaneo de prueba detectó de verdad:

- 💉 **SQLi HIGH** en `/notes?id=`
- 🔥 **XSS HIGH** en `/search?q=`
- 📂 **LFI HIGH** en `/file?file=/etc/passwd`
- 📂 **TRAVERSAL HIGH** en `/download?file=../../../../../../etc/passwd`
- 🌐 **RFI HIGH (OOB)** en `/include?url=<callback>`
- 💀 **RCE CRITICAL** en `/ping?host=;id`
- 📜 **XXE HIGH (OOB)** vía entidad externa en `/xml`
- `.git/config`, `robots.txt`, `api/` expuestos
- `/admin`, `/login`, `/api` accesibles
- IDOR en `id=1`
- Cabeceras HSTS/CSP/X-Frame-Options faltantes
- Tecnología: Apache + Next.js
- Plantilla YAML Nuclei detectó `.git/config` expuesto

---

## 🔧 Ampliable

Cada módulo es una función dentro de `scan_target()` en `server.py`. Para añadir
uno nuevo: agrégalo a la lista `mods` y emite eventos con
`emit({"type": "finding", ...})`. El control de pausa/salto/stop usa un
diccionario `SCANS` por `scan_id`. RFI/XXE usan `start_oob()` / `wait_oob()`
para el callback local.

---

## 📜 Licencia y responsabilidad

Proyecto educativo de la comunidad **hacking team**. Al usarlo, aceptas hacerlo
única y exclusivamente con autorización. Los autores no se hacen responsables
del uso indebido.

💻🔥 Somos una comunidad de hacking y ciberseguridad donde aprender es parte del juego 🔥💻

🧑‍💻 Aquí encontrarás gente que está empezando y otros que ya están en nivel avanzado, todos compartiendo herramientas, trucos, metodologías y experiencias reales.

🛠 Desde pentesting hasta OSINT, explotación o defensa, tocamos todo lo necesario para crecer en este mundo.

🎯 Nos gusta aprender haciendo: laboratorios, retos, pruebas reales y colaboración constante.

🧠 Nuestros logotipos representan quiénes somos: una comunidad unida por la curiosidad, el conocimiento y las ganas de romper (y entender) sistemas.

🚀 Si te mola la ciberseguridad y quieres subir de nivel rodeado de gente que está en lo mismo que tú… este es tu sitio.

🌐 Página Web:
https://www.hackingteamoficcial.uk/

💻 GitHub:
https://github.com/HackingTeamOficial

📲 Telegram:
https://t.me/PlantillasNucleiHackingTeam
https://t.me/HackingTeamGrupoOfficial
https://t.me/+0hHSaKO7eI9mNWY8 (Difusión)
https://t.me/+llcmNGzz6JIyMmI0 (Biblioteca)
https://t.me/TermuxHackingTeam

🐦 X (Twitter):
@HackingTeam77

🦋 Bluesky:
https://bsky.app/profile/hackingteam.bsky.social

💬 Discord:
https://discord.gg/V4nPFbQX

📘 Facebook:
https://www.facebook.com/groups/hackingteam2022/?ref=share
https://www.facebook.com/groups/HackingTeamCyber/?ref=share

🎥 YouTube:
https://www.youtube.com/@HackingTeamOficial/videos

🎵 TikTok:
https://www.tiktok.com/@hackingteamprohackers
https://www.tiktok.com/@hacking.kdea?_t=ZS-8vTtlaQrDTL&_r=1
