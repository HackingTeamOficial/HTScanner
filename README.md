<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_51_40" src="https://github.com/user-attachments/assets/a275a840-7b6e-40cf-bdf5-e25e1497f5ad" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_52_03" src="https://github.com/user-attachments/assets/12fcbeba-2cf8-4fa4-86d6-6ab29c8704fb" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_52_27" src="https://github.com/user-attachments/assets/0b88f2ca-d4b2-4620-a327-220fe676886d" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_52_44" src="https://github.com/user-attachments/assets/e4220f68-31bc-461b-939e-76c2017c9476" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_53_06" src="https://github.com/user-attachments/assets/7a46c516-c500-4ee0-9d8b-46f9c66e9530" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_53_17" src="https://github.com/user-attachments/assets/28a128b0-3ab5-4182-994c-36cdb80a0855" />
<img width="1920" height="1080" alt="Screenshot_2026-07-28_03_53_26" src="https://github.com/user-attachments/assets/c9ae6511-c413-4367-95eb-77cc17c3484d" />


# ⚡ HT Scanner — hacking team

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

🚀 Puesta en marcha (local)

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


🧩 Módulos (13)

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

Sobre RFI y XXE (detección OOB)
RFI y XXE se confirman con un **servidor de callback local** que el scanner
levanta durante el escaneo. Si el objetivo intenta cargar el recurso externo
(`http://127.0.0.1:<puerto>/<token>`), el scanner lo confirma como hallazgo
real. Esto evita falsos positivos: solo reporta si el servidor *de verdad*
intentó la conexión. Estos dos módulos añaden ~2.5 s por endpoint probado.

🎯 Lista de payloads (`.txt`)

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

🔘 Modo activo / pasivo

- ⚡ **ACTIVO** (por defecto): ejecuta todos los módulos, incluyendo el envío de
  payloads de ataque (SQLi / XSS / IDOR / LFI / TRAVERSAL / RFI / RCE / XXE).
- 👁 **PASIVO**: solo hace recon de superficie (headers, archivos, rutas,
  tecnología) **sin enviar payloads**. Ideal para una primera pasada sigilosa
  o contra objetivos sensibles.

🎮 Controles en vivo

Debajo del objetivo hay 3 botones mientras escanea:

- **⏸ PAUSAR / ▶ REANUDAR** — congela y retoma el escaneo.
- **⏭ SALTAR** — salta el módulo que se está ejecutando ahora.
- **⏹ DETENER** — aborta el escaneo completo.

📄 Plantillas YAML (estilo Nuclei)

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

🖥️ Interfaz

- **Mapa de recon**: grafo SVG con nodo central **HACKING TEAM** y los módulos alrededor.
- **Barra de progreso** en tiempo real + nodos que se iluminan al escanear.
- **Log de actividad** estilo terminal (efecto máquina escribiendo en el estado).
- **Panel de hallazgos** por severidad (HIGH / MEDIUM / LOW / CRITICAL).
- **Controles** de pausa / salto / detención en vivo.

📦 Estructura del proyecto

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
````

✅ Probado contra el demo (lab autorizado)

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

🔧 Ampliable

Cada módulo es una función dentro de `scan_target()` en `server.py`. Para añadir
uno nuevo: agrégalo a la lista `mods` y emite eventos con
`emit({"type": "finding", ...})`. El control de pausa/salto/stop usa un
diccionario `SCANS` por `scan_id`. RFI/XXE usan `start_oob()` / `wait_oob()`
para el callback local.

📜 Licencia y responsabilidad

Proyecto educativo de la comunidad **hacking team**. Al usarlo, aceptas hacerlo
única y exclusivamente con autorización. Los autores no se hacen responsables
del uso indebido.
