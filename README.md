# ⚡ HT Scanner — hacking team

Scanner de recon y vulnerabilidades con **interfaz gráfica web** estilo neón.
Busca de forma REAL (no fake): cabeceras, archivos sensibles, rutas, **SQLi**,
**IDOR**, **XSS**, detección de tecnología y **plantillas YAML tipo Nuclei**.

> ⚠️ **SOLO para fines educativos / CTF local.** Úsalo únicamente contra sistemas
> propios o con **autorización explícita por escrito**. El uso no autorizado es ilegal.
> La propia GUI exige marcar el checkbox de autorización antes de escanear.

---

## 🚀 Puesta en marcha (local)

```bash
pip install pyyaml        # solo si quieres el modulo Nuclei/YAML
cd ht_scanner
python3 server.py          # servidor de la herramienta (puerto 8777)
python3 demo_target.py     # lab vulnerable de prueba (puerto 9090) - OPCIONAL
```

Abre en el navegador: **http://127.0.0.1:8777/index.html**

Escribe el objetivo (ej. `http://127.0.0.1:9090` o tu dominio autorizado),
marca la autorización y pulsa **▶ INICIAR SCAN**.

---

## 🧩 Módulos

| Módulo | Qué busca |
|---|---|
| HEADERS | HSTS, CSP, X-Frame-Options faltantes |
| ARCHIVOS | `.git/config`, `robots.txt`, `wp-config.php`, etc. expuestos |
| RUTAS | Enumeración de endpoints comunes (`/admin`, `/login`, `/api`...) |
| SQLi | Inyección SQL en parámetros GET (error-based + diferencial) |
| IDOR | Enumeración de objetos por `id` sin control de acceso |
| XSS | XSS reflejado en parámetros GET |
| TECH | Detección de server, CMS y frameworks (WordPress, Next.js, Laravel...) |
| NUCLEI | Ejecuta tus **plantillas YAML** (formato compatible con Nuclei) |

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
- **Panel de hallazgos** por severidad (HIGH / MEDIUM / LOW).
- **Controles** de pausa / salto / detención en vivo.

---

## 📦 Para tu web (sección Herramientas de hacking team)

Esta carpeta es autocontenida (Python stdlib + `pyyaml` opcional). Para publicarla:

1. **Opción A — Alojarla en tu propio servidor/VPS:**
   - Sube la carpeta `ht_scanner/` a tu VPS.
   - Ejecuta `python3 server.py` (usa `nohup` o `screen` para dejarlo fijo).
   - Apunta un subdominio (ej. `tools.hackingteamoficcial.uk`) al puerto 8777.
   - ⚠️ Nunca expongas el scanner a Internet sin autenticación.

2. **Opción B — Descargable:** pon `ht_scanner.zip` en tu sección "Herramientas".

### Estructura
```
ht_scanner/
├── server.py        # backend (motor de escaneo + SSE + control + YAML)
├── index.html       # interfaz
├── style.css        # tema neón hacking team
├── app.js           # lógica frontend (grafo, progreso, log, control, YAML)
├── demo_target.py   # lab vulnerable para probar (autorizado)
├── launch.sh        # arranque en un comando
└── README.md
```

---

## ✅ Probado contra el demo
El escaneo de prueba detectó de verdad:
- SQLi HIGH en `/notes?id=`
- XSS HIGH en `/search?q=`
- `.git/config`, `robots.txt`, `api/` expuestos
- `/admin`, `/login`, `/api` accesibles
- IDOR en `id=1`
- Cabeceras HSTS/CSP/X-Frame-Options faltantes
- Tecnología: Apache + Next.js
- Plantilla YAML Nuclei detectó `.git/config` expuesto

---

## 🔧 Ampliable
Cada módulo es una función en `server.py` (`scan_target`). Para añadir uno nuevo
basta con agregarlo a la lista `mods` y emitir eventos con `emit({"type": "finding", ...})`.
El control de pausa/salto/stop usa un diccionario `SCANS` por `scan_id`.
