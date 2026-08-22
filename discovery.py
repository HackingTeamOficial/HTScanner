#!/usr/bin/env python3
"""discovery.py - Descubrimiento de archivos y backups sensibles.
Wordlist ampliada estilo Gobuster/ffuf (archivos, config, backups, fuentes).
"""
import threading

FILE_WORDLIST = [
    # config / secretos
    ".env", ".env.local", ".env.production", ".env.example", ".env.backup",
    ".git/config", ".git/HEAD", ".svn/entries", ".hg/store/data",
    "config.php", "config.inc.php", "configuration.php", "config.json",
    "wp-config.php", "configuration.php~", "config.bak",
    # backups / dumps
    "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql",
    "dump.sql", "sitebackup.zip", "www.zip", "wwwroot.zip", "root.zip",
    "admin.zip", "sql.zip", "old.zip", "2023.zip", "2024.zip", "2025.zip",
    # fuentes / manifiestos
    "composer.lock", "package.json", "package-lock.json", "yarn.lock",
    "bower.json", "Gemfile", "pom.xml", "build.gradle", "go.mod",
    "requirements.txt", "pipfile", ".npmrc", ".yarnrc",
    # info expuesta
    "phpinfo.php", "info.php", "test.php", "debug.php", "adminer.php",
    "robots.txt", "sitemap.xml", "sitemap_index.xml", ".well-known/security.txt",
    ".well-known/ai.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    # paneles / admin
    "admin/", "admin/login.php", "administrator/", "login/", "wp-admin/",
    "phpmyadmin/", "pma/", "cpanel/", "webadmin/", "manager/", "panel/",
    "dashboard/", "console/", "debug/", "test/", "dev/", "staging/", "beta/",
    # nubes / storage
    ".aws/credentials", ".s3cfg", ".bash_history", ".ssh/id_rsa",
    "elasticsearch.yaml", "kibana.yml", ".foreverignore",
    # logs
    "error.log", "access.log", "debug.log", "wp-content/debug.log",
    # docker / ci
    "Dockerfile", ".env.docker", "docker-compose.yml", ".gitlab-ci.yml",
    ".travis.yml", "Jenkinsfile", "web.config", ".htaccess", ".htpasswd",
]


def discover(ctx, extensions=("", ".bak", ".old", ".sql", "~", ".txt", ".zip")):
    """Devuelve lista de archivos encontrados (code 200/403) como hallazgos."""
    target = ctx.target
    found = []
    sem = threading.Semaphore(ctx.concurrency * 3)

    def probe(entry):
        with sem:
            if ctx.ctrl("archivos") in ("stop", "skip"):
                return
            for ext in extensions:
                if ctx.ctrl("archivos") in ("stop", "skip"):
                    break
                path = entry + ext
                url = target.rstrip("/") + "/" + path.lstrip("/")
                try:
                    rr = ctx.req("GET", url, timeout=6)
                except Exception:
                    continue
                if rr.get("code") in (200, 403) and rr.get("err") is None:
                    sev = "medium" if rr.get("code") == 200 else "low"
                    msg = f"{path} accesible (HTTP {rr.get('code')})"
                    found.append((path, rr.get("code"), sev, msg))
                    ctx.emit({"type": "finding", "severity": sev, "module": "archivos",
                              "detail": msg, "evidence": {"url": url}})

    threads = []
    for entry in FILE_WORDLIST:
        if ctx.ctrl("archivos") in ("stop", "skip"):
            break
        t = threading.Thread(target=probe, args=(entry,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=120)
    return found
