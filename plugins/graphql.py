#!/usr/bin/env python3
"""Plugin GraphQL: detecta endpoints y prueba introspection (fuga de esquema)."""
import json


def run(ctx):
    target = ctx.target
    hits = []
    endpoints = ["/graphql", "/api/graphql", "/graphql/v1", "/query", "/gql"]
    introspection_q = {
        "query": "{__schema{types{name fields{name}}}}"
    }
    for ep in endpoints:
        url = target.rstrip("/") + ep
        # GET probe
        g = ctx.req("GET", url)
        if g.get("code") == 200 and ("graphql" in (g.get("body", "").lower()) or "query" in g.get("body", "").lower()):
            hits.append(ep + " (GET 200)")
            ctx.emit({"type": "finding", "severity": "info", "module": "graphql",
                      "detail": f"Posible endpoint GraphQL en {url} (HTTP 200)", "evidence": {"url": url}})
            continue
        # POST introspection
        try:
            import urllib.request
            from server import UA, SSL_CTX
            req = urllib.request.Request(url, data=json.dumps(introspection_q).encode(),
                                         headers={"User-Agent": UA, "Content-Type": "application/json"},
                                         method="POST")
            resp = urllib.request.urlopen(req, timeout=8, context=SSL_CTX)
            rb = resp.read().decode("utf-8", "replace")
            if "__schema" in rb or "types" in rb:
                hits.append(ep + " (introspection ON)")
                ctx.emit({"type": "finding", "severity": "medium", "module": "graphql",
                          "detail": f"GraphQL introspection HABILITADA en {url} (fuga de esquema completo)",
                          "evidence": {"url": url}})
        except Exception:
            pass
    ctx.emit({"type": "module", "name": "graphql", "status": "done",
              "msg": f"GraphQL: {len(hits)} hallazgo(s)", "findings": hits})
