"""
Exercicio 9 - Rate limiting guiado por anomalia (Aulas 2, 4, 6 e 8/A09)
FIAP - Coding for Security - CP02

1. before_request grava {ip, rota, metodo, timestamp} em `acessos`.
2. after_request completa o registro com o status devolvido.
3. Agregacao por IP (no banco) -> [req_por_minuto, taxa_4xx, rotas_distintas].
4. IsolationForest(contamination=0.2, random_state=42) marca os anomalos.
5. IP anomalo vai para `bloqueados` (TTL de 60 s) e recebe 429 com
   Retry-After: 60 nas proximas requisicoes.

    python ex09_rate_limit.py            # sobe em 127.0.0.1:5009 e reanalisa a cada 30 s
    python ex09_rate_limit.py --testar   # roteiro normal x hostil com requests

Sobre o IP do cliente: o teste simula dois IPs pelo header X-Forwarded-For,
e por isso so no modo --testar o app confia nesse header (ProxyFix). Em
producao so se confia nele atras de um proxy seu; aceitar X-Forwarded-For
de qualquer um deixa o atacante trocar de "IP" a cada requisicao e escapar
do bloqueio.

Risco de bloquear por anomalia em vez de regra fixa: o modelo sempre marca
~20% da populacao como anomala, entao num dia calmo ele bloqueia gente
legitima (falso positivo derruba usuario real); regra fixa erra menos, mas e
facil de contornar ficando logo abaixo do limite.
"""

import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import numpy as np
import requests
from flask import Flask, g, jsonify, request
from sklearn.ensemble import IsolationForest
from werkzeug.middleware.proxy_fix import ProxyFix

from db import conectar_mongo
from lab import ServidorDeTeste, aplicar_seguranca, conferir

JANELA = timedelta(minutes=15)   # comportamento observado na janela recente
BLOQUEIO_S = 60
MIN_IPS = 5                      # com menos que isso nao ha "populacao" para comparar
MIN_SPAN_S = 10                  # evita dividir por ~0 com 1 requisicao so

app = Flask(__name__)
log = aplicar_seguranca(app, "ex09")
db = conectar_mongo()


def preparar_colecoes():
    db.acessos.drop()
    db.bloqueados.drop()
    db.acessos.create_index([("ip", 1), ("timestamp", 1)])
    # TTL de 7 dias no log de acesso e expiracao exata no bloqueio.
    db.acessos.create_index("timestamp", name="ttl_acessos",
                            expireAfterSeconds=7 * 24 * 3600)
    db.bloqueados.create_index("expira_em", expireAfterSeconds=0)
    db.bloqueados.create_index("ip", unique=True)


# ---------------------------------------------------------------------------
# Registro de acessos + bloqueio
# ---------------------------------------------------------------------------
@app.before_request
def registrar_e_barrar():
    agora = datetime.now(timezone.utc)
    g.acesso_id = db.acessos.insert_one({
        "ip": request.remote_addr, "rota": request.path,
        "metodo": request.method, "timestamp": agora,
    }).inserted_id
    # O TTL do Mongo roda a cada ~60 s; por isso a validade e checada aqui.
    if db.bloqueados.find_one({"ip": request.remote_addr,
                               "expira_em": {"$gt": agora}}):
        resp = jsonify({"erro": "muitas requisições"})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(BLOQUEIO_S)
        return resp


@app.after_request
def completar_registro(resp):
    acesso_id = g.pop("acesso_id", None)
    if acesso_id is not None:
        db.acessos.update_one({"_id": acesso_id},
                              {"$set": {"status": resp.status_code}})
    return resp


@app.get("/api/status")
def status():
    return jsonify({"ok": True})


@app.get("/api/eventos")
def eventos():
    return jsonify([{"id": 1, "tipo": "PORT_SCAN"}])


@app.get("/api/ativos")
def ativos():
    return jsonify([{"nome": "SRV-WEB01"}])


# ---------------------------------------------------------------------------
# Analise: agregacao no banco + IsolationForest
# ---------------------------------------------------------------------------
PIPELINE_FEATURES = [
    {"$group": {
        "_id": "$ip",
        "total": {"$sum": 1},
        # 429 nao conta: senao o proprio bloqueio alimentaria a anomalia.
        "n4xx": {"$sum": {"$cond": [{"$and": [
            {"$gte": ["$status", 400]}, {"$lt": ["$status", 500]},
            {"$ne": ["$status", 429]}]}, 1, 0]}},
        "rotas": {"$addToSet": "$rota"},
        "inicio": {"$min": "$timestamp"},
        "fim": {"$max": "$timestamp"},
    }},
    {"$project": {
        "_id": 0, "ip": "$_id",
        "req_por_minuto": {"$divide": ["$total", {"$divide": [
            {"$max": [{"$dateDiff": {"startDate": "$inicio", "endDate": "$fim",
                                     "unit": "millisecond"}},
                      MIN_SPAN_S * 1000]}, 60000]}]},
        "taxa_4xx": {"$divide": ["$n4xx", "$total"]},
        "rotas_distintas": {"$size": "$rotas"},
    }},
    {"$sort": {"ip": 1}},
]


def analisar(verbose=True):
    desde = datetime.now(timezone.utc) - JANELA
    perfis = list(db.acessos.aggregate(
        [{"$match": {"timestamp": {"$gte": desde}, "status": {"$exists": True}}}]
        + PIPELINE_FEATURES))
    if len(perfis) < MIN_IPS:
        return []

    X = np.array([[p["req_por_minuto"], p["taxa_4xx"], p["rotas_distintas"]]
                  for p in perfis])
    modelo = IsolationForest(contamination=0.2, random_state=42).fit(X)
    rotulos = modelo.predict(X)

    if verbose:
        print("=== Analise de acessos ===")
    bloqueados = []
    agora = datetime.now(timezone.utc)
    for p, r in zip(perfis, rotulos):
        anomalo = r == -1
        if verbose:
            print(f"{p['ip']:<15}[{p['req_por_minuto']:6.1f} req/min | "
                  f"4xx {p['taxa_4xx']:.2f} | {p['rotas_distintas']} rotas]  -> "
                  + ("ANOMALIA -> bloqueado" if anomalo else "normal"))
        if anomalo:
            db.bloqueados.update_one(
                {"ip": p["ip"]},
                {"$set": {"motivo": "isolation_forest", "features": p,
                          "bloqueado_em": agora,
                          "expira_em": agora + timedelta(seconds=BLOQUEIO_S)}},
                upsert=True)
            log.warning("IP %s bloqueado por anomalia: %s", p["ip"], p)
            bloqueados.append(p["ip"])
    return bloqueados


def analisar_periodicamente(intervalo=30):
    def laco():
        while True:
            time.sleep(intervalo)
            analisar(verbose=False)
    threading.Thread(target=laco, daemon=True).start()


# ---------------------------------------------------------------------------
# Roteiro de teste
# ---------------------------------------------------------------------------
NORMAL, HOSTIL = "192.168.1.10", "185.220.101.1"
LEGITIMOS_HISTORICO = ["192.168.1.10", "192.168.1.22", "192.168.1.31",
                       "192.168.1.47"]


def semear_historico():
    """Trafego legitimo dos ultimos 10 min, como ja estaria no log.

    O IsolationForest precisa de uma populacao para saber o que e "normal";
    com so dois IPs nao ha com o que comparar.
    """
    agora = datetime.now(timezone.utc)
    rotas = ["/api/status", "/api/eventos", "/api/ativos"]
    docs = []
    for n, ip in enumerate(LEGITIMOS_HISTORICO):
        for k in range(4 + n):
            docs.append({"ip": ip, "rota": rotas[(k + n) % (1 + n % 3)],
                         "metodo": "GET", "status": 200,
                         "timestamp": agora - timedelta(minutes=10 - 2 * k)})
    db.acessos.insert_many(docs)


def testar():
    preparar_colecoes()
    semear_historico()
    # So em laboratorio: confia no X-Forwarded-For para simular IPs.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
    ok = []
    with ServidorDeTeste(app) as base:
        def get(ip, rota):
            return requests.get(base + rota, headers={"X-Forwarded-For": ip})

        print(f"IP normal {NORMAL}: 5 requisicoes validas espacadas")
        st = []
        for rota in ["/api/status", "/api/eventos"] * 2 + ["/api/status"]:
            st.append(get(NORMAL, rota).status_code)
            time.sleep(1)
        ok.append(conferir("  status das 5 requisicoes", st, [200] * 5))

        print(f"IP hostil {HOSTIL}: 60 requisicoes em ~10 s, 40 para rotas "
              f"inexistentes")
        validas = ["/api/status", "/api/eventos", "/api/ativos"]
        inexist = ["/admin", "/.env", "/wp-login.php", "/phpmyadmin",
                   "/api/usuarios", "/backup.zip"]
        roteiro = [validas[i % 3] for i in range(20)] + \
                  [inexist[i % 6] for i in range(40)]
        np.random.RandomState(42).shuffle(roteiro)
        for rota in roteiro:
            get(HOSTIL, rota)
            time.sleep(10 / 60)
        print()

        bloqueados = analisar()
        ok.append(conferir("IPs bloqueados", bloqueados, [HOSTIL]))

        r = get(HOSTIL, "/api/status")
        print(f"Proxima requisicao de {HOSTIL} -> {r.status_code} {r.json()}")
        print(f"{'':<39}Retry-After: {r.headers.get('Retry-After')}")
        ok.append(conferir("  hostil recebe 429 + Retry-After: 60",
                           (r.status_code, r.headers.get("Retry-After")),
                           (429, "60")))
        ok.append(conferir("  normal continua 200",
                           get(NORMAL, "/api/status").status_code, 200))
        total = db.acessos.count_documents({"ip": {"$in": [NORMAL, HOSTIL]},
                                            "status": {"$exists": True}})
        ok.append(conferir("  todas as requisicoes do teste tem status no log",
                           total, db.acessos.count_documents(
                               {"ip": {"$in": [NORMAL, HOSTIL]}})))
    print(f"\n{sum(ok)}/{len(ok)} testes passaram.")
    return all(ok)


if __name__ == "__main__":
    if "--testar" in sys.argv:
        sys.exit(0 if testar() else 1)
    preparar_colecoes()
    analisar_periodicamente()
    app.run(host="127.0.0.1", port=5009, debug=False)
