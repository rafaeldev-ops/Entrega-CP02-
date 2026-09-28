"""
Exercicio 8 - Modelo de ML servido por API, com metricas auditaveis
(Aulas 2, 4, 6 e 7) - FIAP - Coding for Security - CP02

POST /api/triagem          {"features": [falhas_login, portas_distintas,
                                         bytes_saida, hora_do_dia]}
GET  /api/modelo/metricas  precisao, recall, F1 e matriz do conjunto de teste

Entrada de modelo e entrada de usuario: e validada como qualquer outra
(quantidade, tipo, faixa). Toda previsao valida vai para `previsoes` no
MongoDB com entrada, saida, confianca, versao do modelo e timestamp, para
que o modelo possa ser auditado depois (A09/A08).

    python ex08_ml_api.py            # treina e sobe em 127.0.0.1:5008
    python ex08_ml_api.py --testar   # treina, sobe numa thread e testa
"""

import hashlib
import math
import sys
from datetime import datetime, timezone

import numpy as np
import requests
from flask import Flask, jsonify, request
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (confusion_matrix, f1_score, precision_score,
                             recall_score)
from sklearn.model_selection import train_test_split

from db import conectar_mongo
from lab import ServidorDeTeste, aplicar_seguranca, conferir

SEED = 42
FEATURES = ["falhas_login", "portas_distintas", "bytes_saida", "hora_do_dia"]
# Limites de sanidade: fora disso nao e trafego plausivel, e dado forjado.
LIMITES = [(0, 10_000), (0, 65_535), (0, 10**12), (0, 23)]
CLASSES = ["baixo", "alto"]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024   # corpo gigante nem e lido
log = aplicar_seguranca(app, "ex08")


# ---------------------------------------------------------------------------
# Treino
# ---------------------------------------------------------------------------
def gerar_dataset(n=1200, rng=np.random.RandomState(SEED)):
    """Trafego sintetico com sobreposicao entre as classes (nao e trivial)."""
    n_alto = int(n * 0.3)
    n_baixo = n - n_alto
    baixo = np.column_stack([
        rng.poisson(1.5, n_baixo),
        rng.randint(1, 7, n_baixo),
        rng.lognormal(8.5, 1.3, n_baixo),                # ~5 KB, cauda longa
        rng.choice(np.r_[7:20, 0:24], n_baixo),          # horario comercial
    ])
    alto = np.column_stack([
        rng.poisson(5.0, n_alto),
        rng.randint(2, 14, n_alto),
        rng.lognormal(10.0, 1.4, n_alto),                # ~22 KB
        rng.choice(np.r_[0:7, 0:24], n_alto),            # madrugada
    ])
    X = np.vstack([baixo, alto]).astype(float)
    y = np.array(["baixo"] * n_baixo + ["alto"] * n_alto)
    # 3% de rotulos trocados: analista humano tambem erra a classificacao.
    trocar = rng.rand(n) < 0.03
    y[trocar] = np.where(y[trocar] == "alto", "baixo", "alto")
    return X, y


def treinar():
    X, y = gerar_dataset()
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=SEED)
    modelo = RandomForestClassifier(n_estimators=200, random_state=SEED)
    modelo.fit(X_tr, y_tr)
    pred = modelo.predict(X_te)
    metricas = {
        "precisao": round(precision_score(y_te, pred, pos_label="alto"), 2),
        "recall": round(recall_score(y_te, pred, pos_label="alto"), 2),
        "f1": round(f1_score(y_te, pred, pos_label="alto"), 2),
        # linhas = real, colunas = previsto, na ordem [baixo, alto]
        "matriz": confusion_matrix(y_te, pred, labels=CLASSES).tolist(),
        "classe_positiva": "alto",
        "amostras_teste": int(len(y_te)),
        "aviso": ("A acuracia foi omitida de proposito: com 70% de trafego "
                  "benigno, um modelo que nunca alerta ja acerta 70%; o que "
                  "importa num SOC e quantos ataques escaparam (recall) e "
                  "quantos alarmes sao falsos (precisao)."),
    }
    # Impressao digital do modelo: se alguem trocar o treino, a versao muda
    # e as previsoes antigas continuam rastreaveis a versao que as gerou.
    versao = hashlib.sha256(X_tr.tobytes() + y_tr.tobytes()).hexdigest()[:12]
    return modelo, metricas, versao


MODELO, METRICAS, VERSAO = treinar()


# ---------------------------------------------------------------------------
# Validacao
# ---------------------------------------------------------------------------
def validar(corpo):
    """Devolve (features, None) ou (None, mensagem_de_erro)."""
    if not isinstance(corpo, dict) or "features" not in corpo:
        return None, "corpo JSON com o campo 'features' é obrigatório"
    f = corpo["features"]
    if not isinstance(f, list):
        return None, "features deve ser uma lista"
    if len(f) != len(FEATURES):
        return None, f"esperadas {len(FEATURES)} features, recebidas {len(f)}"
    # bool e subclasse de int em Python: True passaria como 1 sem esta checagem.
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool)
               for v in f):
        return None, "features devem ser numéricas"
    # O json do Python aceita NaN e Infinity; o modelo nao deveria.
    if not all(math.isfinite(v) for v in f):
        return None, "features devem ser números finitos"
    for nome, v, (lo, hi) in zip(FEATURES, f, LIMITES):
        if not lo <= v <= hi:
            return None, f"{nome} fora da faixa [{lo}, {hi}]"
    return [float(v) for v in f], None


@app.post("/api/triagem")
def triagem():
    features, msg = validar(request.get_json(silent=True))
    if msg:
        log.warning("entrada rejeitada de %s: %s", request.remote_addr, msg)
        return jsonify({"erro": msg}), 400

    proba = MODELO.predict_proba([features])[0]
    idx = int(np.argmax(proba))
    risco, confianca = str(MODELO.classes_[idx]), round(float(proba[idx]), 2)

    conectar_mongo().previsoes.insert_one({
        "entrada": dict(zip(FEATURES, features)),
        "risco": risco,
        "confianca": confianca,
        "modelo_versao": VERSAO,
        "ip_cliente": request.remote_addr,
        "timestamp": datetime.now(timezone.utc),
    })
    return jsonify({"risco": risco, "confianca": confianca})


@app.get("/api/modelo/metricas")
def metricas():
    return jsonify(dict(METRICAS, modelo_versao=VERSAO))


def testar():
    col = conectar_mongo().previsoes
    col.drop()
    ok = []
    with ServidorDeTeste(app) as base:
        url = f"{base}/api/triagem"
        casos = [
            ({"features": [12, 7, 90000, 3]}, 200, "alto"),
            ({"features": [0, 1, 1200, 14]}, 200, "baixo"),
            ({"features": [12, 7, 90000]}, 400,
             {"erro": "esperadas 4 features, recebidas 3"}),
            ({"features": ["12", "sete", 0, 3]}, 400,
             {"erro": "features devem ser numéricas"}),
            (None, 400, None),                                   # sem corpo
            ({"features": [True, 1, 1200, 14]}, 400, None),     # bool
            ({"features": [1, 1, 1200, 99]}, 400, None),        # hora 99
        ]
        for corpo, status, esperado in casos:
            r = (requests.post(url, json=corpo) if corpo is not None
                 else requests.post(url))
            j = r.json()
            if status == 200:
                ok.append(conferir(f"POST {corpo}", (r.status_code, j["risco"]),
                                   (200, esperado)))
                print(f"          confianca = {j['confianca']}")
            else:
                obtido = (r.status_code, j) if esperado else r.status_code
                alvo = (400, esperado) if esperado else 400
                ok.append(conferir(f"POST {corpo if corpo else '(sem corpo)'}",
                                   obtido, alvo))
                if not esperado:
                    print(f"          {j}")

        r = requests.get(f"{base}/api/modelo/metricas")
        m = r.json()
        ok.append(conferir("GET /api/modelo/metricas", r.status_code, 200))
        print(f"          precisao={m['precisao']} recall={m['recall']} "
              f"f1={m['f1']} matriz={m['matriz']}")
        print(f"          aviso: {m['aviso']}")
        ok.append(conferir("resposta NAO traz acuracia",
                           "acuracia" in m or "accuracy" in m, False))

    ok.append(conferir("db.previsoes.count_documents({}) (so as validas)",
                       col.count_documents({}), 2))
    print(f"\n{sum(ok)}/{len(ok)} testes passaram.")
    return all(ok)


if __name__ == "__main__":
    if "--testar" in sys.argv:
        sys.exit(0 if testar() else 1)
    app.run(host="127.0.0.1", port=5008, debug=False)
