"""
Exercicio 3 - Retencao e janela temporal (Aula 2)
FIAP - Coding for Security - CP02

Colecao `eventos` com indice TTL de 7 dias, 200 eventos espalhados nas
ultimas 24 h (com um pico simulado de forca bruta de madrugada) e a
distribuicao de falhas por hora feita INTEIRA no banco, via agregacao.

A hora e agrupada no fuso de Sao Paulo ($hour com timezone): o Mongo guarda
em UTC, e um SOC que le "pico as 06h" quando o ataque foi as 03h local
investiga a janela errada.
"""

import random
from datetime import datetime, timedelta, timezone

from db import conectar_mongo

FUSO = "America/Sao_Paulo"
SETE_DIAS = 7 * 24 * 3600
TOTAL = 200
HORA_ATAQUE_LOCAL = 3          # pico simulado as 03h de Sao Paulo
UTC_OFFSET_SP = -3             # Sao Paulo nao tem horario de verao desde 2019


def gerar_eventos(agora, rng):
    """200 eventos em 24 h: ruido de fundo + rajada de falhas as 03h local."""
    # Instante da ultima ocorrencia das 03h local dentro das ultimas 24 h.
    local = agora + timedelta(hours=UTC_OFFSET_SP)
    inicio_ataque = local.replace(hour=HORA_ATAQUE_LOCAL, minute=0, second=0,
                                  microsecond=0)
    if inicio_ataque > local:
        inicio_ataque -= timedelta(days=1)
    inicio_ataque -= timedelta(hours=UTC_OFFSET_SP)   # volta para UTC

    ips_ruido = [f"192.168.1.{i}" for i in range(10, 40)]
    eventos = []
    for i in range(TOTAL):
        if i < 60:   # rajada: 60 eventos dentro da hora do ataque, quase todos FAIL
            ts = inicio_ataque + timedelta(seconds=rng.randint(0, 3599))
            tipo = "FAIL" if rng.random() < 0.9 else "OK"
            ip = "185.220.101.1"
        else:        # ruido: qualquer momento das ultimas 24 h
            ts = agora - timedelta(seconds=rng.randint(0, 24 * 3600 - 1))
            tipo = "FAIL" if rng.random() < 0.3 else "OK"
            ip = rng.choice(ips_ruido)
        eventos.append({"timestamp": ts, "tipo": tipo, "ip": ip,
                        "usuario": rng.choice(["root", "admin", "ana", "bruno"])})
    return eventos


def falhas_por_hora(eventos, desde):
    return list(eventos.aggregate([
        {"$match": {"tipo": "FAIL", "timestamp": {"$gte": desde}}},
        {"$group": {"_id": {"$hour": {"date": "$timestamp", "timezone": FUSO}},
                    "total": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]))


def main():
    db = conectar_mongo()
    eventos = db.eventos
    eventos.drop()

    # TTL: o proprio servidor apaga eventos com mais de 7 dias (varredura a
    # cada ~60 s). O campo precisa ser do tipo Date, senao o TTL o ignora.
    eventos.create_index("timestamp", expireAfterSeconds=SETE_DIAS,
                         name="ttl_7_dias")

    agora = datetime.now(timezone.utc)
    eventos.insert_many(gerar_eventos(agora, random.Random(42)))
    print(f"{eventos.count_documents({})} eventos inseridos nas ultimas 24 h.\n")

    linhas = falhas_por_hora(eventos, agora - timedelta(hours=24))
    pico = max(linhas, key=lambda l: l["total"])   # 24 linhas no maximo
    escala = 40 / pico["total"]

    print("=== Falhas por hora (ultimas 24h, horario de Sao Paulo) ===")
    for l in linhas:
        barra = "█" * max(1, round(l["total"] * escala))
        marca = "   <- pico" if l is pico else ""
        print(f"{l['_id']:02d}h | {barra} {l['total']}{marca}")
    print(f"Hora de pico: {pico['_id']:02d}h ({pico['total']} falhas)")

    # Janela curta, como o analista olharia no plantao.
    seis_h = eventos.count_documents(
        {"tipo": "FAIL", "timestamp": {"$gte": agora - timedelta(hours=6)}})
    print(f"Falhas nas ultimas 6 h: {seis_h}")

    ttl = eventos.index_information()["ttl_7_dias"]["expireAfterSeconds"]
    print(f"\nIndice TTL ativo ({ttl} s): eventos com mais de 7 dias serao "
          f"removidos automaticamente.")

    # TTL e seguranca, nao so disco: log guardado para sempre e dado pessoal
    # acumulado (LGPD) e alvo maior num vazamento; retencao definida e o minimo.


if __name__ == "__main__":
    main()
