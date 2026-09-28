"""
Exercicio 5 - O ORDER BY que o %s nao protege (Aulas 3, 6, 7 e 8/A05)
FIAP - Coding for Security - CP02

GET /api/eventos?ordenar_por=&ordem=&tamanho=&pagina=

    python ex05_ordenacao.py            # sobe a API em 127.0.0.1:5005
    python ex05_ordenacao.py --testar   # sobe numa thread e roda os testes

Por que LIMIT %s funciona e ORDER BY %s nao:
  LIMIT espera um VALOR, e placeholder serve exatamente para valor: vira LIMIT 5.
  ORDER BY espera um IDENTIFICADOR (nome de coluna); o placeholder vira a
  string 'criado_em', que o MySQL trata como constante e "ordena" por ela --
  nao da erro, simplesmente nao ordena. Identificador nao se parametriza: se
  valida contra uma lista fechada, e o que entra no SQL e o VALOR do mapa,
  nunca o texto do usuario.
"""

import random
import sys
from datetime import datetime, timedelta

import requests
from flask import Flask, jsonify, request

from db import conectar_mysql
from lab import ServidorDeTeste, aplicar_seguranca, conferir

COLUNAS = {"data": "criado_em", "sev": "severidade", "ip": "ip_origem"}
ORDEM = {"asc": "ASC", "desc": "DESC"}
TAMANHO_PADRAO, TAMANHO_MAX = 10, 100
N_EVENTOS = 150

app = Flask(__name__)
log = aplicar_seguranca(app, "ex05")


def preparar():
    conn = conectar_mysql()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS eventos")
    # ENUM ordena pela posicao na lista: ORDER BY severidade DESC traz
    # 'critica' primeiro, e nao em ordem alfabetica.
    cur.execute("""
        CREATE TABLE eventos (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            criado_em  DATETIME    NOT NULL,
            severidade ENUM('baixa','media','alta','critica') NOT NULL,
            ip_origem  VARCHAR(45) NOT NULL,
            tipo       VARCHAR(30) NOT NULL
        ) ENGINE=InnoDB""")
    rng = random.Random(42)
    agora = datetime.now().replace(microsecond=0)
    cur.executemany(
        "INSERT INTO eventos (criado_em, severidade, ip_origem, tipo) "
        "VALUES (%s, %s, %s, %s)",
        [(agora - timedelta(minutes=rng.randint(0, 1440)),
          rng.choice(["baixa", "media", "alta", "critica"]),
          f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 254)}",
          rng.choice(["BRUTE_FORCE", "PORT_SCAN", "XSS", "SQLI"]))
         for _ in range(N_EVENTOS)])
    conn.commit()
    conn.close()


def _inteiro(valor):
    try:
        return int(valor)
    except (TypeError, ValueError):
        return None


def erro(msg, status=400):
    return jsonify({"erro": msg}), status


@app.get("/api/eventos")
def listar_eventos():
    args = request.args
    coluna = COLUNAS.get(args.get("ordenar_por", "data"))
    if coluna is None:
        log.warning("ordenacao rejeitada: %r", args.get("ordenar_por"))
        return erro("campo de ordenação inválido")
    direcao = ORDEM.get(args.get("ordem", "desc").lower())
    if direcao is None:
        return erro("ordem deve ser asc ou desc")
    tamanho = _inteiro(args.get("tamanho", TAMANHO_PADRAO))
    if tamanho is None:
        return erro("tamanho deve ser inteiro")
    pagina = _inteiro(args.get("pagina", 1))
    if pagina is None:
        return erro("pagina deve ser inteiro")
    if tamanho < 1 or pagina < 1:
        return erro("tamanho e pagina devem ser maiores que zero")
    tamanho = min(tamanho, TAMANHO_MAX)   # teto do servidor, nao do cliente

    # `coluna` e `direcao` vem do mapa fechado, nunca do request; LIMIT e
    # OFFSET vao como parametro. id no desempate deixa a paginacao estavel.
    sql = (f"SELECT id, criado_em, severidade, ip_origem, tipo FROM eventos "
           f"ORDER BY {coluna} {direcao}, id {direcao} LIMIT %s OFFSET %s")
    conn = conectar_mysql()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, (tamanho, (pagina - 1) * tamanho))
        eventos = cur.fetchall()
        cur.execute("SELECT COUNT(*) AS n FROM eventos")
        total = cur.fetchone()["n"]
    finally:
        conn.close()
    for e in eventos:
        e["criado_em"] = e["criado_em"].isoformat()
    return jsonify({"pagina": pagina, "tamanho": tamanho, "total": total,
                    "eventos": eventos})


def demonstrar_placeholder():
    """Prova pratica: ORDER BY %s nao ordena, LIMIT %s limita."""
    conn = conectar_mysql()
    cur = conn.cursor()
    cur.execute("SELECT ip_origem FROM eventos ORDER BY %s LIMIT %s",
                ("ip_origem", 5))
    com_placeholder = [r[0] for r in cur.fetchall()]
    print("Demonstracao do placeholder no ORDER BY:")
    print(f"  ORDER BY %s ('ip_origem') LIMIT %s (5) -> {com_placeholder}")
    print(f"  ordenado? {com_placeholder == sorted(com_placeholder)}  "
          f"| limitou a 5? {len(com_placeholder) == 5}")
    print("  O SQL real foi: " + cur.statement)
    conn.close()


def testar():
    preparar()
    demonstrar_placeholder()
    print("\nTestes com o servidor no ar:")
    ok = []
    with ServidorDeTeste(app) as base:
        url = f"{base}/api/eventos"

        r = requests.get(url, params={"ordenar_por": "sev", "ordem": "desc",
                                      "tamanho": 5})
        sevs = [e["severidade"] for e in r.json()["eventos"]]
        ordem_enum = ["baixa", "media", "alta", "critica"]
        ordenado = sevs == sorted(sevs, key=ordem_enum.index, reverse=True)
        ok.append(conferir("ordenar_por=sev&ordem=desc&tamanho=5",
                           (r.status_code, len(sevs), ordenado), (200, 5, True)))
        print(f"          severidades: {sevs}")

        # requests codifica o '+' literal; na URL original ele e um espaco.
        r = requests.get(f"{url}?ordenar_por=criado_em,(SELECT+1)&ordem=asc")
        ok.append(conferir("ordenar_por=criado_em,(SELECT+1)&ordem=asc",
                           (r.status_code, r.json()),
                           (400, {"erro": "campo de ordenação inválido"})))

        r = requests.get(url, params={"tamanho": "abc"})
        ok.append(conferir("tamanho=abc", (r.status_code, r.json()),
                           (400, {"erro": "tamanho deve ser inteiro"})))

        r = requests.get(url, params={"tamanho": 100000})
        n = len(r.json()["eventos"])
        ok.append(conferir("tamanho=100000 (teto do servidor)",
                           (r.status_code, n), (200, TAMANHO_MAX)))

        r = requests.get(url, params={"ordem": "desc; DROP TABLE eventos"})
        ok.append(conferir("ordem=desc; DROP TABLE eventos",
                           r.status_code, 400))

        r = requests.get(url, params={"tamanho": 5, "pagina": 2})
        ok.append(conferir("paginacao: tamanho=5&pagina=2",
                           (r.status_code, len(r.json()["eventos"])), (200, 5)))

        r = requests.get(url, params={"ordenar_por": "sev"})
        ok.append(conferir("headers: Content-Security-Policy presente",
                           "Content-Security-Policy" in r.headers, True))
    print(f"\n{sum(ok)}/{len(ok)} testes passaram.")
    return all(ok)


if __name__ == "__main__":
    if "--testar" in sys.argv:
        sys.exit(0 if testar() else 1)
    preparar()
    app.run(host="127.0.0.1", port=5005, debug=False)
