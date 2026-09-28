"""
Exercicio 6 - Controle de acesso quebrado (Aulas 3, 6 e 8/A01)
FIAP - Coding for Security - CP02

API de incidentes autenticada por X-API-Key, validada no MySQL com query
parametrizada. Regras:
  - cada analista so ve os proprios incidentes (IDOR barrado);
  - so nivel >= 5 apaga, e pode apagar qualquer um.

401 = "nao sei quem voce e"   (sem header, ou chave desconhecida)
403 = "sei quem voce e e voce nao pode"

O 403 nunca revela se o incidente existe: para quem nao e nivel 5, "existe
mas e de outro" e "nao existe" devolvem o MESMO 403, com o mesmo corpo. So
quem ja tem visao total (nivel 5) recebe 404 -- para ele a existencia nao e
segredo, porque ele pode apagar qualquer incidente.

A chave nao e guardada em claro: a coluna api_key armazena o SHA-256 dela.
Se a tabela vazar, as chaves nao vazam junto.

    python ex06_acesso.py            # sobe a API em 127.0.0.1:5006
    python ex06_acesso.py --testar   # sobe numa thread e roda a matriz
"""

import hashlib
import sys

import requests
from flask import Flask, g, jsonify, request

from db import conectar_mysql
from lab import ServidorDeTeste, aplicar_seguranca, conferir

NIVEL_APAGAR = 5

# Dados do enunciado (chaves ficticias de laboratorio; em producao seriam
# geradas com secrets.token_urlsafe e entregues uma unica vez ao analista).
ANALISTAS = [(1, "ana", "key-ana-001", 5), (2, "bruno", "key-bruno-002", 2)]
INCIDENTES = [(1, 1, "Brute force SSH", "critica"),
              (2, 2, "Phishing no RH", "media")]

app = Flask(__name__)
log = aplicar_seguranca(app, "ex06")


def hash_chave(chave):
    return hashlib.sha256(chave.encode()).hexdigest()


def preparar():
    conn = conectar_mysql()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS incidentes")
    cur.execute("DROP TABLE IF EXISTS analistas")
    cur.execute("""
        CREATE TABLE analistas (
            id      INT PRIMARY KEY,
            nome    VARCHAR(50) NOT NULL,
            api_key CHAR(64)    NOT NULL UNIQUE,   -- SHA-256 da chave
            nivel   TINYINT     NOT NULL
        ) ENGINE=InnoDB""")
    cur.execute("""
        CREATE TABLE incidentes (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            dono_id    INT          NOT NULL,
            titulo     VARCHAR(100) NOT NULL,
            severidade VARCHAR(10)  NOT NULL,
            status     VARCHAR(20)  NOT NULL DEFAULT 'aberto',
            FOREIGN KEY (dono_id) REFERENCES analistas(id)
        ) ENGINE=InnoDB""")
    cur.executemany("INSERT INTO analistas VALUES (%s, %s, %s, %s)",
                    [(i, n, hash_chave(k), nv) for i, n, k, nv in ANALISTAS])
    cur.executemany("INSERT INTO incidentes (id, dono_id, titulo, severidade) "
                    "VALUES (%s, %s, %s, %s)", INCIDENTES)
    conn.commit()
    conn.close()


def erro(msg, status):
    return jsonify({"erro": msg}), status


NEGADO = ("acesso negado", 403)   # corpo unico para todo 403


@app.before_request
def autenticar():
    chave = request.headers.get("X-API-Key", "")
    if not chave:
        return erro("credencial ausente", 401)
    g.conn = conectar_mysql()
    cur = g.conn.cursor(dictionary=True)
    cur.execute("SELECT id, nome, nivel FROM analistas WHERE api_key = %s",
                (hash_chave(chave),))
    g.analista = cur.fetchone()
    cur.close()
    if g.analista is None:
        log.warning("chave invalida vinda de %s", request.remote_addr)
        return erro("credencial inválida", 401)


@app.teardown_request
def fechar(_exc):
    conn = g.pop("conn", None)
    if conn is not None:
        conn.close()


@app.get("/api/incidentes")
def listar():
    cur = g.conn.cursor(dictionary=True)
    # O filtro pelo dono esta NA QUERY: nao ha como o resultado conter
    # incidente alheio, mesmo que alguem esqueca um if depois.
    cur.execute("SELECT id, titulo, severidade, status FROM incidentes "
                "WHERE dono_id = %s ORDER BY id", (g.analista["id"],))
    return jsonify(cur.fetchall())


@app.get("/api/incidentes/<int:iid>")
def detalhar(iid):
    cur = g.conn.cursor(dictionary=True)
    cur.execute("SELECT id, dono_id, titulo, severidade, status "
                "FROM incidentes WHERE id = %s", (iid,))
    inc = cur.fetchone()
    if inc and inc["dono_id"] == g.analista["id"]:
        return jsonify(inc)
    if g.analista["nivel"] >= NIVEL_APAGAR and inc is None:
        return erro("incidente não encontrado", 404)
    log.warning("acesso negado: analista %s -> incidente %s",
                g.analista["id"], iid)
    return erro(*NEGADO)


@app.delete("/api/incidentes/<int:iid>")
def apagar(iid):
    # Autorizacao ANTES de consultar: quem nao pode apagar nao descobre nada.
    if g.analista["nivel"] < NIVEL_APAGAR:
        log.warning("delete negado: analista %s (nivel %s) -> incidente %s",
                    g.analista["id"], g.analista["nivel"], iid)
        return erro(*NEGADO)
    cur = g.conn.cursor()
    cur.execute("DELETE FROM incidentes WHERE id = %s", (iid,))
    if cur.rowcount == 0:
        g.conn.rollback()
        return erro("incidente não encontrado", 404)
    g.conn.commit()
    log.info("incidente %s apagado por analista %s", iid, g.analista["id"])
    return jsonify({"removido": iid})


def testar():
    preparar()
    ana, bruno = {"X-API-Key": "key-ana-001"}, {"X-API-Key": "key-bruno-002"}
    matriz = [
        ("GET", "/api/incidentes/1", ana, 200),
        ("GET", "/api/incidentes/1", bruno, 403),       # IDOR barrado
        ("GET", "/api/incidentes/1", {}, 401),
        ("GET", "/api/incidentes/1", {"X-API-Key": "key-inexistente"}, 401),
        ("GET", "/api/incidentes", bruno, 200),
        ("DELETE", "/api/incidentes/2", ana, 200),      # nivel 5
        ("DELETE", "/api/incidentes/1", bruno, 403),
        ("GET", "/api/incidentes/999", ana, 404),
    ]
    ok = []
    print("Matriz de testes (status code):")
    with ServidorDeTeste(app) as base:
        for metodo, rota, headers, esperado in matriz:
            r = requests.request(metodo, base + rota, headers=headers)
            quem = headers.get("X-API-Key", "(sem header)")
            ok.append(conferir(f"{metodo:<6} {rota:<22} {quem}",
                               r.status_code, esperado))
            if rota == "/api/incidentes" and r.ok:
                ids = [i["id"] for i in r.json()]
                ok.append(conferir("  lista do bruno contem so o incidente 2",
                                   ids, [2]))

        # O 403 nao pode distinguir "existe e e alheio" de "nao existe".
        preparar()
        r_alheio = requests.get(f"{base}/api/incidentes/1", headers=bruno)
        r_inexistente = requests.get(f"{base}/api/incidentes/999",
                                     headers=bruno)
        ok.append(conferir(
            "bruno: incidente alheio x inexistente -> respostas identicas",
            (r_alheio.status_code, r_alheio.text) ==
            (r_inexistente.status_code, r_inexistente.text), True))
        print(f"          ambos: {r_alheio.status_code} {r_alheio.json()}")
    print(f"\n{sum(ok)}/{len(ok)} testes passaram.")
    return all(ok)


if __name__ == "__main__":
    if "--testar" in sys.argv:
        sys.exit(0 if testar() else 1)
    preparar()
    app.run(host="127.0.0.1", port=5006, debug=False)
