# ===== app_seguro.py — versao corrigida do app_vulneravel.py (Ex. 10) =====
"""
Exercicio 10 (Desafio) - Antes e depois (Aulas 1 a 8 / OWASP Top 10 2025)
FIAP - Coding for Security - CP02

Mesmas rotas do app_vulneravel.py, mas cada falha catalogada em auditoria.md
foi corrigida. O exploit.py roda identico contra os dois apps: aqui os 6
ataques falham (0 de 6).

O que mudou, ponto a ponto (numeros = ataques do exploit.py):
  [1] SQLi   -> query 100% parametrizada; o payload vira texto procurado.
  [2] XSS    -> markupsafe.escape() antes de ir para o HTML.
  [3] Acesso -> DELETE exige X-API-Key (401) e nivel >= 5 (403).
  [4] Erro   -> handler global de 500 devolve {"erro":"erro interno"} e joga
                o traceback so para o log (aplicar_seguranca, em lab.py).
  [5] Vazam. -> a busca seleciona colunas explicitas; senha/api_key nunca saem.
  [6] Headers-> aplicar_seguranca liga CSP, X-Content-Type-Options, etc.

Ausencias que o enunciado pede (nao existiam no app vulneravel):
  - AUTENTICACAO: nao havia nenhuma; agora ha X-API-Key validada no banco.
  - LOGGING/MONITORAMENTO: nao havia; aplicar_seguranca registra toda
    requisicao e toda tentativa de credencial invalida (A09).

E o resto: sem SENHA_MESTRA fixa no codigo, sem debug=True, escuta so em
127.0.0.1. Credenciais e conexao vem do db.py (senha so do ambiente).

    python app_seguro.py            # sobe em 127.0.0.1:5011
    python app_seguro.py --testar   # sobe numa thread e prova que funciona
                                     # (busca, escape, auth com e sem chave)
"""

import hashlib
import sys
from pathlib import Path

from flask import Flask, g, jsonify, request
from markupsafe import escape

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db import conectar_mysql              # noqa: E402
from lab import ServidorDeTeste, aplicar_seguranca, conferir  # noqa: E402
from lab_dados import semear               # noqa: E402

NIVEL_REMOVER = 5   # so administrador (nivel 5) remove usuarios

app = Flask(__name__)
log = aplicar_seguranca(app, "ex10_seguro")   # headers + log + 500 generico


def hash_chave(chave):
    return hashlib.sha256(chave.encode()).hexdigest()


def erro(msg, status):
    return jsonify({"erro": msg}), status


# --- Autenticacao: so as rotas que MUDAM estado exigem credencial. -----------
# A busca e o perfil sao leitura publica; remover usuario nao e.
def exigir_admin():
    """Devolve None se OK, ou uma resposta de erro (401/403). Popula g.usuario."""
    chave = request.headers.get("X-API-Key", "")
    if not chave:
        return erro("credencial ausente", 401)
    cur = g.conn.cursor(dictionary=True)
    cur.execute("SELECT id, nome, nivel FROM usuarios WHERE api_key = %s",
                (hash_chave(chave),))
    g.usuario = cur.fetchone()
    cur.close()
    if g.usuario is None:
        log.warning("chave invalida vinda de %s", request.remote_addr)
        return erro("credencial invalida", 401)
    if g.usuario["nivel"] < NIVEL_REMOVER:
        log.warning("delete negado: usuario %s (nivel %s)",
                    g.usuario["id"], g.usuario["nivel"])
        return erro("acesso negado", 403)
    return None


@app.before_request
def abrir_conexao():
    g.conn = conectar_mysql()


@app.teardown_request
def fechar_conexao(_exc):
    conn = g.pop("conn", None)
    if conn is not None:
        conn.close()


@app.get("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")
    cur = g.conn.cursor(dictionary=True)
    # [1] Parametrizado: o driver manda o valor separado do SQL, entao aspas
    #     no payload sao dado, nunca codigo. Os curingas do LIKE ficam no
    #     PARAMETRO, nao no texto da query.
    # [5] Colunas explicitas: senha (hash) e api_key nunca saem pela API.
    cur.execute("SELECT id, nome, email, nivel FROM usuarios "
                "WHERE nome LIKE %s ORDER BY id", (f"%{nome}%",))
    return jsonify(cur.fetchall())


@app.get("/perfil")
def perfil():
    # [2] escape() transforma < > " & em entidades HTML: o payload volta como
    #     texto literal na tela, nunca como <script> executavel.
    u = escape(request.args.get("u", ""))
    return f"<h1>Bem-vindo, {u}</h1>"


@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    # [3] Autorizacao ANTES de tocar no banco: sem credencial -> 401;
    #     credencial sem nivel -> 403; so entao remove.
    negado = exigir_admin()
    if negado is not None:
        return negado
    cur = g.conn.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = %s", (uid,))
    if cur.rowcount == 0:
        g.conn.rollback()
        return erro("usuario nao encontrado", 404)
    g.conn.commit()
    log.info("usuario %s removido por %s", uid, g.usuario["id"])
    return jsonify({"removido": uid})


@app.get("/api/relatorio")
def relatorio():
    # [4] O bug continua aqui DE PROPOSITO (consulta tabela inexistente) para
    #     provar a defesa: o handler global de 500 (lab.py) captura a excecao,
    #     manda o traceback e o nome da tabela SO para o log, e devolve ao
    #     cliente apenas {"erro":"erro interno"}. Quem ataca nao aprende nada.
    cur = g.conn.cursor()
    cur.execute("SELECT * FROM tabela_inexistente")
    return jsonify(cur.fetchall())


def testar():
    """Prova que a versao segura CONTINUA FUNCIONANDO (a defesa nao quebrou o
    recurso). Os ataques em si sao provados pelo exploit.py."""
    chaves = semear()                       # recria usuarios; devolve as chaves
    admin = {"X-API-Key": chaves["admin"]}  # nivel 5
    maria = {"X-API-Key": chaves["maria"]}  # nivel 1
    ok = []
    import requests
    with ServidorDeTeste(app) as base:
        r = requests.get(f"{base}/api/usuarios/buscar", params={"nome": "mar"})
        nomes = sorted(u["nome"] for u in r.json())
        ok.append(conferir("busca legitima 'mar' acha maria e marcos",
                           nomes, ["marcos", "maria"]))
        ok.append(conferir("busca nao devolve a coluna senha",
                           any("senha" in u for u in r.json()), False))
        ok.append(conferir("perfil escapa o payload",
                           "&lt;" in requests.get(
                               f"{base}/perfil", params={"u": "<b>x"}).text, True))
        ok.append(conferir("DELETE sem chave -> 401",
                           requests.delete(f"{base}/api/usuarios/3").status_code, 401))
        ok.append(conferir("DELETE com chave nivel 1 -> 403",
                           requests.delete(f"{base}/api/usuarios/3",
                                           headers=maria).status_code, 403))
        ok.append(conferir("DELETE com chave admin -> 200",
                           requests.delete(f"{base}/api/usuarios/3",
                                           headers=admin).status_code, 200))
    print(f"\n{sum(ok)}/{len(ok)} testes passaram.")
    return all(ok)


if __name__ == "__main__":
    if "--testar" in sys.argv:
        sys.exit(0 if testar() else 1)
    semear()
    app.run(host="127.0.0.1", port=5011, debug=False)
