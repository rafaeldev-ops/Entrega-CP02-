# ===== app_vulneravel.py — laboratório apenas =====
import os
import sys
from pathlib import Path

from flask import Flask, request, jsonify
import mysql.connector

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db import MYSQL_CFG, carregar_env  # noqa: E402  [LAB]

carregar_env()

app = Flask(__name__)
# [LAB] O original so passa debug=True em app.run(). Marcamos aqui tambem para
# que o exploit.py, ao servir este modulo numa thread, reproduza o MESMO
# comportamento (debugger do Werkzeug -> traceback com o nome da tabela no
# corpo da resposta). Nao corrige nada: e a propria falha [4]/A05.
app.debug = True
SENHA_MESTRA = "Cyber@2024"  # falha original do enunciado (ver auditoria.md)


def db():
    return mysql.connector.connect(host=MYSQL_CFG["host"],           # [LAB]
                                   port=MYSQL_CFG["port"],
                                   user=MYSQL_CFG["user"],
                                   password=os.environ["MYSQL_PASSWORD"],
                                   database="seguranca")

@app.route("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")
    con = db(); cur = con.cursor(dictionary=True)  # [LAB] guarda a conexao
    cur.execute(f"SELECT * FROM usuarios WHERE nome LIKE '%{nome}%'")
    return jsonify(cur.fetchall())

@app.route("/perfil")
def perfil():
    return f"<h1>Bem-vindo, {request.args.get('u','')}</h1>"

@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    con = db(); cur = con.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = %s", (uid,))
    con.commit()
    return jsonify({"removido": uid})

@app.route("/api/relatorio")
def relatorio():
    con = db(); cur = con.cursor()  # [LAB] guarda a conexao (senao o GC a solta)
    cur.execute("SELECT * FROM tabela_inexistente")
    return jsonify(cur.fetchall())

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1",                            # [LAB]
            port=int(os.getenv("PORTA", "5010")))
