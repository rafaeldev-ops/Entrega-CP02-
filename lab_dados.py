"""
Popula a tabela `usuarios` usada pelas duas versoes do app do Ex. 10.

Nenhuma senha ou chave fica escrita aqui: sao geradas aleatoriamente a cada
execucao. A coluna `senha` guarda so o hash PBKDF2 (e mesmo assim nao pode
sair na API: hash vazado vira ataque de dicionario offline). A coluna
`api_key` guarda o SHA-256 da chave.
"""

import hashlib
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from db import conectar_mysql  # noqa: E402

USUARIOS = [(1, "admin", "admin@lab.local", 5),
            (2, "maria", "maria@lab.local", 1),
            (3, "marcos", "marcos@lab.local", 1)]


def hash_senha(senha):
    sal = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", senha.encode(), sal, 600_000)
    return f"pbkdf2_sha256$600000${sal.hex()}${dk.hex()}"


def hash_chave(chave):
    return hashlib.sha256(chave.encode()).hexdigest()


def semear():
    """Recria a tabela e devolve {nome: api_key} (em claro, so em memoria)."""
    conn = conectar_mysql()
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios")
    cur.execute("""
        CREATE TABLE usuarios (
            id      INT PRIMARY KEY,
            nome    VARCHAR(50)  NOT NULL,
            email   VARCHAR(100) NOT NULL UNIQUE,
            senha   VARCHAR(200) NOT NULL,
            nivel   TINYINT      NOT NULL,
            api_key CHAR(64)     NOT NULL UNIQUE
        ) ENGINE=InnoDB""")
    chaves = {}
    for uid, nome, email, nivel in USUARIOS:
        chaves[nome] = secrets.token_urlsafe(24)
        cur.execute("INSERT INTO usuarios VALUES (%s, %s, %s, %s, %s, %s)",
                    (uid, nome, email, hash_senha(secrets.token_urlsafe(12)),
                     nivel, hash_chave(chaves[nome])))
    conn.commit()
    conn.close()
    return chaves


if __name__ == "__main__":
    semear()
    print(f"Tabela usuarios recriada com {len(USUARIOS)} usuarios.")
