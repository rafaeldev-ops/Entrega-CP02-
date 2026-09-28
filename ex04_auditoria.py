"""
Exercicio 4 - Transacao com trilha de auditoria (Aulas 2, 3 e 8/A09)
FIAP - Coding for Security - CP02

alterar_nivel(admin_id, alvo_id, novo_nivel):
  - roda numa transacao MySQL; SELECT ... FOR UPDATE trava as duas linhas
    para que ninguem mude os niveis entre a checagem e o UPDATE;
  - so grava se todas as regras passarem, senao faz rollback;
  - TODA tentativa vira um documento em `auditoria` no MongoDB.

Ordem importante: no caminho de sucesso a auditoria e gravada ANTES do
commit. Se o Mongo estiver fora, a alteracao e desfeita -- mudanca de
privilegio sem rastro nao pode acontecer (fail closed).
"""

from datetime import datetime, timezone

from db import conectar_mongo, conectar_mysql

USUARIOS = [(1, "ana", "ana@x.com", 5),
            (2, "bruno", "bruno@x.com", 2),
            (3, "caio", "caio@x.com", 1)]

NIVEL_ADMIN = 5
NIVEIS_VALIDOS = range(1, 10)


class Recusa(Exception):
    """Tentativa barrada por regra de negocio (nao e erro de sistema)."""


def preparar(conn, db):
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios")
    cur.execute("""
        CREATE TABLE usuarios (
            id           INT PRIMARY KEY,
            nome         VARCHAR(50)  NOT NULL,
            email        VARCHAR(100) NOT NULL UNIQUE,
            nivel_acesso TINYINT      NOT NULL
        ) ENGINE=InnoDB""")
    cur.executemany("INSERT INTO usuarios VALUES (%s, %s, %s, %s)", USUARIOS)
    conn.commit()
    cur.close()
    db.auditoria.drop()


def _nivel(cur, uid):
    cur.execute("SELECT nivel_acesso FROM usuarios WHERE id = %s FOR UPDATE",
                (uid,))
    linha = cur.fetchone()
    return linha[0] if linha else None


def alterar_nivel(conn, db, admin_id, alvo_id, novo_nivel):
    registro = {"quem": admin_id, "alvo": alvo_id, "nivel_anterior": None,
                "nivel_novo": novo_nivel, "resultado": None, "motivo": None}
    cur = conn.cursor()
    try:
        conn.start_transaction()
        nivel_admin = _nivel(cur, admin_id)
        nivel_alvo = _nivel(cur, alvo_id)
        registro["nivel_anterior"] = nivel_alvo

        if admin_id == alvo_id:
            raise Recusa("auto-promocao")
        if nivel_admin is None or nivel_admin < NIVEL_ADMIN:
            raise Recusa("admin sem privilegio")
        if nivel_alvo is None:
            raise Recusa("alvo inexistente")
        if novo_nivel not in NIVEIS_VALIDOS or novo_nivel > nivel_admin:
            raise Recusa("nivel fora do permitido")

        cur.execute("UPDATE usuarios SET nivel_acesso = %s WHERE id = %s",
                    (novo_nivel, alvo_id))
        registro.update(resultado="OK", motivo="alteracao aplicada")
        _auditar(db, registro)     # antes do commit: sem rastro, sem mudanca
        conn.commit()
        return "OK", None

    except Recusa as r:
        conn.rollback()
        registro.update(resultado="RECUSADO", motivo=str(r))
        _auditar(db, registro)
        return "RECUSADO", str(r)

    except Exception as e:
        # Erro de sistema (MySQL ou Mongo fora do ar): desfaz e tenta ao menos
        # registrar. Se nem isso der, o log local ainda mostra a excecao.
        conn.rollback()
        registro.update(resultado="ERRO", motivo=type(e).__name__)
        try:
            _auditar(db, registro)
        except Exception:
            pass
        return "ERRO", type(e).__name__
    finally:
        cur.close()


def _auditar(db, registro):
    doc = dict(registro, timestamp=datetime.now(timezone.utc))
    db.auditoria.insert_one(doc)


def nivel_atual(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT nome, nivel_acesso FROM usuarios WHERE id = %s", (uid,))
    linha = cur.fetchone()
    cur.close()
    conn.commit()   # encerra o snapshot de leitura do InnoDB
    return linha


def main():
    conn = conectar_mysql()
    conn.autocommit = False
    db = conectar_mongo()
    preparar(conn, db)

    testes = [(1, 2, 4), (2, 3, 5), (1, 1, 9), (1, 99, 3)]
    for admin, alvo, nivel in testes:
        antes = nivel_atual(conn, alvo)
        resultado, motivo = alterar_nivel(conn, db, admin, alvo, nivel)
        depois = nivel_atual(conn, alvo)
        chamada = f"alterar_nivel({admin}, {alvo}, {nivel})"
        if resultado == "OK":
            print(f"{chamada:<24} -> OK. commit. "
                  f"{depois[0].capitalize()}: {antes[1]} -> {depois[1]}")
        else:
            estado = (f" {depois[0].capitalize()}: {depois[1]}"
                      if depois else "")
            print(f"{chamada:<24} -> {resultado} ({motivo}). rollback.{estado}")

    total = db.auditoria.count_documents({})
    ok = db.auditoria.count_documents({"resultado": "OK"})
    recusas = db.auditoria.count_documents({"resultado": "RECUSADO"})
    print(f"\nTrilha de auditoria ao final: {total} documentos "
          f"({ok} sucesso, {recusas} recusas)")
    print(f'db.auditoria.count_documents({{"resultado":"RECUSADO"}}) -> {recusas}')
    for d in db.auditoria.find({}, {"_id": 0}).sort("timestamp", 1):
        print(f"  quem={d['quem']} alvo={d['alvo']} "
              f"{d['nivel_anterior']}->{d['nivel_novo']} "
              f"{d['resultado']:<8} ({d['motivo']})")
    conn.close()


if __name__ == "__main__":
    main()
