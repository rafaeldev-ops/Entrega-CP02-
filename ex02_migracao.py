"""
Exercicio 2 - Migracao relacional -> documentos (Aulas 1, 2 e 3)
FIAP - Coding for Security - CP02

MySQL normalizado (ativos 1-N alertas) -> MongoDB com o ativo ANINHADO em
cada alerta. A leitura e feita com JOIN parametrizado, em lotes (keyset
pagination: WHERE al.id > %s LIMIT %s), e a migracao e verificada duas
vezes: por contagem e por conteudo, campo a campo.
"""

from datetime import datetime, timedelta, timezone

from db import conectar_mongo, conectar_mysql

ATIVOS = [(1, "SRV-WEB01", "192.168.1.10", "alta"),
          (2, "PC-RH03", "192.168.1.45", "baixa")]
ALERTAS = [(1, 1, "BRUTE_FORCE", "critica"),
           (2, 1, "PORT_SCAN", "alta"),
           (3, 2, "XSS", "media")]

LOTE = 2   # pequeno de proposito, para exercitar mais de um lote

JOIN = """
SELECT al.id, al.tipo, al.severidade, al.criado_em,
       a.nome, a.ip, a.criticidade
  FROM alertas al
  JOIN ativos a ON a.id = al.ativo_id
 WHERE al.id > %s
 ORDER BY al.id
 LIMIT %s
"""


def preparar_mysql(conn):
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS alertas")
    cur.execute("DROP TABLE IF EXISTS ativos")
    cur.execute("""
        CREATE TABLE ativos (
            id          INT PRIMARY KEY,
            nome        VARCHAR(50) NOT NULL,
            ip          VARCHAR(45) NOT NULL UNIQUE,
            criticidade ENUM('baixa','media','alta') NOT NULL
        ) ENGINE=InnoDB""")
    cur.execute("""
        CREATE TABLE alertas (
            id         INT PRIMARY KEY,
            ativo_id   INT NOT NULL,
            tipo       VARCHAR(30) NOT NULL,
            severidade VARCHAR(10) NOT NULL,
            criado_em  DATETIME NOT NULL,
            FOREIGN KEY (ativo_id) REFERENCES ativos(id)
        ) ENGINE=InnoDB""")
    cur.executemany("INSERT INTO ativos VALUES (%s, %s, %s, %s)", ATIVOS)
    agora = datetime.now().replace(microsecond=0)
    cur.executemany(
        "INSERT INTO alertas VALUES (%s, %s, %s, %s, %s)",
        [(*a, agora - timedelta(minutes=10 * i)) for i, a in enumerate(ALERTAS)],
    )
    conn.commit()
    cur.close()
    print(f"MySQL: {len(ATIVOS)} ativos e {len(ALERTAS)} alertas criados.")


def para_documento(linha):
    alerta_id, tipo, sev, criado_em, nome, ip, crit = linha
    return {
        "mysql_id": alerta_id,           # rastreabilidade ate a origem
        "tipo": tipo,
        "severidade": sev,
        "criado_em": criado_em.replace(tzinfo=timezone.utc),
        "ativo": {"nome": nome, "ip": ip, "criticidade": crit},
    }


def migrar(conn, colecao):
    cur = conn.cursor()
    ultimo_id, total = 0, 0
    while True:
        cur.execute(JOIN, (ultimo_id, LOTE))   # parametrizado
        linhas = cur.fetchall()
        if not linhas:
            break
        colecao.insert_many([para_documento(l) for l in linhas])
        total += len(linhas)
        ultimo_id = linhas[-1][0]
    cur.close()
    return total


def verificar(conn, colecao):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alertas")
    n_mysql = cur.fetchone()[0]
    n_mongo = colecao.count_documents({})

    # Contagem igual nao prova que o conteudo veio certo: compara campo a campo.
    cur.execute(JOIN, (0, n_mysql))
    divergentes = []
    for linha in cur.fetchall():
        esperado = para_documento(linha)
        obtido = colecao.find_one({"mysql_id": esperado["mysql_id"]},
                                  {"_id": 0})
        if obtido != esperado:
            divergentes.append(esperado["mysql_id"])
    cur.close()

    status = ("MIGRACAO INTEGRA" if n_mysql == n_mongo and not divergentes
              else f"MIGRACAO COM DIVERGENCIA (ids {divergentes})")
    print(f"\nMySQL: {n_mysql} alertas | MongoDB: {n_mongo} documentos "
          f"-> {status}")
    print(f"Conferencia campo a campo: {n_mysql - len(divergentes)}/{n_mysql} "
          f"documentos identicos a origem.")
    return not divergentes and n_mysql == n_mongo


def main():
    conn = conectar_mysql()
    db = conectar_mongo()
    colecao = db.alertas
    colecao.drop()   # idempotente

    preparar_mysql(conn)
    n = migrar(conn, colecao)
    print(f"Migrados {n} alertas em lotes de {LOTE} (insert_many por lote).")

    verificar(conn, colecao)

    filtro = {"ativo.criticidade": "alta"}
    n_alta = colecao.count_documents(filtro)
    print(f'\nConsulta sem JOIN: db.alertas.find({{"ativo.criticidade":"alta"}}) '
          f"-> {n_alta} documentos")
    for d in colecao.find(filtro, {"_id": 0, "tipo": 1, "ativo.nome": 1}):
        print(f"  {d['tipo']:<12} em {d['ativo']['nome']}")

    # Demonstra o custo da duplicacao: renomear o ativo toca N documentos.
    r = colecao.update_many({"ativo.ip": "192.168.1.10"},
                            {"$set": {"ativo.nome": "SRV-WEB01-PRD"}})
    print(f"\nRenomear SRV-WEB01 no Mongo: update_many alterou "
          f"{r.modified_count} documentos (no MySQL seria 1 linha).")

    # Ganho: a leitura mais comum do SOC (alerta + contexto do ativo) vira um
    #        unico find, sem JOIN e sem segunda consulta.
    # Perda: o ativo fica copiado em cada alerta; renomear exige update_many e,
    #        se ele falhar no meio, alertas antigos ficam com o nome antigo.

    conn.close()


if __name__ == "__main__":
    main()
