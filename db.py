"""
Helpers de conexao com tratamento de erro.
FIAP - Coding for Security - CP02

Continuacao do db.py do CP01, com uma mudanca que agora vale nota: NENHUMA
senha tem valor padrao no codigo. No CP01 havia um default "labpass"; aqui a
senha do MySQL vem exclusivamente do ambiente (ou do arquivo .env, que esta
no .gitignore). Sem ela, o programa para com uma mensagem clara -- nunca cai
num default silencioso.

    cp .env.example .env      # e edite a senha
    python db.py              # testa as duas conexoes
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import mysql.connector
from mysql.connector import errorcode
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError

PASTA = Path(__file__).resolve().parent


def carregar_env(caminho=PASTA / ".env"):
    """Le um .env simples (CHAVE=valor) sem sobrescrever o ambiente real.

    Evita depender do python-dotenv so para isso. Variaveis ja exportadas no
    shell tem precedencia -- o .env e so conveniencia local.
    """
    if not caminho.exists():
        return
    for linha in caminho.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        chave, valor = linha.split("=", 1)
        os.environ.setdefault(chave.strip(), valor.strip().strip('"').strip("'"))


carregar_env()

# Host, porta, usuario e nome do banco tem defaults (nao sao segredo).
# A senha NAO tem: e lida sob demanda em _senha_mysql().
MYSQL_CFG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "database": os.getenv("MYSQL_DATABASE", "seguranca"),
}
MONGO_URI = os.getenv(
    "MONGO_URI",
    f"mongodb://{os.getenv('MONGO_HOST', '127.0.0.1')}:"
    f"{os.getenv('MONGO_PORT', '27017')}/",
)
MONGO_DB = os.getenv("MONGO_DATABASE", "seguranca")

# Nomes dos containers da apostila (Ambiente de Laboratorio), usados so para
# orientar o usuario quando a conexao falha. A senha aparece como $VARIAVEL,
# nunca como valor.
CONTAINERS = {
    "mysql": (
        "mysql-lab",
        'docker run -d --name mysql-lab -e MYSQL_ROOT_PASSWORD="$MYSQL_PASSWORD" '
        f"-e MYSQL_DATABASE={MYSQL_CFG['database']} "
        f"-p {MYSQL_CFG['port']}:3306 mysql:8",
    ),
    "mongo": (
        "mongo-lab",
        "docker run -d --name mongo-lab -p 27017:27017 mongo:7",
    ),
}


def _senha_mysql():
    senha = os.getenv("MYSQL_PASSWORD")
    if not senha:
        print("[ERRO] Variavel de ambiente MYSQL_PASSWORD nao definida.")
        print("       Copie .env.example para .env e preencha a senha, ou:")
        print('         export MYSQL_PASSWORD="sua-senha"')
        sys.exit(1)
    return senha


def _docker(*args, timeout=10):
    """Roda um comando docker e devolve (ok, saida). Nunca levanta excecao."""
    try:
        proc = subprocess.run(["docker", *args], capture_output=True,
                              text=True, timeout=timeout)
        return proc.returncode == 0, proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False, ""


def _dica(servico):
    """Descobre POR QUE a conexao falhou e imprime a acao que resolve."""
    nome, comando_run = CONTAINERS[servico]
    if shutil.which("docker") is None:
        print("       Docker nao encontrado no PATH. Instale o Docker Desktop "
              "ou aponte as variaveis de ambiente para um servidor existente.")
        return
    if not _docker("info", "--format", "{{.ServerVersion}}")[0]:
        print("       O Docker Desktop nao esta rodando. Abra-o e rode:")
        print(f"         docker start {nome}")
        return
    ok, saida = _docker("ps", "-a", "--filter", f"name=^{nome}$",
                        "--format", "{{.Names}} {{.State}}")
    if ok and saida:
        if saida.split()[-1] == "running":
            print(f"       O container '{nome}' esta rodando, mas a porta nao "
                  f"respondeu. Se acabou de subir, espere ~25 s.")
        else:
            print(f"       O container '{nome}' existe mas esta parado:")
            print(f"         docker start {nome}")
        return
    print(f"       O container '{nome}' nao existe. Crie com:")
    print(f"         {comando_run}")


def conectar_mysql(database=True):
    """Conecta no MySQL. Cria o schema se ainda nao existir."""
    cfg = dict(MYSQL_CFG, password=_senha_mysql())
    banco = cfg.pop("database")
    try:
        conn = mysql.connector.connect(**cfg)
    except mysql.connector.Error as e:
        if e.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("[ERRO] Usuario ou senha do MySQL invalidos "
                  "(confira MYSQL_USER / MYSQL_PASSWORD).")
        else:
            print(f"[ERRO] Nao foi possivel conectar ao MySQL em "
                  f"{cfg['host']}:{cfg['port']} -> {e.msg}")
            _dica("mysql")
        sys.exit(1)
    if database:
        cur = conn.cursor()
        # Identificador nao pode ser parametrizado (ver Ex. 5); o nome vem da
        # configuracao, nao do usuario, e e validado antes de ir para o SQL.
        if not banco.replace("_", "").isalnum():
            raise ValueError(f"nome de banco invalido: {banco!r}")
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{banco}`")
        cur.execute(f"USE `{banco}`")
        cur.close()
    return conn


def conectar_mongo():
    """Conecta no MongoDB e confirma o handshake com um ping."""
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000,
                             tz_aware=True)
        client.admin.command("ping")
        return client[MONGO_DB]
    except ServerSelectionTimeoutError as e:
        causa = str(e).split(", Timeout:")[0].split(" (configured")[0]
        # Nunca imprime a URI inteira: ela pode conter usuario:senha.
        print("[ERRO] Nao foi possivel conectar ao MongoDB.")
        print(f"       {causa}")
        _dica("mongo")
        sys.exit(1)


if __name__ == "__main__":
    conn = conectar_mysql()
    cur = conn.cursor()
    cur.execute("SELECT VERSION(), DATABASE()")
    versao, banco = cur.fetchone()
    print(f"MySQL   OK -> versao {versao}, banco '{banco}'")
    conn.close()

    db = conectar_mongo()
    print(f"MongoDB OK -> versao {db.client.server_info()['version']}, "
          f"banco '{db.name}'")
