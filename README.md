# Entrega CP02 — Coding for Security

**Aluno:** Rafael · **RM:** 571199 · **Turma:** 1TDCPF
**Disciplina:** Coding for Security — FIAP

---

## Como rodar

### 1. Credenciais

```bash
cp .env.example .env        # preencha MYSQL_PASSWORD; o .env está no .gitignore
```

Nenhum arquivo do projeto tem senha com valor padrão: sem `MYSQL_PASSWORD`, o
programa para com uma mensagem explicando o que fazer.

### 2. Subir os bancos 

```bash
docker run -d --name mysql-lab -e MYSQL_ROOT_PASSWORD="$MYSQL_PASSWORD" -e MYSQL_DATABASE=seguranca -p 3306:3306 mysql:8
docker run -d --name mongo-lab -p 27017:27017 mongo:7
```

### 3. Dependências e teste de conexão

```bash
python -m pip install -r requirements.txt
python db.py
```

### 4. Rodar

```bash
python run_all.py                 # todos, com placar
python ex05_ordenacao.py --testar # uma API: sobe o servidor e roda os testes
python ex05_ordenacao.py          # uma API: só sobe o servidor (127.0.0.1)
```

Todos os scripts são idempotentes (recriam o próprio estado).

### 5. Exercício 10 — antes e depois (prova o ataque, prova a defesa)

O mesmo `exploit.py` roda contra os dois apps: vence os 6 ataques no
`app_vulneravel.py` e falha em todos no `app_seguro.py`.

```bash
# pré-requisitos: MySQL no ar (passo 2) e MYSQL_PASSWORD definida (passo 1).
# a MESMA senha tem que estar no .env E no MYSQL_ROOT_PASSWORD do container.

python ex10/lab_dados.py            # cria a tabela usuarios (3 usuários)

python ex10/exploit.py              # ANTES  -> 6 de 6 ataques bem-sucedidos
python ex10/exploit.py --seguro     # DEPOIS -> 0 de 6 ataques bem-sucedidos
python ex10/exploit.py --verificar  # roda os dois e confirma 6/6 e depois 0/6
python ex10/app_seguro.py --testar  # prova que a defesa não quebrou o recurso
```

Também é possível subir cada app e testar no navegador:

```bash
python ex10/app_vulneravel.py       # sobe o app vulnerável em 127.0.0.1:5010
python ex10/app_seguro.py           # sobe o app seguro     em 127.0.0.1:5011
```

O laudo com as 10 falhas (código OWASP 2025, impacto e correção) está em
[`ex10/auditoria.md`](ex10/auditoria.md); duas delas são ausências (sem
autenticação e sem logging).



