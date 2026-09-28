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

---


