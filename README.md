# Entrega CP02 — Coding for Security

**Aluno:** Rafael · **RM:** 571199 · **Turma:** 1TDCPF
**Disciplina:** Coding for Security — FIAP

Continuação do CP01: bancos (MySQL + MongoDB), ML e APIs Flask com foco em
OWASP Top 10 (2025).

---

## Como rodar

### 1. Credenciais (nunca no código)

```bash
cp .env.example .env        # preencha MYSQL_PASSWORD; o .env está no .gitignore
```

Nenhum arquivo do projeto tem senha com valor padrão: sem `MYSQL_PASSWORD`, o
programa para com uma mensagem explicando o que fazer.

### 2. Subir os bancos (Docker, nomes da apostila)

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

## Arquivos

| Arquivo | Ex. | O que demonstra |
|---|---|---|
| `db.py` | — | Conexões por variável de ambiente, sem senha padrão |
| `lab.py` | — | Headers de segurança, log de requisições (A09), 500 genérico, servidor de teste |
| `ex01_recomendar.py` | 1 | Decisão banco/CAP/OWASP pelo custo de cada modo de falha |
| `ex02_migracao.py` | 2 | JOIN parametrizado em lotes → `insert_many`, verificação por contagem **e** conteúdo |
| `ex03_ttl.py` | 3 | Índice TTL de 7 dias + falhas por hora (fuso de SP) via agregação |
| `ex04_auditoria.py` | 4 | Transação com `FOR UPDATE`, auditoria gravada antes do commit (fail closed) |
| `ex05_ordenacao.py` | 5 | Prova prática de que `ORDER BY %s` não ordena + whitelist + teto de 100 |
| `ex06_acesso.py` | 6 | 401 × 403 × 404, IDOR barrado, 403 idêntico para "alheio" e "inexistente" |
| `ex07_xss.py` | 7 | Jinja2 × f-string, payload em atributo, CSP, prova com parser (e Chromium) |
| `ex08_ml_api.py` | 8 | RandomForest servido por API, validação de entrada, previsões auditadas |
| `ex09_rate_limit.py` | 9 | Log de acessos → agregação → IsolationForest → 429 + `Retry-After` |
| `ex10/app_vulneravel.py` | 10 | App vulnerável do enunciado (ajustado só para rodar no lab) |
| `ex10/lab_dados.py` | 10 | Popula `usuarios` com senhas/chaves aleatórias, guardadas só como hash |
| `ex10/app_seguro.py` | 10 | Versão corrigida: mesmas rotas, 10 falhas fechadas |
| `ex10/exploit.py` | 10 | Mesmo exploit nos dois apps: 6/6 no vulnerável, 0/6 no seguro |
| `ex10/auditoria.md` | 10 | Uma linha por falha: código OWASP 2025, impacto e correção |

## Status

- **Ex. 1 a 10:** implementados e testados contra MySQL 8.4 e MongoDB 7.0
  (`python run_all.py` → 10/10).
- **Ex. 10:** `python ex10/exploit.py --verificar` → 6 de 6 ataques vencem
  `app_vulneravel.py` e 0 de 6 vencem `app_seguro.py`.

---

## Observações honestas

- **Ex. 7:** no Chromium, sem CSP, a rota insegura dispara `alert('xss1')`. Com o
  CSP (aplicado a todas as rotas), nenhuma dispara: na rota insegura quem segura
  é o CSP, não o código. O `onerror` do p2 só executa se a imagem falhar, mas o
  atributo é injetado de qualquer forma (o teste mostra isso lendo o HTML).
- **Ex. 8:** os dados são sintéticos, com sobreposição entre classes e 3% de
  rótulos trocados, para as métricas não darem 1.00 de forma irreal.
- **Ex. 9:** o teste simula dois IPs com `X-Forwarded-For`. O app só confia nesse
  header no modo `--testar`. Para existir uma "população" de comparação, o log
  recebe antes o tráfego legítimo dos últimos 10 min de 4 IPs.
