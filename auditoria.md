# Auditoria — Exercício 10 (Desafio): antes e depois

**Aluno:** Rafael · **RM:** 571199 · **Turma:** 1TDCPF
**Disciplina:** Coding for Security — FIAP · **OWASP Top 10 (2025)**

Alvo: `app_vulneravel.py` (cópia do enunciado). Correções em `app_seguro.py`.
Prova automática: `python exploit.py --verificar` → **6 de 6** ataques vencem o
app vulnerável e **0 de 6** vencem o app seguro (o mesmo `exploit.py` nos dois).

10 falhas catalogadas. **Duas são ausências** (marcadas 🕳️): não há uma única
linha sobre elas no arquivo — é a *falta* que é a falha. As seis primeiras são
os ataques numerados que o `exploit.py` dispara.

| # | Falha (onde) | OWASP 2025 | Impacto | Correção em `app_seguro.py` |
|---|---|---|---|---|
| 1 | SQL Injection na busca — `f"... LIKE '%{nome}%'"` (`/api/usuarios/buscar`) | **A05 Injection** | `nome=' OR '1'='1` quebra o filtro e vaza a base inteira; `; DROP`/`UNION` levariam a leitura/escrita arbitrária | Query 100% parametrizada: `LIKE %s` com `("%"+nome+"%",)`; o payload vira texto procurado, nunca código |
| 2 | XSS refletido — `f"<h1>Bem-vindo, {u}</h1>"` (`/perfil`) | **A05 Injection** | `u=<script>alert(1)</script>` volta cru e executa no navegador da vítima (roubo de sessão/cookie) | `markupsafe.escape(u)` antes de compor o HTML → `&lt;script&gt;`, texto literal |
| 3 | Falta de autorização no `DELETE /api/usuarios/<id>` | **A01 Broken Access Control** | Qualquer um apaga qualquer usuário sem credencial (200 e registro removido) | Exige `X-API-Key` (401 sem) e `nivel >= 5` (403 sem nível); checagem **antes** de tocar no banco |
| 4 | Erro cru vazado — `debug=True` + rota sem `try/except` (`/api/relatorio`) | **A10 Mishandling of Exceptional Conditions** | 500 devolve traceback e `Table 'seguranca.tabela_inexistente'...`: entrega schema e stack ao atacante | Handler global de 500 (`aplicar_seguranca`): traceback só no log; cliente recebe `{"erro":"erro interno"}`; `debug=False` |
| 5 | Exposição de dado sensível — `SELECT *` devolve a coluna `senha` | **A04 Cryptographic Failures** | Hash de senha (e `api_key`) sai na API → ataque de dicionário offline / uso da chave | `SELECT id, nome, email, nivel`: colunas explícitas; segredo nunca trafega |
| 6 | Headers de segurança ausentes (nenhum é definido) | **A02 Security Misconfiguration** | Sem CSP/`X-Frame-Options`/`nosniff`: clickjacking, MIME-sniffing, XSS mais fácil | `aplicar_seguranca` injeta CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control` em toda resposta |
| 7 | Credencial fixa no código — `SENHA_MESTRA = "Cyber@2024"` | **A07 Authentication Failures** | Segredo versionado no Git; qualquer leitor do repositório o conhece (backdoor de autenticação típico) | Removida; nenhum segredo no código — credenciais/senha vêm só do ambiente (`db.py`, `.env` no `.gitignore`) |
| 8 | `debug=True` e bind em `0.0.0.0` | **A02 Security Misconfiguration** | Console interativo do Werkzeug (RCE) exposto à rede inteira | `debug=False` e escuta em `127.0.0.1` |
| 9 🕳️ | **Ausência**: nenhum mecanismo de autenticação/sessão no arquivo | **A07 Authentication Failures** | Toda a API é anônima — não há como saber *quem* faz cada chamada; nada dá para autorizar | Autenticação por `X-API-Key` validada no banco (SHA-256 da chave, nunca em claro) |
| 10 🕳️ | **Ausência**: nenhum log ou monitoramento de eventos | **A09 Logging & Alerting Failures** | Ataque sem log é ataque invisível: injeção, delete e força-bruta não deixam rastro para resposta a incidente | `aplicar_seguranca` registra método/rota/status/IP de toda requisição e toda credencial inválida em `logs/` (sem vazar o `X-API-Key`) |

## Como reproduzir

```bash
export MYSQL_PASSWORD="sua-senha"      # nunca no código (ver .env.example)
python ex10/lab_dados.py               # cria a tabela usuarios (3 usuários)

python ex10/exploit.py                 # ANTES  -> 6 de 6 ataques bem-sucedidos
python ex10/exploit.py --seguro        # DEPOIS -> 0 de 6 ataques bem-sucedidos
python ex10/exploit.py --verificar     # roda os dois e confirma 6 e depois 0
python ex10/app_seguro.py --testar     # prova que a defesa não quebrou o recurso
```

## Observações

- **Por que [4] usa `debug=True` no laboratório:** ao servir o app numa thread, o
  `exploit.py` embrulha o app vulnerável no debugger do Werkzeug — é o que faz o
  traceback voltar *no corpo* da resposta, exatamente como o `app.run(debug=True)`
  do enunciado. O app seguro roda com `debug=False`, então esse vazamento não
  ocorre e sobra apenas `{"erro":"erro interno"}`.
- **[5] vs [4]** são falhas distintas: [5] é dado sensível saindo numa resposta
  *bem-sucedida* (a coluna `senha`); [4] é detalhe interno saindo numa resposta
  de *erro* (traceback + nome da tabela).
- **[3] vs [9]** também: [3] é a rota `DELETE` sem *checagem de autorização*
  (A01); [9] é a *ausência total* de um mecanismo de autenticação no arquivo
  (A07). Corrigir a segunda é pré-requisito para corrigir a primeira.
