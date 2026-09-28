"""
Exercicio 1 - Assistente de decisao de armazenamento (Aulas 1 e 8)
FIAP - Coding for Security - CP02

Abordagem: em vez de perguntar "qual banco combina com o perfil?", a funcao
pergunta "qual ERRO cada opcao pode cometer, e qual desses erros este perfil
nao tolera?". Cada opcao (MySQL/MongoDB, CP/AP) tem modos de falha
conhecidos; o perfil diz o custo de cada um. Escolhe-se a opcao de menor
custo, e a justificativa e montada a partir do erro que foi evitado.

Com isso a decisao se explica sozinha: a saida lista o erro inaceitavel e
qual opcao o produziria.
"""

# ---------------------------------------------------------------------------
# Modos de falha de cada opcao. "custo" diz, para um perfil, quanto aquele
# erro doi (0 = irrelevante). Os pesos maiores vao para o que nao se conserta
# depois: transacao pela metade e dado lido errado.
# ---------------------------------------------------------------------------
FALHAS_BANCO = {
    "MongoDB": [
        ("operacao gravada pela metade (sem transacao que envolva tudo)",
         lambda p: 3 * p["precisa_acid"]),
        ("registro malformado aceito sem reclamar",
         lambda p: 1 * p["schema_fixo"]),
    ],
    "MySQL": [
        ("gargalo num no so quando o volume cresce",
         lambda p: 2 * p["escala_horizontal"]),
        ("migracao de schema a cada formato novo de dado",
         lambda p: 1 * (not p["schema_fixo"])),
    ],
}

FALHAS_CAP = {
    # AP responde mesmo particionado -> pode devolver dado velho.
    "AP": ("ler um valor desatualizado numa replica atrasada",
           lambda p: 2 * (not p["tolera_atraso_de_consistencia"])),
    # CP recusa quando nao tem quorum -> para de aceitar escrita.
    "CP": ("deixar de aceitar escritas enquanto a rede esta particionada",
           lambda p: 2 * p["tolera_atraso_de_consistencia"]),
}

# O que o erro de CAP significa NESTE cenario, e qual categoria do
# OWASP Top 10 (2025) ele abre. Chave: (erro_evitado, dado_sensivel, acid).
CONSEQUENCIA = {
    ("AP", True, True): (
        "A07", "autenticar alguem com uma credencial ja revogada porque a "
               "replica ainda nao recebeu a revogacao - autenticar errado e "
               "pior que ficar fora do ar"),
    ("AP", True, False): (
        "A08", "duas replicas com trilhas diferentes - auditoria divergente "
               "nao vale como prova"),
    ("AP", False, True): (
        "A06", "vender a mesma licenca duas vezes porque cada no viu um "
               "estoque diferente - falha de desenho, nao de codigo"),
    ("AP", False, False): (
        "A06", "decidir com base em dado velho sem saber que ele e velho"),
    ("CP", False, False): (
        "A09", "parar de aceitar log enquanto a rede esta particionada - "
               "perder 1s de log e menos grave que parar de aceitar log, e "
               "ataque sem log e ataque invisivel"),
    ("CP", True, False): (
        "A07", "o login inteiro cair porque a sessao nao pode ser validada, "
               "empurrando para um 'aceita o cookie sem checar' - uma sessao "
               "que vale por alguns segundos a mais e o risco menor "
               "(mitigue com expiracao curta)"),
    ("CP", False, True): (
        "A06", "recusar operacoes que o negocio aceitaria reconciliar"),
    ("CP", True, True): (
        "A07", "indisponibilidade de autenticacao levando a atalhos "
               "inseguros"),
}


def _validar(perfil):
    esperadas = {"schema_fixo", "precisa_acid", "escala_horizontal",
                 "tolera_atraso_de_consistencia", "dado_sensivel"}
    if set(perfil) != esperadas:
        raise ValueError(f"perfil deve ter exatamente as chaves {sorted(esperadas)}")
    if not all(isinstance(v, bool) for v in perfil.values()):
        raise ValueError("todos os valores do perfil devem ser bool")


def _custo(falhas, perfil):
    """Soma o custo das falhas de uma opcao e devolve as que pesaram."""
    pesaram = [(desc, c) for desc, f in falhas if (c := f(perfil)) > 0]
    return sum(c for _, c in pesaram), pesaram


def recomendar(perfil):
    _validar(perfil)

    # Banco: menor custo de falha. Empate -> MySQL (erra fechado: recusa em
    # vez de aceitar dado estranho).
    custos = {b: _custo(f, perfil) for b, f in FALHAS_BANCO.items()}
    banco = min(custos, key=lambda b: (custos[b][0], b != "MySQL"))
    rejeitado = "MongoDB" if banco == "MySQL" else "MySQL"
    erros_evitados = [d for d, _ in custos[rejeitado][1]]

    # CAP: escolhe o lado cujo modo de falha custa menos para o perfil.
    cap = min(FALHAS_CAP, key=lambda lado: FALHAS_CAP[lado][1](perfil))
    lado_errado = "AP" if cap == "CP" else "CP"

    codigo, erro_inaceitavel = CONSEQUENCIA[
        (lado_errado, perfil["dado_sensivel"], perfil["precisa_acid"])]

    motivo_banco = (f"{banco} porque com {rejeitado} o risco seria "
                    + " e ".join(erros_evitados)) if erros_evitados else \
                   f"{banco} (nenhuma falha do outro lado pesou; desempate)"
    justificativa = (f"{motivo_banco}. {cap} porque o erro inaceitavel aqui "
                     f"e {erro_inaceitavel}.")

    return {"banco": banco, "cap": cap, "justificativa": justificativa,
            "risco_owasp": codigo}


PERFIS = {
    "credenciais_do_SOC":     {"schema_fixo": True,  "precisa_acid": True,  "escala_horizontal": False, "tolera_atraso_de_consistencia": False, "dado_sensivel": True},
    "telemetria_de_sensores": {"schema_fixo": False, "precisa_acid": False, "escala_horizontal": True,  "tolera_atraso_de_consistencia": True,  "dado_sensivel": False},
    "trilha_de_auditoria":    {"schema_fixo": False, "precisa_acid": False, "escala_horizontal": True,  "tolera_atraso_de_consistencia": False, "dado_sensivel": True},
    "carrinho_de_licencas":   {"schema_fixo": True,  "precisa_acid": True,  "escala_horizontal": False, "tolera_atraso_de_consistencia": False, "dado_sensivel": False},
    "cache_de_sessoes":       {"schema_fixo": True,  "precisa_acid": False, "escala_horizontal": True,  "tolera_atraso_de_consistencia": True,  "dado_sensivel": True},
}


def main():
    for nome, perfil in PERFIS.items():
        r = recomendar(perfil)
        print(f"{nome:<23} -> {r['banco']:<7} | {r['cap']} | {r['risco_owasp']}")
        print(f"{'':<26}{r['justificativa']}\n")


if __name__ == "__main__":
    main()
