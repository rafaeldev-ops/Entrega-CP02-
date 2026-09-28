"""
Executa os exercicios em sequencia e mostra um placar.
FIAP - Coding for Security - CP02

    python run_all.py           saida completa de cada exercicio
    python run_all.py --resumo  so o placar

As APIs (Ex. 5 a 9) rodam com --testar: sobem numa thread e sao testadas
com requests contra o servidor no ar.
"""

import subprocess
import sys
from pathlib import Path

PASTA = Path(__file__).parent

EXERCICIOS = [
    (["ex01_recomendar.py"], "Decisao de armazenamento"),
    (["ex02_migracao.py"], "Migracao MySQL -> MongoDB"),
    (["ex03_ttl.py"], "TTL e janela temporal"),
    (["ex04_auditoria.py"], "Transacao com trilha de auditoria"),
    (["ex05_ordenacao.py", "--testar"], "ORDER BY com whitelist"),
    (["ex06_acesso.py", "--testar"], "Controle de acesso (IDOR)"),
    (["ex07_xss.py", "--testar"], "XSS em atributo"),
    (["ex08_ml_api.py", "--testar"], "Modelo servido por API"),
    (["ex09_rate_limit.py", "--testar"], "Rate limit por anomalia"),
    (["ex10/exploit.py", "--verificar"], "Antes e depois: 6/6 vs 0/6 (OWASP)"),
]


def main():
    resumo = "--resumo" in sys.argv
    resultados = []
    for args, descricao in EXERCICIOS:
        print(f"\n{f' {args[0]} - {descricao} ':=^72}\n")
        proc = subprocess.run([sys.executable, str(PASTA / args[0]), *args[1:]],
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace")
        ok = proc.returncode == 0
        resultados.append((args[0], ok))
        if not resumo:
            print(proc.stdout.rstrip())
        if not ok:
            print(f"[FALHOU] codigo de saida {proc.returncode}")
            print(proc.stderr.rstrip())

    print(f"\n{' RESUMO ':=^72}\n")
    for arquivo, ok in resultados:
        print(f"  {'OK   ' if ok else 'FALHA'}  {arquivo}")
    falhas = sum(1 for _, ok in resultados if not ok)
    print(f"\n{len(resultados) - falhas}/{len(resultados)} exercicios OK.")
    sys.exit(1 if falhas else 0)


if __name__ == "__main__":
    main()
