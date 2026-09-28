"""
Exercicio 7 - XSS dentro do atributo (Aulas 6, 7 e 8/A05)
FIAP - Coding for Security - CP02

EXERCICIO DEFENSIVO: os payloads rodam apenas contra esta aplicacao local.

GET /dashboard          -> template Jinja2 (autoescape), SEGURO
GET /dashboard-inseguro -> f-string sem escape, INSEGURO, so para comparar

    python ex07_xss.py            # sobe em 127.0.0.1:5007 (abra no navegador)
    python ex07_xss.py --testar   # sobe numa thread e prova a defesa

Por que um |safe mal colocado reabre o buraco: |safe diz ao Jinja2 "este
texto ja e HTML confiavel, nao escape" -- aplicado a dado do banco, devolve
as aspas e os < > ao atacante, exatamente como a rota insegura.

Defesa em profundidade: TODAS as respostas levam Content-Security-Policy:
default-src 'self'. Ela barra script inline e handlers como onerror mesmo na
rota insegura -- mas CSP e a segunda camada; a primeira e nao deixar o
payload virar HTML. Verificado no Chromium: removendo o CSP, a rota insegura
dispara alert('xss1'); a segura nao dispara nada. O onerror do p2 so executa
se a imagem falhar ao carregar, mas o atributo e injetado de qualquer jeito
(o Inspetor abaixo mostra img.onerror no HTML inseguro).
"""

import os
import sys
from html.parser import HTMLParser

import requests
from flask import Flask, render_template

from db import conectar_mongo
from lab import ServidorDeTeste, aplicar_seguranca, conferir

P1 = "<script>alert('xss1')</script>"
P2 = 'x" onerror="alert(\'xss2\')'   # escapa do atributo sem usar <script>

app = Flask(__name__)
log = aplicar_seguranca(app, "ex07")


def preparar():
    col = conectar_mongo().incidentes_dashboard
    col.drop()
    col.insert_many([
        {"titulo": P1, "ativo": P1, "severidade": "alta"},
        {"titulo": P2, "ativo": P2, "severidade": "critica"},
        {"titulo": "Brute force SSH", "ativo": "SRV-WEB01", "severidade": "media"},
    ])


def carregar():
    col = conectar_mongo().incidentes_dashboard
    return list(col.find({}, {"_id": 0}))


@app.get("/dashboard")
def dashboard():
    return render_template("ex07_dashboard.html", incidentes=carregar())


# ===========================================================================
# !!! ROTA INSEGURA DE PROPOSITO -- SO PARA COMPARACAO LADO A LADO !!!
# Monta HTML por concatenacao, sem escape. Nunca copie este padrao.
# ===========================================================================
@app.get("/dashboard-inseguro")
def dashboard_inseguro():
    linhas = "".join(
        f'<tr><td><img src="/static/icone.png" alt="{i["ativo"]}"> '
        f'{i["ativo"]}</td><td>{i["titulo"]}</td><td>{i["severidade"]}</td></tr>'
        for i in carregar())
    return ('<!doctype html><html><head><meta charset="utf-8">'
            '<title>INSEGURO</title>'
            '<link rel="stylesheet" href="/static/ex07.css"></head><body>'
            '<div class="alerta-inseguro">ROTA INSEGURA - demonstracao de XSS. '
            'Nao usar em producao.</div>'
            f'<table>{linhas}</table></body></html>')


class Inspetor(HTMLParser):
    """Le o HTML como o navegador leria: quais tags e atributos existem?"""

    def __init__(self):
        super().__init__()
        self.scripts, self.alts, self.handlers = 0, [], []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.scripts += 1
        for nome, valor in attrs:
            if tag == "img" and nome == "alt":
                self.alts.append(valor)
            if nome.startswith("on"):
                self.handlers.append(f"{tag}.{nome}")


def inspecionar(html):
    p = Inspetor()
    p.feed(html)
    return p


def testar_no_navegador(base):
    """Prova final com Chromium real, se o Playwright estiver instalado."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("  (Playwright nao instalado: teste no navegador pulado)")
        return []
    ok = []
    with sync_playwright() as pw:
        try:
            nav = pw.chromium.launch(
                executable_path=os.getenv("CHROMIUM_PATH") or None)
        except Exception as e:
            print(f"  (Chromium nao abriu: {str(e).splitlines()[0][:80]}; "
                  f"defina CHROMIUM_PATH. Teste no navegador pulado)")
            return []
        for rota in ("/dashboard", "/dashboard-inseguro"):
            pagina = nav.new_page()
            alertas = []
            pagina.on("dialog", lambda d: (alertas.append(d.message), d.dismiss()))
            pagina.goto(base + rota)
            pagina.wait_for_timeout(300)
            ok.append(conferir(f"Chromium em {rota}: alert() disparados",
                               alertas, []))
            pagina.close()
        nav.close()
    print("          (na rota insegura quem segurou foi o CSP, nao o codigo)")
    return ok


def testar():
    preparar()
    ok = []
    with ServidorDeTeste(app) as base:
        seguro = requests.get(f"{base}/dashboard")
        inseguro = requests.get(f"{base}/dashboard-inseguro")

        print("=== /dashboard (Jinja2, autoescape) ===")
        s = inspecionar(seguro.text)
        ok.append(conferir("p1 como texto: nenhuma tag <script> criada",
                           s.scripts, 0))
        ok.append(conferir("p1 aparece literal no HTML (escapado)",
                           "&lt;script&gt;alert(" in seguro.text, True))
        ok.append(conferir("p2: alt contem o payload inteiro como texto",
                           P2 in s.alts, True))
        ok.append(conferir("p2: nenhum atributo on* criado", s.handlers, []))
        ok.append(conferir("CSP: default-src 'self'",
                           seguro.headers.get("Content-Security-Policy"),
                           "default-src 'self'"))

        print("\n=== /dashboard-inseguro (f-string, para comparacao) ===")
        i = inspecionar(inseguro.text)
        print(f"  tags <script> injetadas: {i.scripts}")
        print(f"  handlers injetados:      {i.handlers}")
        print(f"  alt truncado para:       {[a for a in i.alts if a != P1]}")
        ok.append(conferir("rota insegura TAMBEM recebe o CSP",
                           inseguro.headers.get("Content-Security-Policy"),
                           "default-src 'self'"))

        print()
        ok += testar_no_navegador(base)
    print(f"\n{sum(ok)}/{len(ok)} testes passaram.")
    return all(ok)


if __name__ == "__main__":
    if "--testar" in sys.argv:
        sys.exit(0 if testar() else 1)
    preparar()
    app.run(host="127.0.0.1", port=5007, debug=False)
