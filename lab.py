"""
Utilitarios compartilhados pelas APIs Flask (Ex. 5 a 10).
FIAP - Coding for Security - CP02

- aplicar_seguranca(app): headers de seguranca + log de toda requisicao (A09)
  + handler generico de 500 que nunca vaza detalhe interno (A10).
- ServidorDeTeste: sobe o app numa thread, numa porta livre, para que os
  testes rodem com `requests` contra um servidor HTTP de verdade.
"""

import logging
import threading
import time
from pathlib import Path

from flask import jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.serving import WSGIRequestHandler, make_server

PASTA_LOGS = Path(__file__).resolve().parent / "logs"

HEADERS_SEGURANCA = {
    # So carrega recursos do proprio dominio; scripts inline sao bloqueados.
    "Content-Security-Policy": "default-src 'self'",
    # Impede o navegador de "adivinhar" o tipo (JSON interpretado como HTML).
    "X-Content-Type-Options": "nosniff",
    # Impede que a pagina seja embutida num iframe (clickjacking).
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def criar_logger(nome):
    """Logger que grava em logs/<nome>.log. Nunca registra headers de auth."""
    PASTA_LOGS.mkdir(exist_ok=True)
    logger = logging.getLogger(nome)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(PASTA_LOGS / f"{nome}.log", encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(fh)
        logger.propagate = False
    return logger


def aplicar_seguranca(app, nome):
    """Liga headers, logging de requisicoes e erro 500 generico no app."""
    logger = criar_logger(nome)
    app.config["LOGGER_SEGURANCA"] = logger

    @app.after_request
    def _headers_e_log(resp):
        for chave, valor in HEADERS_SEGURANCA.items():
            resp.headers.setdefault(chave, valor)
        # Loga metodo, rota, status e IP. A query string vai junto porque e
        # nela que tentativas de injecao aparecem -- mas nunca o X-API-Key.
        logger.info("%s %s %s -> %s", request.remote_addr, request.method,
                    request.full_path.rstrip("?"), resp.status_code)
        return resp

    @app.errorhandler(Exception)
    def _erro_interno(e):
        if isinstance(e, HTTPException):
            # 404/405/413 etc.: devolve JSON em vez da pagina HTML padrao.
            return jsonify({"erro": e.name.lower()}), e.code
        # O detalhe (traceback, nome de tabela) vai para o LOG, nunca para
        # o cliente. Quem ataca aprende com mensagem de erro.
        logger.exception("erro nao tratado em %s %s", request.method,
                         request.path)
        return jsonify({"erro": "erro interno"}), 500

    return logger


class _HandlerSilencioso(WSGIRequestHandler):
    """O log do werkzeug polui a saida dos testes; o log de seguranca de
    verdade ja e gravado em logs/ pelo after_request."""

    def log_request(self, *args, **kwargs):
        pass


class ServidorDeTeste:
    """Sobe um app Flask em 127.0.0.1 numa thread (porta livre por padrao).

        with ServidorDeTeste(app) as base:
            requests.get(f"{base}/api/...")
    """

    def __init__(self, app, porta=0):
        self.srv = make_server("127.0.0.1", porta, app, threaded=True,
                               request_handler=_HandlerSilencioso)
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        time.sleep(0.1)
        return f"http://127.0.0.1:{self.srv.server_port}"

    def __exit__(self, *exc):
        self.srv.shutdown()


def conferir(descricao, obtido, esperado):
    """Imprime uma linha de teste e devolve True/False."""
    ok = obtido == esperado
    marca = "OK  " if ok else "FALHOU"
    print(f"  [{marca}] {descricao:<62} -> {obtido}"
          + ("" if ok else f" (esperado {esperado})"))
    return ok
