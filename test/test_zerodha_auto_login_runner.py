"""The scheduler runner makes exactly one local request without logging secrets."""

from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scripts import zerodha_auto_login as runner

JOB_TOKEN = "SENTINEL_JOB_BEARER"
EVENT_ID = "c0a8012345674def9abc0123456789ab"


@pytest.fixture
def fake_server(monkeypatch):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.server.calls.append(
                (
                    self.path,
                    self.headers.get("Authorization"),
                    int(self.headers.get("Content-Length", 0)),
                    self.headers.get("X-Correlation-ID"),
                )
            )
            payload = self.server.payload
            body = json.dumps(payload).encode("utf-8")
            self.send_response(self.server.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.calls = []
    server.status = 200
    server.payload = {"status": "success", "event_id": EVENT_ID}
    monkeypatch.setattr(
        runner,
        "ENDPOINT_URL",
        f"http://127.0.0.1:{server.server_port}/auth/broker/zerodha-auto-login",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def test_runner_posts_once_with_bearer_and_prints_only_safe_result(fake_server, monkeypatch, capsys):
    monkeypatch.setenv("ZERODHA_AUTO_LOGIN_TOKEN", JOB_TOKEN)

    result = runner.main()

    assert result == 0
    path, authorization, body_length, correlation_id = fake_server.calls[0]
    assert (path, authorization, body_length) == (
        "/auth/broker/zerodha-auto-login",
        f"Bearer {JOB_TOKEN}",
        0,
    )
    assert uuid.UUID(correlation_id).hex == correlation_id
    assert capsys.readouterr().out == f"ok=true event_id={EVENT_ID}\n"


def test_runner_hides_server_error_body_and_returns_failure(fake_server, monkeypatch, capsys):
    fake_server.status = 500
    fake_server.payload = {"status": "error", "message": "SENTINEL_SERVER_DETAIL"}
    monkeypatch.setenv("ZERODHA_AUTO_LOGIN_TOKEN", JOB_TOKEN)

    result = runner.main()

    output = capsys.readouterr().out
    assert result == 1
    assert output == (
        "ok=false event_id=unavailable "
        f"correlation_id={fake_server.calls[0][3]}\n"
    )
    assert JOB_TOKEN not in output
    assert "SENTINEL_SERVER_DETAIL" not in output
    assert len(fake_server.calls) == 1


def test_runner_without_token_never_contacts_endpoint(fake_server, monkeypatch, capsys):
    monkeypatch.delenv("ZERODHA_AUTO_LOGIN_TOKEN", raising=False)

    result = runner.main()

    assert result == 1
    assert capsys.readouterr().out == "ok=false event_id=unavailable\n"
    assert not fake_server.calls
