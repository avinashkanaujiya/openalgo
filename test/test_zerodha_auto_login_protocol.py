import json

import pytest

from broker.zerodha.api import auto_login


class FakeResponse:
    def __init__(self, status=200, payload=None, location=None, url=""):
        self.status_code = status
        self._payload = payload
        self.headers = {"Location": location} if location else {}
        self.url = url

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)

    def close(self):
        self.closed = True


def _session(monkeypatch, responses):
    session = FakeSession(responses)
    session.factory_calls = []
    monkeypatch.setattr(
        auto_login.requests,
        "Session",
        lambda: session.factory_calls.append(session) or session,
    )
    return session


def _responses(*redirects, initial=None):
    return [
        initial or FakeResponse(url="https://kite.zerodha.com/connect/login"),
        FakeResponse(payload={"status": "success", "data": {"request_id": "rid", "twofa_types": ["totp"]}}),
        FakeResponse(payload={"status": "success"}),
        *[FakeResponse(status=302, location=location) for location in redirects],
    ]


def test_initial_cookie_request_accepts_same_origin_redirect_without_following(monkeypatch):
    session = _session(
        monkeypatch,
        _responses(
            "https://openalgo.imavinash.net/zerodha/callback?request_token=late123",
            initial=FakeResponse(status=302, location="/connect/login?request_token=early"),
        ),
    )

    token = auto_login.obtain_request_token(
        "api-key", "user", "password", "JBSWY3DPEHPK3PXP",
        "https://openalgo.imavinash.net/zerodha/callback",
    )

    assert token == "late123"
    assert len(session.calls) == 4
    assert session.calls[0][0] == "GET"
    assert session.calls[0][1] == "https://kite.zerodha.com/connect/login"
    assert session.closed


def test_captures_token_from_expected_callback_after_broker_redirect_hops(monkeypatch):
    session = _session(
        monkeypatch,
        _responses(
            "/connect/finish?sess_id=opaque",
            "https://kite.zerodha.com/connect/finish?next=1",
            "https://openalgo.imavinash.net/zerodha/callback?status=success&request_token=abc123",
        ),
    )

    token = auto_login.obtain_request_token(
        "api-key", "user", "password", "JBSWY3DPEHPK3PXP",
        "https://openalgo.imavinash.net/zerodha/callback",
    )

    assert token == "abc123"
    assert session.closed
    assert len(session.calls) == 6
    assert session.factory_calls == [session]
    assert all(call[2]["allow_redirects"] is False for call in session.calls)
    assert all(call[2]["timeout"] for call in session.calls)
    assert session.calls[1][2]["data"] == {"user_id": "user", "password": "password"}
    twofa = session.calls[2][2]["data"]
    assert twofa["user_id"] == "user"
    assert twofa["request_id"] == "rid"
    assert twofa["twofa_type"] == "totp"
    assert twofa["skip_session"] == "true"
    assert twofa["twofa_value"] != "JBSWY3DPEHPK3PXP"
    assert all("openalgo.imavinash.net" not in call[1] for call in session.calls)


def test_rejects_cross_origin_redirect_without_requesting_it(monkeypatch):
    session = _session(monkeypatch, _responses("https://evil.example/steal"))

    with pytest.raises(auto_login.AutoLoginError) as error:
        auto_login.obtain_request_token(
            "api-key", "user", "password", "JBSWY3DPEHPK3PXP",
            "https://openalgo.imavinash.net/zerodha/callback",
        )

    assert error.value.step == "redirect"
    assert "evil.example" not in str(error.value)
    assert len(session.calls) == 4
    assert session.closed


def test_rejects_token_on_non_callback_origin(monkeypatch):
    session = _session(monkeypatch, _responses("https://kite.zerodha.com/other?request_token=abc123"))

    with pytest.raises(auto_login.AutoLoginError) as error:
        auto_login.obtain_request_token(
            "api-key", "user", "password", "JBSWY3DPEHPK3PXP",
            "https://openalgo.imavinash.net/zerodha/callback",
        )

    assert error.value.step == "redirect"
    assert len(session.calls) == 4
    assert session.closed


def test_login_failure_does_not_retry_credentials_or_expose_secrets(monkeypatch):
    session = _session(
        monkeypatch,
        [
            FakeResponse(),
            FakeResponse(status=401, payload={"status": "error", "message": "password leaked"}),
        ],
    )

    with pytest.raises(auto_login.AutoLoginError) as error:
        auto_login.obtain_request_token(
            "api-key", "sensitive-user", "sensitive-password", "sensitive-totp",
            "https://openalgo.imavinash.net/zerodha/callback",
        )

    assert error.value.step == "login"
    assert "sensitive" not in str(error.value)
    assert "password leaked" not in str(error.value)
    assert [call[0] for call in session.calls] == ["GET", "POST"]
    assert session.closed


def test_rejects_http_callback_before_creating_session(monkeypatch):
    constructed = []
    monkeypatch.setattr(auto_login.requests, "Session", lambda: constructed.append(True))

    with pytest.raises(auto_login.AutoLoginError) as error:
        auto_login.obtain_request_token(
            "api-key", "user", "password", "JBSWY3DPEHPK3PXP", "http://openalgo.imavinash.net/callback"
        )

    assert error.value.step == "config"
    assert constructed == []


def test_malformed_login_response_is_sanitized_and_closes_session(monkeypatch):
    session = _session(
        monkeypatch,
        [FakeResponse(), FakeResponse(payload=json.JSONDecodeError("bad", "secret", 0))],
    )

    with pytest.raises(auto_login.AutoLoginError) as error:
        auto_login.obtain_request_token(
            "api-key", "user", "password", "JBSWY3DPEHPK3PXP",
            "https://openalgo.imavinash.net/zerodha/callback",
        )

    assert error.value.step == "login"
    assert "secret" not in str(error.value)
    assert session.closed


def test_stops_after_five_manual_redirect_hops(monkeypatch):
    session = _session(
        monkeypatch,
        _responses(
            "/connect/finish/1",
            "/connect/finish/2",
            "/connect/finish/3",
            "/connect/finish/4",
            "/connect/finish/5",
            "/connect/finish/6",
        ),
    )

    with pytest.raises(auto_login.AutoLoginError) as error:
        auto_login.obtain_request_token(
            "api-key", "user", "password", "JBSWY3DPEHPK3PXP",
            "https://openalgo.imavinash.net/zerodha/callback",
        )

    assert error.value.step == "redirect"
    assert len(session.calls) == 8
    assert session.closed
