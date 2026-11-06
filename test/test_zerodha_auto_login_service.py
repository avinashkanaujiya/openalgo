"""Zerodha scheduled login stays account-bound and fail-closed."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from threading import Lock
from types import SimpleNamespace

import pytest
from flask import Flask

TEST_DB = Path(__file__).resolve().parents[1] / "tmp" / "test_zerodha_auto_login_service.db"
TEST_DB.parent.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("DATABASE_URL", f"sqlite:///{TEST_DB.as_posix()}")
os.environ.setdefault("API_KEY_PEPPER", "test-only-zerodha-auto-login-pepper-0123456789")
os.environ.setdefault("FERNET_SALT", "a" * 64)


from broker.zerodha.api import auto_login_service as service  # noqa: E402

USER_ID = "KITE-USER-123"
ACCESS_TOKEN = "SENTINEL_ACCESS_TOKEN"
CORRELATION_ID = "f" * 32


@pytest.fixture
def configured(monkeypatch, tmp_path):
    audit = tmp_path / "broker-auth.jsonl"
    audit.touch()
    monkeypatch.setattr(service, "AUDIT_PATH", audit)
    for key, value in {
        "ZERODHA_AUTO_LOGIN_ENABLED": "true",
        "ZERODHA_AUTO_LOGIN_TOKEN": "job-token",
        "ZERODHA_AUTO_LOGIN_USERNAME": "imavinash",
        "ZERODHA_AUTO_LOGIN_APPROVAL": "2026-10-22-main-daily-0850-keep-strategies-running",
        "ZERODHA_AUTO_LOGIN_CODE_VERSION": "a" * 64,
        "KITE_USER_ID": USER_ID,
        "KITE_PASSWORD": "password-value",
        "KITE_TOTP_SECRET": "totp-value",
        "BROKER_API_KEY": "api-key",
        "BROKER_API_SECRET": "api-secret",
        "HOST_SERVER": "https://openalgo.imavinash.net",
        "REDIRECT_URL": "https://openalgo.imavinash.net/zerodha/callback",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(
        service,
        "_find_exact_user",
        lambda username: SimpleNamespace(username=username) if username == "imavinash" else None,
    )
    return audit


def _call(headers=None, remote_addr="127.0.0.1"):
    app = Flask(__name__)
    app.secret_key = "test-session-key"
    with app.test_request_context(
        "/auth/broker/zerodha-auto-login",
        method="POST",
        headers=headers or {},
        environ_base={"REMOTE_ADDR": remote_addr},
    ):
        return service.execute_auto_login()


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_kite_profile_verification_uses_composite_token_and_checks_account(monkeypatch):
    from utils import httpx_client

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"status": "success", "data": {"user_id": USER_ID}}

    class FakeClient:
        def __init__(self):
            self.response = FakeResponse()
            self.request = None

        def get(self, url, *, headers, timeout):
            self.request = (url, headers, timeout)
            return self.response

    client = FakeClient()
    monkeypatch.setattr(httpx_client, "get_httpx_client", lambda: client)

    assert service._profile_account("kite-key", "access-token") == ("valid", USER_ID)
    assert client.request == (
        "https://api.kite.trade/user/profile",
        {
            "X-Kite-Version": "3",
            "Authorization": "token kite-key:access-token",
        },
        15.0,
    )
    client.response.status_code = 403
    assert service._profile_account("kite-key", "expired-token") == ("rejected", None)


def test_rejects_bad_bearer_before_any_broker_login(configured, monkeypatch, caplog):
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("unauthorized request reached Kite")
    )

    payload, status = _call(
        {"Authorization": "Bearer wrong-token", "X-Correlation-ID": CORRELATION_ID}
    )

    assert status == 401
    assert payload["status"] == "error"
    assert payload["correlation_id"] == CORRELATION_ID
    assert not _records(configured)
    assert "wrong-token" not in configured.read_text(encoding="utf-8")
    assert "wrong-token" not in caplog.text


def test_rejects_non_loopback_even_with_valid_bearer(configured, monkeypatch):
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("remote request reached Kite")
    )

    payload, status = _call({"Authorization": "Bearer job-token"}, "172.20.0.8")

    assert status == 403
    assert payload["status"] == "error"
    assert not _records(configured)


def test_disabled_endpoint_never_reaches_kite(configured, monkeypatch):
    monkeypatch.delenv("ZERODHA_AUTO_LOGIN_ENABLED")
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("disabled endpoint reached Kite")
    )

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 404
    assert payload["status"] == "error"
    assert not _records(configured)


def test_concurrent_attempt_is_rejected_without_a_second_login(configured, monkeypatch):
    lock = Lock()
    lock.acquire()
    monkeypatch.setattr(service, "_LOGIN_LOCK", lock)
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("concurrent request reached Kite")
    )
    try:
        payload, status = _call({"Authorization": "Bearer job-token"})
    finally:
        lock.release()

    assert status == 409
    assert payload["status"] == "error"
    assert _records(configured)[-1]["reason"] == "login_in_progress"


def test_persists_only_profile_verified_access_token(configured, monkeypatch):
    persisted = []
    monkeypatch.setattr(service, "_load_auth_record", lambda _username: None)
    monkeypatch.setattr(service, "obtain_request_token", lambda *_args: "request-token")
    monkeypatch.setattr(service, "authenticate_broker", lambda _token: (ACCESS_TOKEN, None))
    monkeypatch.setattr(service, "_profile_account", lambda _api_key, token: ("valid", USER_ID))
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 200
    assert payload["status"] == "success"
    assert ACCESS_TOKEN not in json.dumps(payload)
    assert persisted == [("api-key:" + ACCESS_TOKEN, "imavinash", "zerodha")]
    outcome = _records(configured)[-1]
    assert outcome["phase"] == "result" and outcome["outcome"] == "success"
    assert ACCESS_TOKEN not in configured.read_text(encoding="utf-8")
    audit_text = configured.read_text(encoding="utf-8")
    for secret_or_identifier in (
        ACCESS_TOKEN,
        USER_ID,
        "api-key",
        "api-secret",
        "password-value",
        "totp-value",
        "imavinash",
    ):
        assert secret_or_identifier not in audit_text
    assert outcome["sequence"] == 2
    assert outcome["version"] == 2
    assert outcome["approval_ref"] == "2026-10-22-main-daily-0850-keep-strategies-running"
    assert outcome["code_version"] == "a" * 64
    assert "auto-login.env" in outcome["input_refs"]
    assert outcome["inputs"]["app_sha256"] == hashlib.sha256(b"api-key").hexdigest()
    assert outcome["inputs"]["account_sha256"] == hashlib.sha256(USER_ID.encode()).hexdigest()
    assert outcome["target"] == hashlib.sha256(b"imavinash").hexdigest()
    assert outcome["config_version"] == hashlib.sha256(
        json.dumps(outcome["inputs"], sort_keys=True).encode()
    ).hexdigest()


def test_refuses_new_token_when_kite_profile_is_another_account(configured, monkeypatch):
    persisted = []
    monkeypatch.setattr(service, "_load_auth_record", lambda _username: None)
    monkeypatch.setattr(service, "obtain_request_token", lambda *_args: "request-token")
    monkeypatch.setattr(service, "authenticate_broker", lambda _token: (ACCESS_TOKEN, None))
    monkeypatch.setattr(service, "_profile_account", lambda _api_key, _token: ("valid", "OTHER-USER"))
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 409
    assert payload["status"] == "error"
    assert not persisted
    assert _records(configured)[-1]["reason"] == "profile_account_mismatch"
    assert _records(configured)[-1]["resulting_state"] == {"auth_changed": False}
    assert ACCESS_TOKEN not in configured.read_text(encoding="utf-8")


def test_refuses_to_replace_existing_token_for_another_kite_account(configured, monkeypatch):
    persisted = []
    monkeypatch.setattr(
        service,
        "_load_auth_record",
        lambda _username: SimpleNamespace(broker="zerodha", is_revoked=False, auth="encrypted"),
    )
    monkeypatch.setattr(service, "_existing_access_token", lambda _username: "api-key:old-token")
    monkeypatch.setattr(service, "_profile_account", lambda _key, _token: ("valid", "OTHER-USER"))
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("account mismatch reached Kite login")
    )
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 409
    assert payload["status"] == "error"
    assert not persisted
    assert _records(configured)[-1]["reason"] == "current_profile_account_mismatch"


def test_missing_deployed_code_identity_fails_before_broker_login(configured, monkeypatch):
    monkeypatch.delenv("ZERODHA_AUTO_LOGIN_CODE_VERSION")
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("unidentified code reached Kite")
    )

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 503
    assert payload["status"] == "error"
    assert _records(configured)[-1]["reason"] == "code_identity_missing"


def test_existing_valid_same_day_session_is_noop(configured, monkeypatch):
    persisted = []
    monkeypatch.setattr(
        service,
        "_load_auth_record",
        lambda _username: SimpleNamespace(broker="zerodha", is_revoked=False, auth="encrypted"),
    )
    monkeypatch.setattr(service, "_existing_access_token", lambda _record: "api-key:prior-token")
    monkeypatch.setattr(service, "has_login_this_trading_session", lambda _username: True)
    monkeypatch.setattr(service, "_profile_account", lambda _api_key, token: ("valid", USER_ID))
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("valid session must not log in again")
    )
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 200
    assert payload["status"] == "success"
    assert payload["outcome"] == "already_valid"
    assert not persisted
    assert _records(configured)[-1]["outcome"] == "noop"



def test_valid_token_from_another_api_app_is_not_reused(configured, monkeypatch):
    persisted = []
    profile_calls = []
    profiles = iter([("valid", USER_ID), ("valid", USER_ID)])
    monkeypatch.setattr(
        service,
        "_load_auth_record",
        lambda _username: SimpleNamespace(broker="zerodha", is_revoked=False, auth="encrypted"),
    )
    monkeypatch.setattr(service, "_existing_access_token", lambda _username: "other-app-key:prior-token")
    monkeypatch.setattr(service, "has_login_this_trading_session", lambda _username: True)
    monkeypatch.setattr(
        service,
        "_profile_account",
        lambda api_key, token: profile_calls.append((api_key, token)) or next(profiles),
    )
    monkeypatch.setattr(service, "obtain_request_token", lambda *_args: "request-token")
    monkeypatch.setattr(service, "authenticate_broker", lambda _token: (ACCESS_TOKEN, None))
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 200
    assert payload["status"] == "success"
    assert profile_calls == [
        ("other-app-key", "prior-token"),
        ("api-key", ACCESS_TOKEN),
    ]
    assert persisted == [("api-key:" + ACCESS_TOKEN, "imavinash", "zerodha")]

    assert _records(configured)[-1]["outcome"] == "success"


def test_expired_prior_token_still_enters_new_login(configured, monkeypatch):
    persisted = []
    monkeypatch.setattr(
        service,
        "_load_auth_record",
        lambda _username: SimpleNamespace(broker="zerodha", is_revoked=False, auth="encrypted"),
    )
    monkeypatch.setattr(service, "_existing_access_token", lambda _record: "api-key:expired-token")
    profiles = iter([("rejected", None), ("valid", USER_ID)])
    monkeypatch.setattr(service, "_profile_account", lambda _api_key, _token: next(profiles))
    monkeypatch.setattr(service, "obtain_request_token", lambda *_args: "request-token")
    monkeypatch.setattr(service, "authenticate_broker", lambda _token: (ACCESS_TOKEN, None))
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 200
    assert payload["status"] == "success"
    assert persisted == [("api-key:" + ACCESS_TOKEN, "imavinash", "zerodha")]
    assert ACCESS_TOKEN not in configured.read_text(encoding="utf-8")


def test_daily_revoked_empty_broker_row_can_authenticate(configured, monkeypatch):
    persisted = []
    monkeypatch.setattr(
        service, "_load_auth_record",
        lambda _username: SimpleNamespace(broker="", is_revoked=True, auth=""),
    )
    monkeypatch.setattr(
        service, "_existing_access_token",
        lambda *_: pytest.fail("daily-revoked token must not be reused"),
    )
    monkeypatch.setattr(service, "obtain_request_token", lambda *_: "request-token")
    monkeypatch.setattr(service, "authenticate_broker", lambda _: (ACCESS_TOKEN, None))
    monkeypatch.setattr(service, "_profile_account", lambda *_: ("valid", USER_ID))
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 200
    assert payload["status"] == "success"
    assert persisted == [("api-key:" + ACCESS_TOKEN, "imavinash", "zerodha")]
    assert _records(configured)[-1]["outcome"] == "success"


def test_non_zerodha_auth_record_is_never_overwritten(configured, monkeypatch):
    persisted = []
    monkeypatch.setattr(
        service,
        "_load_auth_record",
        lambda _username: SimpleNamespace(broker="dhan", is_revoked=False, auth="encrypted"),
    )
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("conflicting broker reached Kite")
    )
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 409
    assert payload["status"] == "error"
    assert not persisted
    assert _records(configured)[-1]["reason"] == "existing_broker_conflict"


def test_pre_action_audit_failure_stops_before_auth(configured, monkeypatch):
    monkeypatch.setattr(service, "_append_audit", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("unaudited request reached Kite")
    )

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 503
    assert payload["status"] == "error"


def test_result_audit_failure_returns_failure_even_after_persistence(configured, monkeypatch):
    persisted = []
    real_append = service._append_audit
    monkeypatch.setattr(service, "_load_auth_record", lambda _username: None)
    monkeypatch.setattr(service, "obtain_request_token", lambda *_args: "request-token")
    monkeypatch.setattr(service, "authenticate_broker", lambda _token: (ACCESS_TOKEN, None))
    monkeypatch.setattr(service, "_profile_account", lambda _api_key, _token: ("valid", USER_ID))
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    def append_until_result(record):
        if record["phase"] == "result":
            raise OSError("not included in response")
        real_append(record)

    monkeypatch.setattr(service, "_append_audit", append_until_result)
    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 500
    assert payload["status"] == "error"
    assert payload["event_id"] == "unavailable"
    assert persisted == [("api-key:" + ACCESS_TOKEN, "imavinash", "zerodha")]
    assert ACCESS_TOKEN not in json.dumps(payload)


def test_profile_unknown_does_not_overwrite_existing_session(configured, monkeypatch):
    persisted = []
    monkeypatch.setattr(
        service,
        "_load_auth_record",
        lambda _username: SimpleNamespace(broker="zerodha", is_revoked=False, auth="encrypted"),
    )
    monkeypatch.setattr(service, "_existing_access_token", lambda _record: "api-key:prior-token")
    monkeypatch.setattr(service, "_profile_account", lambda _api_key, _token: ("unknown", None))
    monkeypatch.setattr(
        service, "obtain_request_token", lambda *_: pytest.fail("unknown current state must fail closed")
    )
    monkeypatch.setattr(service, "_persist_auth", lambda *args: persisted.append(args) or True)

    payload, status = _call({"Authorization": "Bearer job-token"})

    assert status == 503
    assert payload["status"] == "error"
    assert not persisted
    assert _records(configured)[-1]["reason"] == "current_profile_unknown"


def test_login_route_has_only_narrow_csrf_exemption():
    from blueprints import brlogin

    class CSRFRecorder:
        def __init__(self):
            self.exempted = []

        def exempt(self, view):
            self.exempted.append(view)

    app = Flask(__name__)
    app.csrf = CSRFRecorder()
    app.register_blueprint(brlogin.brlogin_bp)

    rule = next(rule for rule in app.url_map.iter_rules() if rule.endpoint == "brlogin.zerodha_auto_login")
    assert rule.rule == "/auth/broker/zerodha-auto-login"
    assert rule.methods == {"OPTIONS", "POST"}
    assert app.csrf.exempted == [app.view_functions["brlogin.zerodha_auto_login"]]
