"""A stale browser expiry must not revoke a concurrently renewed broker token."""

import sys
from datetime import timedelta
from threading import Event, Thread
from types import SimpleNamespace

from flask import Flask, session

import database.auth_db as auth_db
import utils.auth_utils as auth_utils
import utils.session as session_utils
from extensions import socketio


def test_expiry_cannot_overwrite_concurrent_broker_login(monkeypatch):
    state = {"token": "old", "fresh": False}
    checked = Event()
    release_expiry = Event()
    committed = Event()
    login_started = Event()
    errors = []

    def freshness(*_args):
        fresh = state["fresh"]
        checked.set()
        assert release_expiry.wait(3)
        return fresh

    def upsert(_username, token, _broker, **kwargs):
        state["token"] = "revoked" if kwargs.get("revoke") else token
        if not kwargs.get("revoke"):
            committed.set()
        return 1

    def register(**_kwargs):
        state["fresh"] = True

    monkeypatch.setattr(session_utils, "_has_fresher_session", freshness)
    monkeypatch.setattr(auth_db, "upsert_auth", upsert)
    monkeypatch.setattr(auth_utils, "upsert_auth", upsert)
    monkeypatch.setattr(auth_db, "invalidate_user_auth_cache", lambda *_: None)
    monkeypatch.setattr(auth_db, "register_session", register)
    monkeypatch.setattr(auth_db, "get_active_sessions", lambda *_: [])
    monkeypatch.setattr(auth_db, "log_login_attempt", lambda **_kwargs: None)
    monkeypatch.setattr(auth_db, "clear_user_sessions", lambda *_: state.update(fresh=False))
    monkeypatch.setattr(socketio, "emit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(auth_utils, "get_session_expiry_time", lambda: timedelta(days=1))
    monkeypatch.setattr(auth_utils, "set_session_login_time", lambda: None)
    monkeypatch.setattr(auth_utils, "get_real_ip", lambda: "127.0.0.1")
    monkeypatch.setattr(auth_utils, "should_download_master_contract", lambda _: (True, "test"))
    monkeypatch.setattr(auth_utils, "try_start_master_contract_download", lambda *_args, **_kwargs: False)
    for module, name in (
        ("database.cache_invalidation", "publish_all_cache_invalidation"),
        ("database.master_contract_cache_hook", "clear_cache_on_logout"),
        ("database.settings_db", "clear_settings_cache"),
        ("database.telegram_db", "clear_telegram_cache"),
    ):
        monkeypatch.setitem(sys.modules, module, SimpleNamespace(**{name: lambda *_: None}))

    app = Flask(__name__)
    app.secret_key = "isolated-race-check"

    def expire():
        try:
            with app.test_request_context("/dashboard"):
                session.update(user="trader", session_id="stale")
                session_utils.revoke_user_tokens()
        except BaseException as error:
            errors.append(error)

    def login():
        try:
            with app.test_request_context("/auth/broker/zerodha-auto-login", headers={"Accept": "application/json"}):
                login_started.set()
                auth_utils.handle_auth_success("fresh", "trader", "zerodha")
        except BaseException as error:
            errors.append(error)

    expiry_thread = Thread(target=expire, daemon=True)
    login_thread = Thread(target=login, daemon=True)
    expiry_thread.start()
    try:
        assert checked.wait(3)
        login_thread.start()
        assert login_started.wait(3)
        # Without serialization login commits while the stale freshness decision
        # is parked. With serialization login waits until expiry finishes.
        committed.wait(0.5)
    finally:
        release_expiry.set()
        expiry_thread.join(3)
        if login_thread.ident is not None:
            login_thread.join(3)
    assert not expiry_thread.is_alive() and not login_thread.is_alive()
    assert errors == []
    assert state["token"] == "fresh"
    assert state["fresh"] is True
