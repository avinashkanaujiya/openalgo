"""Authorized, audited Zerodha login for the scheduled OpenAlgo job."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import uuid
from datetime import UTC, datetime
from threading import Lock
from urllib.parse import urlsplit

from flask import request, session

from broker.zerodha.api.auth_api import authenticate_broker
from broker.zerodha.api.auto_login import AutoLoginError, obtain_request_token
from database.auth_db import get_auth_token
from utils.auth_utils import handle_auth_success
from utils.config import (
    build_external_url,
    get_broker_api_key,
    get_broker_api_secret,
    get_host_server,
)
from utils.logging import get_logger
from utils.session import has_login_this_trading_session

logger = get_logger(__name__)
_LOGIN_LOCK = Lock()  # ponytail: process-local; cross-process lock only if worker count changes.

AUDIT_PATH = "/app/log/broker-auth.jsonl"
MAX_AUDIT_BYTES = 64 * 1024 * 1024
_MAX_AUDIT_LINE_BYTES = 4096
_PROFILE_URL = "https://api.kite.trade/user/profile"
_PROFILE_TIMEOUT = 15.0
_APPROVAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_AUDIT_CONFIG_REFS = (
    "ZERODHA_AUTO_LOGIN_ENABLED",
    "ZERODHA_AUTO_LOGIN_TOKEN",
    "ZERODHA_AUTO_LOGIN_USERNAME",
    "ZERODHA_AUTO_LOGIN_APPROVAL",
    "ZERODHA_AUTO_LOGIN_CODE_VERSION",
    "KITE_USER_ID",
    "KITE_PASSWORD",
    "KITE_TOTP_SECRET",
    "BROKER_API_KEY",
    "BROKER_API_SECRET",
    "HOST_SERVER",
    "REDIRECT_URL",
)


class _LoginResult(Exception):
    def __init__(self, status, reason, outcome="rejected", error="none", message="Authentication rejected."):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.outcome = outcome
        self.error = error
        self.message = message


def _append_audit(record):
    """Append and fsync one sanitized record to the pre-provisioned audit sink."""
    flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    write_fd = os.open(AUDIT_PATH, flags)
    read_fd = None
    try:
        initial = os.fstat(write_fd)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise OSError("invalid audit sink")
        fcntl.flock(write_fd, fcntl.LOCK_EX)
        before = os.fstat(write_fd)
        if before.st_size > MAX_AUDIT_BYTES:
            raise OSError("audit capacity reached")
        read_fd = os.open(AUDIT_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        current = os.fstat(read_fd)
        if (
            (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
            or current.st_nlink != 1
        ):
            raise OSError("audit sink changed")
        sequence = _last_sequence(read_fd, current.st_size) + 1
        inputs = {
            name: hashlib.sha256(os.getenv(setting, "").encode()).hexdigest()
            for name, setting in (
                ("instance_sha256", "HOST_SERVER"),
                ("user_sha256", "ZERODHA_AUTO_LOGIN_USERNAME"),
                ("account_sha256", "KITE_USER_ID"),
                ("app_sha256", "BROKER_API_KEY"),
                ("callback_sha256", "REDIRECT_URL"),
            )
        }
        entry = {
            "version": 2,
            "event_id": record["event_id"],
            "sequence": sequence,
            "timestamp": datetime.now(UTC).isoformat(),
            "actor": "scheduled-job",
            "source": "loopback POST /auth/broker/zerodha-auto-login",
            "correlation_id": record["correlation_id"],
            "target": inputs["user_sha256"],
            "action": "zerodha-auto-login",
            "phase": record["phase"],
            "config_refs": list(_AUDIT_CONFIG_REFS),
            "input_refs": ["auto-login.env", "OpenAlgo broker configuration"],
            "inputs": inputs,
            "config_version": hashlib.sha256(
                json.dumps(inputs, sort_keys=True).encode()
            ).hexdigest(),
            "code_version": record["code_version"],
            "approval_ref": record["approval_ref"],
            "reason": record["reason"],
            "outcome": record["outcome"],
            "errors": {"classification": record["error"], "retries": 0},
            "resulting_state": record["resulting_state"],
        }
        payload = (json.dumps(entry, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
        if current.st_size + len(payload) > MAX_AUDIT_BYTES:
            raise OSError("audit capacity reached")
        remaining = memoryview(payload)
        while remaining:
            count = os.write(write_fd, remaining)
            if count <= 0:
                raise OSError("audit append failed")
            remaining = remaining[count:]
        os.fsync(write_fd)
    finally:
        if read_fd is not None:
            os.close(read_fd)
        try:
            fcntl.flock(write_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(write_fd)


def _last_sequence(fd, size):
    if not size:
        return 0
    pos = size
    collected = b""
    while pos:
        count = min(1024, pos)
        pos -= count
        collected = os.pread(fd, count, pos) + collected
        trimmed = collected.rstrip(b"\n")
        if len(trimmed) > _MAX_AUDIT_LINE_BYTES:
            raise OSError("invalid audit record")
        if b"\n" in trimmed:
            break
    line = collected.rstrip(b"\n").rsplit(b"\n", 1)[-1]
    if not line or len(line) > _MAX_AUDIT_LINE_BYTES:
        raise OSError("invalid audit record")
    try:
        sequence = json.loads(line)["sequence"]
        if type(sequence) is not int or sequence < 0:
            raise ValueError
        return sequence
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise OSError("invalid audit record") from exc


def _audit_failure():
    logger.error(
        "Broker-auth audit unavailable or at 64 MiB; scheduled login stopped. "
        "Administrator must archive and rotate /app/log/broker-auth.jsonl while "
        "retaining at least 30 days; never truncate the append-only sink."
    )


def _audit_record(correlation_id, event_id, *, phase, reason, outcome, error="none", state=None):
    approval = os.getenv("ZERODHA_AUTO_LOGIN_APPROVAL", "")
    if not _APPROVAL_RE.fullmatch(approval):
        approval = "unconfigured"
    code_version = os.getenv("ZERODHA_AUTO_LOGIN_CODE_VERSION", "")
    if not re.fullmatch(r"[0-9a-f]{64}", code_version):
        code_version = "unconfigured"
    _append_audit(
        {
            "correlation_id": correlation_id,
            "event_id": event_id,
            "phase": phase,
            "reason": reason,
            "outcome": outcome,
            "error": error,
            "code_version": code_version,
            "approval_ref": approval,
            "resulting_state": state or {"auth_persisted": False},
        }
    )


def _find_exact_user(username):
    from database.user_db import find_user_by_exact_username

    return find_user_by_exact_username(username)


def _load_auth_record(username):
    from database.auth_db import Auth

    return Auth.query.filter_by(name=username).first()


def _existing_access_token(username):
    return get_auth_token(username, bypass_cache=True)


def _profile_account(api_key, access_token):
    try:
        from utils.httpx_client import get_httpx_client

        response = get_httpx_client().get(
            _PROFILE_URL,
            headers={
                "X-Kite-Version": "3",
                "Authorization": f"token {api_key}:{access_token}",
            },
            timeout=_PROFILE_TIMEOUT,
        )
        if response.status_code in (401, 403):
            return "rejected", None
        if response.status_code != 200:
            return "unknown", None
        data = response.json().get("data")
        user_id = data.get("user_id") if isinstance(data, dict) else None
        if isinstance(user_id, str) and user_id:
            return "valid", user_id
    except Exception:
        pass
    return "unknown", None

def _persist_auth(auth_token, username, broker):
    session.clear()
    session["user"] = username
    request.environ["HTTP_ACCEPT"] = "application/json"
    try:
        result = handle_auth_success(auth_token, username, broker)
    except Exception:
        session.clear()
        raise
    if isinstance(result, tuple) and len(result) == 2:
        body, status = result
        if hasattr(body, "get_json"):
            body = body.get_json(silent=True)
        persisted = status == 200 and isinstance(body, dict) and body.get("status") == "success"
    else:
        persisted = getattr(result, "status_code", None) == 200
    if not persisted:
        session.clear()
    return persisted


def _profile_or_raise(api_key, access_token, expected_user_id, *, existing):
    state, user_id = _profile_account(api_key, access_token)
    if state == "rejected" and existing:
        return False
    if state == "unknown":
        reason = "current_profile_unknown" if existing else "profile_unknown"
        raise _LoginResult(503, reason, outcome="failure", error="profile_unavailable", message="Authentication could not be verified.")
    if state == "rejected":
        raise _LoginResult(502, "new_profile_rejected", outcome="failure", error="profile_rejected", message="Authentication failed.")
    if user_id != expected_user_id:
        reason = "current_profile_account_mismatch" if existing else "profile_account_mismatch"
        raise _LoginResult(409, reason, error="account_mismatch", message="Configured broker account did not match.")
    return True


def _request_gate():
    if os.getenv("ZERODHA_AUTO_LOGIN_ENABLED", "").strip().lower() != "true":
        return _LoginResult(404, "feature_disabled", error="feature_disabled", message="Not found.")
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return _LoginResult(403, "not_loopback", error="source_policy")
    expected_token = os.getenv("ZERODHA_AUTO_LOGIN_TOKEN", "")
    authorization = request.headers.get("Authorization", "")
    supplied_token = authorization[7:] if authorization.startswith("Bearer ") else ""
    if not expected_token or not hmac.compare_digest(
        supplied_token.encode("utf-8"), expected_token.encode("utf-8")
    ):
        return _LoginResult(401, "bearer_rejected", error="authorization")
    return None

def _run_login():

    code_version = os.getenv("ZERODHA_AUTO_LOGIN_CODE_VERSION", "")
    if not re.fullmatch(r"[0-9a-f]{64}", code_version):
        raise _LoginResult(
            503,
            "code_identity_missing",
            outcome="failure",
            error="configuration",
            message="Auto-login configuration unavailable.",
        )
    approval = os.getenv("ZERODHA_AUTO_LOGIN_APPROVAL", "")
    if not _APPROVAL_RE.fullmatch(approval):
        raise _LoginResult(
            503,
            "approval_reference_missing",
            outcome="failure",
            error="configuration",
            message="Auto-login configuration unavailable.",
        )
    username = os.getenv("ZERODHA_AUTO_LOGIN_USERNAME", "")
    user = _find_exact_user(username) if username else None
    if not user or getattr(user, "username", None) != username:
        raise _LoginResult(
            503,
            "target_user_unavailable",
            outcome="failure",
            error="configuration",
            message="Auto-login configuration unavailable.",
        )

    api_key = get_broker_api_key()
    api_secret = get_broker_api_secret()
    user_id = os.getenv("KITE_USER_ID", "")
    password = os.getenv("KITE_PASSWORD", "")
    totp_secret = os.getenv("KITE_TOTP_SECRET", "")
    if not all((api_key, api_secret, user_id, password, totp_secret)):
        raise _LoginResult(
            503,
            "broker_credentials_missing",
            outcome="failure",
            error="configuration",
            message="Auto-login configuration unavailable.",
        )

    callback = build_external_url("/zerodha/callback")
    redirect_url = os.getenv("REDIRECT_URL", "")
    parsed = urlsplit(callback)
    host_server = get_host_server().rstrip("/")
    if (
        (redirect_url and redirect_url != callback)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/zerodha/callback"
        or parsed.query
        or parsed.fragment
        or host_server != callback.removesuffix("/zerodha/callback")
    ):
        raise _LoginResult(
            503,
            "callback_configuration_invalid",
            outcome="failure",
            error="configuration",
            message="Auto-login configuration unavailable.",
        )

    existing = _load_auth_record(username)
    # Daily expiry intentionally clears broker metadata while revoking the row.
    if (
        existing
        and existing.broker != "zerodha"
        and not (existing.is_revoked and existing.broker == "")
    ):
        raise _LoginResult(
            409,
            "existing_broker_conflict",
            error="broker_conflict",
            message="Configured broker is not Zerodha.",
        )
    if existing and not existing.is_revoked:
        stored_token = _existing_access_token(username)
        prefix, separator, old_access_token = (stored_token or "").partition(":")
        if not separator or not prefix or not old_access_token:
            raise _LoginResult(
                503,
                "current_token_unavailable",
                outcome="failure",
                error="current_token_unavailable",
                message="Authentication could not be verified.",
            )
        old_state = _profile_or_raise(prefix, old_access_token, user_id, existing=True)
        if old_state and prefix == api_key and has_login_this_trading_session(username):
            return (
                {
                    "status": "success",
                    "outcome": "already_valid",
                    "message": "Zerodha session already valid.",
                },
                200,
                "already_valid_today",
                "noop",
                "none",
                {
                    "auth_persisted": True,
                    "auth_changed": False,
                    "current_session_valid": True,
                    "broker": "zerodha",
                },
            )

    try:
        request_token = obtain_request_token(api_key, user_id, password, totp_secret, callback)
    except AutoLoginError as exc:
        raise _LoginResult(
            502,
            f"protocol_{exc.step}",
            outcome="failure",
            error=f"protocol_{exc.step}",
            message="Authentication failed.",
        ) from None
    except Exception:
        raise _LoginResult(
            502,
            "protocol_failed",
            outcome="failure",
            error="protocol_failed",
            message="Authentication failed.",
        ) from None

    try:
        access_token, _ = authenticate_broker(request_token)
    except Exception:
        raise _LoginResult(
            502,
            "token_exchange_failed",
            outcome="failure",
            error="token_exchange_failed",
            message="Authentication failed.",
        ) from None
    if not isinstance(access_token, str) or not access_token:
        raise _LoginResult(
            502,
            "token_exchange_failed",
            outcome="failure",
            error="token_exchange_failed",
            message="Authentication failed.",
        )
    _profile_or_raise(api_key, access_token, user_id, existing=False)
    if not _persist_auth(f"{api_key}:{access_token}", username, "zerodha"):
        raise _LoginResult(
            500,
            "auth_persistence_failed",
            outcome="failure",
            error="persistence_failed",
            message="Authentication could not be saved.",
        )
    return (
        {"status": "success", "message": "Zerodha authentication successful."},
        200,
        "profile_verified",
        "success",
        "none",
        {"auth_persisted": True, "profile_verified": True, "broker": "zerodha"},
    )

def execute_auto_login():
    """Run one audited login attempt and return a sanitized payload/status pair."""
    requested_id = request.headers.get("X-Correlation-ID", "")
    try:
        correlation_id = uuid.UUID(requested_id).hex
    except (ValueError, AttributeError):
        correlation_id = uuid.uuid4().hex
    gate = _request_gate()
    if gate is not None:
        logger.warning("Rejected Zerodha auto-login request: %s", gate.reason)
        return {
            "status": "error",
            "message": gate.message,
            "event_id": "unavailable",
            "correlation_id": correlation_id,
        }, gate.status
    attempt_id = uuid.uuid4().hex
    try:
        _audit_record(
            correlation_id,
            attempt_id,
            phase="attempt",
            reason="request_received",
            outcome="attempt",
            state={"operation": "not_started"},
        )
    except Exception:
        _audit_failure()
        return {
            "status": "error",
            "message": "Audit unavailable.",
            "event_id": "unavailable",
            "correlation_id": correlation_id,
        }, 503

    locked = _LOGIN_LOCK.acquire(blocking=False)
    if locked:
        try:
            payload, status, reason, outcome, error, state = _run_login()
        except _LoginResult as result:
            payload = {"status": "error", "message": result.message}
            status, reason, outcome, error = result.status, result.reason, result.outcome, result.error
            state = {"auth_changed": False}
        except Exception:
            logger.error("Zerodha auto-login failed during an internal operation.")
            payload = {"status": "error", "message": "Authentication failed."}
            status, reason, outcome, error = 500, "internal_error", "failure", "internal_error"
            state = {"auth_changed": "unknown"}
    else:
        payload = {"status": "error", "message": "Authentication already in progress."}
        status, reason, outcome, error = 409, "login_in_progress", "rejected", "concurrency"
        state = {"auth_changed": False}

    result_id = uuid.uuid4().hex
    try:
        try:
            _audit_record(
                correlation_id,
                result_id,
                phase="result",
                reason=reason,
                outcome=outcome,
                error=error,
                state=state,
            )
        except Exception:
            _audit_failure()
            return {
                "status": "error",
                "message": "Result audit unavailable.",
                "event_id": "unavailable",
                "correlation_id": correlation_id,
            }, 500
        payload["event_id"] = result_id
        payload["correlation_id"] = correlation_id
        return payload, status
    finally:
        if locked:
            _LOGIN_LOCK.release()
