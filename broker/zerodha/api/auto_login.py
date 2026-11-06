"""Obtain a Zerodha request token through the browser login protocol."""

from urllib.parse import parse_qs, urljoin, urlsplit

import pyotp
import requests

_BROKER_ORIGIN = ("https", "kite.zerodha.com", 443)
_BASE = "https://kite.zerodha.com"
_TIMEOUT = (5, 10)
_MAX_REDIRECT_HOPS = 5


class AutoLoginError(Exception):
    """Sanitized failure in one step of the Zerodha login flow."""

    def __init__(self, step: str, message: str):
        super().__init__(message)
        self.step = step


def _origin(parts):
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        return None
    return parts.scheme.lower(), (parts.hostname or "").lower(), port


def _callback_parts(expected_callback: str):
    try:
        parts = urlsplit(expected_callback)
        origin = _origin(parts)
        valid = (
            parts.scheme.lower() == "https"
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and not parts.query
            and not parts.fragment
            and parts.path.startswith("/")
            and origin is not None
        )
    except (AttributeError, TypeError, ValueError):
        valid = False
        parts = None
    if not valid or parts is None:
        raise AutoLoginError("config", "Invalid expected callback URL")
    return parts


def _is_broker_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
        return (
            _origin(parts) == _BROKER_ORIGIN
            and parts.username is None
            and parts.password is None
        )
    except (TypeError, ValueError):
        return False

def _response_data(response, step: str):
    if not 200 <= response.status_code < 300:
        raise AutoLoginError(step, "Zerodha login request failed")
    try:
        data = response.json()
    except (ValueError, TypeError, AttributeError):
        raise AutoLoginError(step, "Zerodha returned an invalid response") from None
    if not isinstance(data, dict):
        raise AutoLoginError(step, "Zerodha returned an invalid response")
    return data


def _callback_token(location: str, callback, base_url: str):
    try:
        target = urlsplit(urljoin(base_url, location))
    except (TypeError, ValueError):
        raise AutoLoginError("redirect", "Zerodha returned an invalid redirect") from None
    query = parse_qs(target.query, keep_blank_values=True)
    values = query.get("request_token", [])
    if (
        _origin(target) != _origin(callback)
        or target.path != callback.path
        or target.username is not None
        or target.password is not None
        or target.fragment
    ):
        if values:
            raise AutoLoginError("redirect", "Request token appeared outside the expected callback")
        return None
    if len(values) != 1 or not values[0].isalnum() or not values[0].isascii():
        raise AutoLoginError("redirect", "Expected callback did not contain a valid request token")
    return values[0]


def obtain_request_token(
    api_key: str,
    user_id: str,
    password: str,
    totp_secret: str,
    expected_callback: str,
) -> str:
    """Perform one login attempt and return request_token without exchanging it."""
    callback = _callback_parts(expected_callback)
    if not all(isinstance(value, str) and value.strip() for value in (api_key, user_id, password, totp_secret)):
        raise AutoLoginError("config", "Zerodha auto-login credentials are not configured")

    try:
        session = requests.Session()
    except Exception:
        raise AutoLoginError("login", "Zerodha login request failed") from None
    current_step = "login"
    try:
        session.trust_env = False
        session.headers["User-Agent"] = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        )
        connect_response = session.get(
            f"{_BASE}/connect/login",
            params={"v": "3", "api_key": api_key},
            allow_redirects=False,
            timeout=_TIMEOUT,
        )
        if 200 <= connect_response.status_code < 300:
            pass
        elif connect_response.status_code in (301, 302, 303, 307, 308):
            location = connect_response.headers.get("Location")
            try:
                connect_target = urlsplit(urljoin(f"{_BASE}/", location)) if location else None
            except (TypeError, ValueError):
                connect_target = None
            if (
                connect_target is None
                or not _is_broker_url(connect_target.geturl())
                or connect_target.path != "/connect/login"
                or connect_target.fragment
            ):
                raise AutoLoginError("login", "Zerodha connect redirect left the broker origin")
        else:
            raise AutoLoginError("login", "Zerodha login request failed")
        login_response = session.post(
            f"{_BASE}/api/login",
            data={"user_id": user_id, "password": password},
            allow_redirects=False,
            timeout=_TIMEOUT,
        )
        login = _response_data(login_response, "login")
        login_data = login.get("data")
        if login.get("status") != "success" or not isinstance(login_data, dict):
            raise AutoLoginError("login", "Zerodha login failed")
        request_id = login_data.get("request_id")
        twofa_types = login_data.get("twofa_types")
        if not isinstance(request_id, str) or not request_id or not isinstance(twofa_types, list):
            raise AutoLoginError("login", "Zerodha returned an invalid login response")
        if "totp" not in twofa_types:
            raise AutoLoginError("twofa", "External TOTP is not enabled on this account")

        current_step = "twofa"
        try:
            code = pyotp.TOTP(totp_secret).now()
        except Exception:
            raise AutoLoginError("config", "Invalid external TOTP configuration") from None
        twofa_response = session.post(
            f"{_BASE}/api/twofa",
            data={
                "user_id": user_id,
                "request_id": request_id,
                "twofa_value": code,
                "twofa_type": "totp",
                "skip_session": "true",
            },
            allow_redirects=False,
            timeout=_TIMEOUT,
        )
        twofa = _response_data(twofa_response, "twofa")
        if twofa.get("status") != "success":
            raise AutoLoginError("twofa", "Zerodha two-factor authentication failed")

        current_step = "redirect"
        url = f"{_BASE}/connect/login"
        for hop in range(_MAX_REDIRECT_HOPS):
            response = session.get(
                url,
                params={"v": "3", "api_key": api_key, "skip_session": "true"} if hop == 0 else None,
                allow_redirects=False,
                timeout=_TIMEOUT,
            )
            if response.status_code not in (301, 302, 303, 307, 308):
                raise AutoLoginError("redirect", "Zerodha returned an invalid redirect")
            location = response.headers.get("Location")
            if not isinstance(location, str) or not location:
                raise AutoLoginError("redirect", "Zerodha redirect location is missing")
            token = _callback_token(location, callback, url)
            if token is not None:
                return token
            next_url = urljoin(url, location)
            if not _is_broker_url(next_url):
                raise AutoLoginError("redirect", "Zerodha redirect left the broker origin")
            if hop == _MAX_REDIRECT_HOPS - 1:
                break
            url = next_url
        raise AutoLoginError("redirect", "Zerodha redirect limit exceeded")
    except AutoLoginError:
        raise
    except Exception:
        raise AutoLoginError(current_step, "Zerodha auto-login request failed") from None
    finally:
        session.close()
