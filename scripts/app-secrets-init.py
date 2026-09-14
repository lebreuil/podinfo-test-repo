#!/usr/bin/env python3
"""
secrets-init.py — Generate and manage application secrets in OpenBao.

Uses the OpenBao HTTP API directly.

Requirements:
    pip install requests

Required environment variables:
    OPENBAO_ADDR
    OPENBAO_APP_TOKEN
    CF_ACCESS_CLIENT_ID
    CF_ACCESS_CLIENT_SECRET

Optional environment variables:
    BAO_NAMESPACE=your-app
    SECRET_MOUNT=secret
    SECRET_KEY=config
    DEBUG=0

Usage:
    python3 secrets-init.py
    python3 secrets-init.py --get <key>
    python3 secrets-init.py --renew
"""

import base64
import os
import secrets
import sys
from getpass import getpass
from pathlib import Path

import requests


# ============================================================
# Configuration
# ============================================================

OPENBAO_ADDR = os.environ.get("OPENBAO_ADDR", "").rstrip("/")
APP_TOKEN = os.environ.get("OPENBAO_APP_TOKEN", "")

BAO_NAMESPACE = os.environ.get("BAO_NAMESPACE", "your-app")
SECRET_MOUNT = os.environ.get("SECRET_MOUNT", "secret")
SECRET_KEY = os.environ.get("SECRET_KEY", "config")

CF_ACCESS_CLIENT_ID = os.environ.get("CF_ACCESS_CLIENT_ID", "")
CF_ACCESS_CLIENT_SECRET = os.environ.get("CF_ACCESS_CLIENT_SECRET", "")

DEBUG = os.environ.get("DEBUG", "").lower() in (
    "1",
    "true",
    "yes",
)


# ============================================================
# Secret definitions
# ============================================================

def gen_base64(length):
    return base64.urlsafe_b64encode(
        secrets.token_bytes(length)
    ).decode().rstrip("=")


def gen_hex(length):
    return secrets.token_hex(length)


# Replace these example keys with the values required by the application.
GENERATED_KEYS = {
    "secret-key": lambda: gen_base64(50),
    "password": lambda: gen_base64(24),
}


# Keys entered interactively.
#
# mode:
#   "prompt" -> securely read a single-line value using getpass()
#   "file"   -> ask for a file path and read the complete file
#
PROMPTED_KEYS = {
    # "smtp-password": {
    #     "prompt": "SMTP password",
    #     "mode": "prompt",
    # },
}


# ============================================================
# Output helpers
# ============================================================

GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
RESET = "\033[0m"


def info(message):
    print(f"{GREEN}✓ {message}{RESET}")


def warn(message):
    print(f"{YELLOW}⚠ {message}{RESET}")


def error(message):
    print(f"{RED}✗ {message}{RESET}", file=sys.stderr)
    sys.exit(1)


# ============================================================
# Configuration validation
# ============================================================

def validate_environment():
    required = {
        "OPENBAO_ADDR": OPENBAO_ADDR,
        "OPENBAO_APP_TOKEN": APP_TOKEN,
        "CF_ACCESS_CLIENT_ID": CF_ACCESS_CLIENT_ID,
        "CF_ACCESS_CLIENT_SECRET": CF_ACCESS_CLIENT_SECRET,
    }

    missing = [
        name
        for name, value in required.items()
        if not value
    ]

    if missing:
        error(
            "Missing environment variable(s): "
            + ", ".join(missing)
        )


# ============================================================
# OpenBao API
# ============================================================

def api_headers():
    headers = {
        "X-Vault-Token": APP_TOKEN,
        "CF-Access-Client-Id": CF_ACCESS_CLIENT_ID,
        "CF-Access-Client-Secret": CF_ACCESS_CLIENT_SECRET,
    }

    if BAO_NAMESPACE:
        headers["X-Vault-Namespace"] = BAO_NAMESPACE

    return headers


def api_request(method, path, **kwargs):
    """Perform an OpenBao API request and return the response."""

    url = f"{OPENBAO_ADDR}/v1/{path.lstrip('/')}"
    headers = api_headers()

    if DEBUG:
        print()
        print(f"DEBUG: {method} {url}")
        print(
            "DEBUG: X-Vault-Token: "
            f"{'present' if APP_TOKEN else 'MISSING'}"
        )
        print(
            "DEBUG: X-Vault-Namespace: "
            f"{BAO_NAMESPACE or '<root>'}"
        )
        print(
            "DEBUG: CF-Access-Client-Id: "
            f"{'present' if CF_ACCESS_CLIENT_ID else 'MISSING'}"
        )
        print(
            "DEBUG: CF-Access-Client-Secret: "
            f"{'present' if CF_ACCESS_CLIENT_SECRET else 'MISSING'}"
        )
        if "json" in kwargs:
            print(
                "DEBUG: Request JSON keys: "
                + ", ".join(kwargs["json"].keys())
            )

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=30,
            allow_redirects=False,
            **kwargs,
        )
    except requests.RequestException as exc:
        error(f"Cannot connect to OpenBao: {exc}")

    if DEBUG:
        print(f"DEBUG: Response status: {response.status_code}")
        if response.is_redirect:
            print(
                "DEBUG: Redirect location: "
                f"{response.headers.get('Location', '<none>')}"
            )

    if 300 <= response.status_code < 400:
        error(
            "Request was redirected before reaching OpenBao.\n"
            f"HTTP {response.status_code}\n"
            f"Location: {response.headers.get('Location', '')}"
        )

    return response


def response_json(response):
    """Return response JSON, or None if the response is not JSON."""

    try:
        return response.json()
    except ValueError:
        return None


def raise_for_error(response, action):
    """Stop with a useful error message for unsuccessful responses."""

    if response.ok:
        return

    details = response_json(response)
    if details is None:
        details = response.text

    error(f"{action}\nHTTP {response.status_code}: {details}")


def authenticate():
    """Verify that the application token works in the namespace."""

    validate_environment()
    response = api_request("GET", "auth/token/lookup-self")
    raise_for_error(
        response,
        (
            "Token is not authenticated "
            f"in namespace '{BAO_NAMESPACE}'."
        ),
    )
    info(f"Authenticated in namespace: {BAO_NAMESPACE}")


# ============================================================
# Secret input helpers
# ============================================================

def read_secret_from_file(prompt):
    """
    Ask for a file path and return its contents.

    This is useful for multiline secrets such as PEM private keys.
    """

    path = input(f"  {prompt} file path: ").strip()

    if not path:
        error("No file path provided.")

    file_path = Path(path).expanduser()

    if not file_path.is_file():
        error(f"File not found: {file_path}")

    try:
        value = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        error(f"Could not read '{file_path}': {exc}")

    if not value:
        error(f"File '{file_path}' is empty.")

    # Remove only trailing newlines.
    # Internal newlines in PEM files are preserved.
    return value.rstrip("\r\n")


def get_secret_input(config):
    """Read a prompted secret according to its configured mode."""

    prompt = config["prompt"]
    mode = config.get("mode", "prompt")

    if mode == "prompt":
        return getpass(f"  {prompt}: ")

    if mode == "file":
        return read_secret_from_file(prompt)

    error(f"Unknown input mode '{mode}' for '{prompt}'.")


# ============================================================
# KV v2 helpers
# ============================================================

def secret_api_path():
    """Return the KV v2 API path for the configured secret."""

    return f"{SECRET_MOUNT}/data/{SECRET_KEY.strip('/')}"


def read_secret():
    """Return the configured KV v2 secret, or None when it is absent."""

    response = api_request("GET", secret_api_path())
    if response.status_code == 404:
        return None

    raise_for_error(response, "Failed to read secret.")
    data = response_json(response)
    if data is None:
        error("OpenBao returned an invalid JSON response.")
    return data


def secret_values(secret):
    """Extract values from a KV v2 response."""

    try:
        return secret["data"]["data"]
    except (KeyError, TypeError):
        error("Unexpected OpenBao KV v2 response format.")


def write_secret(secret_data):
    """Create or update the configured KV v2 secret."""

    response = api_request(
        "POST",
        secret_api_path(),
        json={"data": secret_data},
    )
    raise_for_error(response, "Failed to store secrets.")


# ============================================================
# Initialise secrets
# ============================================================

def initialise():
    print()
    print("Secrets initialisation")
    print("=" * 46)
    print(f"  OpenBao URL       : {OPENBAO_ADDR}")
    print(f"  OpenBao namespace : {BAO_NAMESPACE}")
    print(f"  KV mount          : {SECRET_MOUNT}")
    print(f"  Secret key        : {SECRET_KEY}")
    print()

    authenticate()
    existing = read_secret()
    if existing is not None:
        existing_keys = sorted(secret_values(existing))
        warn("Secrets already exist — keys: " + ", ".join(existing_keys))
        confirm = input("Overwrite existing secrets? [y/N] ").strip().lower()
        if confirm != "y":
            info("Existing secrets preserved")
            return

    secret_data = {
        key: generator()
        for key, generator in GENERATED_KEYS.items()
    }
    if secret_data:
        info("Generated: " + ", ".join(sorted(secret_data)))

    if PROMPTED_KEYS:
        print()
        info("Enter application secrets:")
    for key, config in PROMPTED_KEYS.items():
        secret_data[key] = get_secret_input(config)

    info(
        f"Storing secrets at "
        f"{BAO_NAMESPACE}/{SECRET_MOUNT}/{SECRET_KEY}..."
    )
    try:
        write_secret(secret_data)
    finally:
        secret_data.clear()

    info("Secrets stored successfully")
    stored = read_secret()
    if stored is None:
        error("Secret was not found after being written.")
    info("Verifying secret keys...")
    for key in sorted(secret_values(stored)):
        print(f"  ✓ {key}")

    print()
    print(f"{GREEN}{'=' * 46}{RESET}")
    print(f"{GREEN}Secrets initialised successfully{RESET}")
    print(f"{GREEN}{'=' * 46}{RESET}")
    print()


# ============================================================
# Get one secret
# ============================================================

def get_secret(key):
    authenticate()
    stored = read_secret()
    if stored is None:
        error(
            f"No secrets found at "
            f"{BAO_NAMESPACE}/{SECRET_MOUNT}/{SECRET_KEY}."
        )

    value = secret_values(stored).get(key)
    if value is None:
        error(
            f"Key '{key}' not found at "
            f"{BAO_NAMESPACE}/{SECRET_MOUNT}/{SECRET_KEY}"
        )
    print(value)


# ============================================================
# Renew token
# ============================================================

def renew_token():
    authenticate()
    response = api_request("POST", "auth/token/renew-self", json={})
    raise_for_error(response, "Token renewal failed.")
    data = response_json(response)
    try:
        ttl = data["auth"]["lease_duration"]
    except (KeyError, TypeError):
        error("OpenBao did not return a token lease duration.")

    days, remainder = divmod(ttl, 86400)
    hours = remainder // 3600
    info(f"Token renewed — new TTL: {days}d {hours}h")


# ============================================================
# Entry point
# ============================================================

def main():
    args = sys.argv[1:]
    if not args:
        initialise()
    elif len(args) == 2 and args[0] == "--get":
        get_secret(args[1])
    elif args == ["--renew"]:
        renew_token()
    else:
        print(f"Usage: {sys.argv[0]} [--get <key>] [--renew]")
        sys.exit(1)


if __name__ == "__main__":
    main()
