"""HashiCorp Vault Transit provider (Ed25519) — the production cloud-KMS adapter.

STATUS: validated against a REAL Vault `transit` secrets engine (dev server, see
docs/KMS_HSM.md and tests/test_kms_vault.py). It has NOT been exercised against a
managed Vault Enterprise cluster / HCP Vault, nor is a cloud account provisioned here.

Custody model
-------------
Keys are created with `exportable=false`, so the private key is generated inside Vault
and can never be read back — signing happens server-side. The public key is the only
material we pull back, and only to embed as the verification key in a passport/issuer
certificate.

Wire API (no heavy SDK dependency — plain HTTP so the adapter stays auditable):
  create : POST   {addr}/v1/{mount}/keys/{name}          {"type":"ed25519", ...}
  read   : GET    {addr}/v1/{mount}/keys/{name}
  sign   : POST   {addr}/v1/{mount}/sign/{name}          {"input": b64(raw bytes)}
  destroy: POST   {addr}/v1/{mount}/keys/{name}/config   {"deletion_allowed":true}
           DELETE {addr}/v1/{mount}/keys/{name}
"""
import base64
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Optional, Tuple

from ..errors import (KeyCollisionError, KeyNotFoundError, KmsConfigError,
                      ProviderPermissionError, ProviderRateLimitedError,
                      ProviderResponseError, ProviderTimeoutError,
                      ProviderUnavailableError)
from ..interfaces import CryptoBackend
from ..models import KeyAlgorithm, ProviderHealth

_ED25519_PUB_LEN = 32
_ED25519_SIG_LEN = 64
_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def _safe_name(prefix: str, key_id: str) -> str:
    """Vault key names must be path-safe; key_ids are generated internally already."""
    cleaned = "".join(c if c in _SAFE else "-" for c in key_id)
    if not cleaned:
        raise ProviderResponseError("empty key name")
    return f"{prefix}-{cleaned}" if prefix else cleaned


class HttpTransport:
    """Thin, injectable HTTP transport (tests inject a fake to simulate failures)."""

    def __init__(self, *, tls_verify: bool = True, ca_cert: str = ""):
        self._tls_verify = tls_verify
        self._ca_cert = ca_cert or None

    def request(self, url: str, method: str, headers: dict, body: Optional[bytes],
                timeout: float) -> Tuple[int, dict]:
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        ctx = None
        if url.lower().startswith("https"):
            ctx = ssl.create_default_context(cafile=self._ca_cert)
            if not self._tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                payload = json.loads(raw) if raw else {}
            except Exception:
                payload = {"raw": raw[:200].decode("utf-8", "replace")}
            return e.code, payload


class VaultTransitBackend(CryptoBackend):
    name = "vault"
    exportable = False

    def __init__(self, *, addr: str, token: str, mount: str = "transit",
                 prefix: str = "agentguard", namespace: str = "", tls_verify: bool = True,
                 ca_cert: str = "", timeout: float = 5.0, exportable: bool = False,
                 transport=None):
        if not addr:
            raise KmsConfigError("vault provider requires an address")
        if not token:
            raise KmsConfigError("vault provider requires a token")
        self._addr = addr.rstrip("/")
        self._token = token
        self._mount = mount.strip("/")
        self._prefix = prefix
        self._namespace = namespace
        self._timeout = float(timeout)
        self._exportable = bool(exportable)
        self._transport = transport or HttpTransport(tls_verify=tls_verify, ca_cert=ca_cert)

    # ------------------------------------------------------------------ backend
    def generate(self, key_id: str, algorithm: KeyAlgorithm) -> Tuple[bytes, dict]:
        self._require(algorithm)
        name = _safe_name(self._prefix, key_id)
        # Explicit existence check: Vault's create is an upsert, so we must detect
        # collisions ourselves rather than silently adopting a foreign key.
        status, _ = self._call("GET", f"/v1/{self._mount}/keys/{name}", None, ok=(200, 404))
        if status == 200:
            raise KeyCollisionError("key id already exists in Vault")
        body = {"type": "ed25519", "exportable": self._exportable,
                "allow_plaintext_backup": False}
        status, _ = self._call("POST", f"/v1/{self._mount}/keys/{name}", body,
                               ok=(200, 204))
        pub = self._read_public(name)
        return pub, {"ref": name}

    def public(self, key_id, external_ref, algorithm) -> bytes:
        self._require(algorithm)
        return self._read_public(external_ref or _safe_name(self._prefix, key_id))

    def sign(self, key_id, external_ref, algorithm, data: bytes) -> bytes:
        self._require(algorithm)
        name = external_ref or _safe_name(self._prefix, key_id)
        payload = {"input": base64.b64encode(data).decode("ascii"), "prehashed": False}
        status, resp = self._call("POST", f"/v1/{self._mount}/sign/{name}", payload, ok=(200,))
        sig = (((resp or {}).get("data") or {}).get("signature"))
        if not isinstance(sig, str) or not sig.startswith("vault:v"):
            raise ProviderResponseError("vault returned no signature")
        try:
            b64 = sig.split(":", 2)[2]
            raw = base64.b64decode(b64, validate=True)
        except Exception:
            raise ProviderResponseError("vault signature is not valid base64") from None
        if len(raw) != _ED25519_SIG_LEN:
            raise ProviderResponseError("vault signature is not Ed25519-sized")
        return raw

    def destroy(self, key_id, external_ref) -> None:
        name = external_ref or _safe_name(self._prefix, key_id)
        status, _ = self._call("GET", f"/v1/{self._mount}/keys/{name}", None, ok=(200, 404))
        if status == 404:
            return                                    # already gone: idempotent
        self._call("POST", f"/v1/{self._mount}/keys/{name}/config",
                   {"deletion_allowed": True}, ok=(200, 204))
        self._call("DELETE", f"/v1/{self._mount}/keys/{name}", None, ok=(200, 204))

    def health(self) -> ProviderHealth:
        start = time.time()
        try:
            status, _ = self._call("GET", "/v1/sys/health", None,
                                   ok=(200, 429, 472, 473, 501, 503))
            latency = round((time.time() - start) * 1000, 2)
            # 200 = active, 429 = standby, 472/473 = DR/perf standby: all usable reads
            return ProviderHealth(healthy=status in (200, 429, 472, 473),
                                  provider=self.name, checked_at=time.time(),
                                  latency_ms=latency, detail=f"http {status}")
        except Exception as e:  # noqa: BLE001 - health must never raise
            return ProviderHealth(healthy=False, provider=self.name, checked_at=time.time(),
                                  detail=type(e).__name__)

    # ----------------------------------------------------------------- internals
    def _read_public(self, name: str) -> bytes:
        status, resp = self._call("GET", f"/v1/{self._mount}/keys/{name}", None, ok=(200, 404))
        if status == 404:
            raise KeyNotFoundError("key not found in Vault")
        data = (resp or {}).get("data") or {}
        keys_map = data.get("keys") or {}
        latest = data.get("latest_version")
        entry = keys_map.get(str(latest)) if latest is not None else None
        if entry is None and keys_map:
            entry = keys_map[max(keys_map, key=lambda k: int(k))]
        pub_b64 = (entry or {}).get("public_key")
        if not isinstance(pub_b64, str):
            raise ProviderResponseError("vault key response has no public_key")
        try:
            raw = base64.b64decode(pub_b64, validate=True)
        except Exception:
            raise ProviderResponseError("vault public key is not valid base64") from None
        if len(raw) != _ED25519_PUB_LEN:
            raise ProviderResponseError("vault public key is not a raw Ed25519 key")
        return raw

    def _call(self, method: str, path: str, body: Optional[dict],
              ok: Tuple[int, ...]) -> Tuple[int, dict]:
        url = f"{self._addr}{path}"
        headers = {"X-Vault-Token": self._token, "Accept": "application/json"}
        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            status, resp = self._transport.request(url, method, headers, payload, self._timeout)
        except socket.timeout:
            raise ProviderTimeoutError("vault request timed out") from None
        except (urllib.error.URLError, OSError) as e:
            raise ProviderUnavailableError(f"vault unreachable: {type(e).__name__}") from None
        if status in ok:
            return status, (resp if isinstance(resp, dict) else {})
        # --- non-accepted status: map to a precise, non-leaking error ---
        errors = (resp or {}).get("errors") if isinstance(resp, dict) else None
        detail = "; ".join(str(x) for x in errors[:2]) if isinstance(errors, list) else ""
        if status in (400, 403):
            raise ProviderPermissionError(f"vault denied the operation ({status})")
        if status == 404:
            raise KeyNotFoundError("vault reports the key does not exist")
        if status == 429:
            raise ProviderRateLimitedError("vault rate limited the request")
        if status >= 500:
            raise ProviderUnavailableError(f"vault unavailable ({status})")
        raise ProviderResponseError(f"vault returned unexpected status {status}: {detail[:120]}")

    @staticmethod
    def _require(algorithm: KeyAlgorithm) -> None:
        if algorithm is not KeyAlgorithm.ED25519:
            from ..errors import UnsupportedAlgorithmError
            raise UnsupportedAlgorithmError(f"vault provider does not support {algorithm}")

    def __repr__(self) -> str:
        return f"VaultTransitBackend(addr={self._addr!r}, mount={self._mount!r}, <redacted>)"
