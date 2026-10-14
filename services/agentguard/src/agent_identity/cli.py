"""AgentGuard CLI -- a thin, scriptable client over the Phase 8 management API (``/v2/*``).

Design
------
* **No business logic.** Every command is a thin wrapper over a documented ``/v2`` route; the CLI
  never re-implements authorization, tenant isolation or policy evaluation. It cannot bypass
  server-side authorization because it holds no authority of its own -- it only carries a session
  token the server verifies.
* **No embedded secrets.** The token comes from ``--token``, ``$AGENTGUARD_TOKEN`` or a token file
  (``--token-file``, mode-checked). Nothing is written to disk by default.
* **Machine-readable.** ``--json`` emits the raw API payload on stdout; human output goes to stdout
  and diagnostics to stderr, so ``agentguard ... --json | jq`` works.
* **Honest exit codes.** 0 ok, 2 usage, 3 auth, 4 forbidden, 5 not found, 6 rate-limited,
  7 server/transport error, 1 other.
* **Safe by default.** High-impact operations (agent suspend, approval decide, retention apply)
  require ``--yes``; without it the CLI refuses and exits 2. ``--non-interactive`` is the documented
  automation mode and never prompts.

Usage::

    agentguard --base-url https://agentguard.internal login --email a@b.c --password ...
    agentguard --token "$T" agents list --limit 20 --json
    agentguard --token "$T" audit verify
    agentguard --token "$T" --yes agents suspend agt_123 --reason administrative_action
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

CLI_VERSION = "0.1.0"

# --------------------------------------------------------------------------- exit codes
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_FORBIDDEN = 4
EXIT_NOT_FOUND = 5
EXIT_RATE_LIMITED = 6
EXIT_SERVER = 7

_STATUS_TO_EXIT = {400: EXIT_USAGE, 401: EXIT_AUTH, 403: EXIT_FORBIDDEN, 404: EXIT_NOT_FOUND,
                   409: EXIT_ERROR, 413: EXIT_USAGE, 429: EXIT_RATE_LIMITED, 500: EXIT_SERVER,
                   503: EXIT_SERVER}


class CliError(Exception):
    def __init__(self, message: str, code: int = EXIT_ERROR):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------- HTTP client
class ApiClient:
    """A minimal stdlib HTTP client for the management API. Never logs the token."""

    def __init__(self, base_url: str, token: Optional[str] = None, *, timeout: float = 30.0,
                 verify_tls: bool = True):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.verify_tls = verify_tls

    def request(self, method: str, path: str, *, query: Optional[dict] = None,
                body: Optional[dict] = None, csrf: Optional[str] = None) -> Tuple[int, Any]:
        url = self.base_url + path
        if query:
            clean = {k: v for k, v in query.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if csrf:
            req.add_header("X-CSRF-Token", csrf)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8") or "{}"
                return resp.status, _maybe_json(raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8") or "{}"
            return e.code, _maybe_json(raw)
        except urllib.error.URLError as e:
            raise CliError(f"transport error: {e.reason}", EXIT_SERVER)
        except Exception as e:                                       # noqa: BLE001
            raise CliError(f"request failed: {e}", EXIT_SERVER)


def _maybe_json(raw: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return {"raw": raw}


# --------------------------------------------------------------------------- output
def _emit(payload: Any, *, as_json: bool, human: Optional[str] = None) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(human if human is not None else json.dumps(payload, indent=2, default=str))


def _table(rows: List[dict], columns: List[str]) -> str:
    if not rows:
        return "(no results)"
    widths = {c: len(c) for c in columns}
    for r in rows:
        for c in columns:
            widths[c] = max(widths[c], len(str(r.get(c, ""))[:48]))
    header = "  ".join(c.ljust(widths[c]) for c in columns)
    sep = "  ".join("-" * widths[c] for c in columns)
    lines = [header, sep]
    for r in rows:
        lines.append("  ".join(str(r.get(c, ""))[:48].ljust(widths[c]) for c in columns))
    return "\n".join(lines)


def _page_rows(payload: Any) -> List[dict]:
    if isinstance(payload, dict):
        for key in ("items", "agents", "policies", "incidents", "approvals", "audit", "alerts",
                    "destinations", "deliveries", "correlations", "recommendations", "proposals",
                    "controls", "checkpoints", "resources", "tools"):
            if isinstance(payload.get(key), list):
                return payload[key]
    if isinstance(payload, list):
        return payload
    return []


# --------------------------------------------------------------------------- token resolution
def _resolve_token(args) -> Optional[str]:
    if getattr(args, "token", None):
        return args.token
    env = os.environ.get("AGENTGUARD_TOKEN")
    if env:
        return env
    tf = getattr(args, "token_file", None)
    if tf:
        try:
            mode = os.stat(tf).st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                print(f"warning: token file {tf} is group/world accessible", file=sys.stderr)
            with open(tf, "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as e:
            raise CliError(f"cannot read token file: {e}", EXIT_USAGE)
    return None


# --------------------------------------------------------------------------- commands
def _cmd_login(client: ApiClient, args) -> int:
    if not args.email or not args.password:
        raise CliError("login requires --email and --password", EXIT_USAGE)
    status, payload = client.request("POST", "/v1/auth/login",
                                     body={"email": args.email, "password": args.password,
                                           "org_id": args.org_id})
    if status != 200:
        return _fail(status, payload, args)
    token = payload.get("access_token")
    csrf = payload.get("csrf_token")
    if args.json:
        _emit({"user": payload.get("user"), "session": payload.get("session"),
               "expires_in": payload.get("expires_in")}, as_json=True)
    else:
        print(f"logged in as {payload.get('user', {}).get('email')} "
              f"(org={payload.get('user', {}).get('org_id')})")
        print("export AGENTGUARD_TOKEN=<access_token>   # token not printed for safety")
    if args.save_token:
        with open(args.save_token, "w", encoding="utf-8") as fh:
            fh.write(token or "")
        os.chmod(args.save_token, 0o600)
        print(f"token written to {args.save_token} (mode 0600)", file=sys.stderr)
    if csrf and not args.json:
        print(f"csrf_token={csrf}", file=sys.stderr)
    return EXIT_OK


def _cmd_session(client: ApiClient, args) -> int:
    status, payload = client.request("GET", "/v2/session")
    if status != 200:
        return _fail(status, payload, args)
    if args.json:
        _emit(payload, as_json=True)
    else:
        print(f"user:        {payload.get('user_id')}")
        print(f"org:         {payload.get('org_id')}")
        print(f"roles:       {', '.join(payload.get('roles', []))}")
        print(f"permissions: {len(payload.get('permissions', []))} granted")
    return EXIT_OK


def _cmd_agents(client: ApiClient, args) -> int:
    if args.action == "list":
        status, payload = client.request("GET", "/v2/agents",
                                         query={"limit": args.limit, "offset": args.offset,
                                                "status": args.status, "agent_type": args.agent_type,
                                                "q": args.q})
        if status != 200:
            return _fail(status, payload, args)
        rows = _page_rows(payload)
        _emit(payload, as_json=args.json,
              human=_table(rows, ["agent_id", "agent_name", "agent_type", "status", "owner"]))
        return EXIT_OK
    if args.action == "get":
        status, payload = client.request("GET", f"/v2/agents/{args.agent_id}")
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json)
        return EXIT_OK
    if args.action == "health":
        status, payload = client.request("GET", f"/v2/agents/{args.agent_id}/health")
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json)
        return EXIT_OK
    if args.action == "suspend":
        if not _confirm(args, f"suspend agent {args.agent_id}"):
            return EXIT_USAGE
        status, payload = client.request("POST", f"/v2/agents/{args.agent_id}/suspend",
                                         body={"reason": args.reason}, csrf=args.csrf)
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json, human=f"suspended {args.agent_id}")
        return EXIT_OK
    raise CliError(f"unknown agents action: {args.action}", EXIT_USAGE)


def _cmd_policies(client: ApiClient, args) -> int:
    if args.action == "list":
        status, payload = client.request("GET", "/v2/policies",
                                         query={"limit": args.limit, "offset": args.offset})
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json,
              human=_table(_page_rows(payload), ["policy_id", "name", "status", "active_version"]))
        return EXIT_OK
    if args.action == "versions":
        status, payload = client.request("GET", f"/v2/policies/{args.policy_id}/versions")
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json,
              human=_table(_page_rows(payload), ["version", "status", "checksum", "created_at"]))
        return EXIT_OK
    if args.action == "simulate":
        cases = _load_cases(args.cases_file)
        status, payload = client.request("POST", f"/v2/policies/{args.policy_id}/simulate",
                                         body={"version": args.version, "cases": cases},
                                         csrf=args.csrf)
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json)
        return EXIT_OK
    raise CliError(f"unknown policies action: {args.action}", EXIT_USAGE)


def _load_cases(path: Optional[str]) -> List[dict]:
    if not path:
        raise CliError("--cases-file is required for simulate", EXIT_USAGE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        raise CliError(f"cannot read cases file: {e}", EXIT_USAGE)
    if isinstance(data, dict) and isinstance(data.get("cases"), list):
        data = data["cases"]
    if not isinstance(data, list) or not data:
        raise CliError("cases file must contain a non-empty list", EXIT_USAGE)
    return data


def _cmd_incidents(client: ApiClient, args) -> int:
    if args.action == "list":
        status, payload = client.request("GET", "/v2/incidents",
                                         query={"limit": args.limit, "offset": args.offset,
                                                "status": args.status})
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json,
              human=_table(_page_rows(payload), ["incident_id", "title", "severity", "status"]))
        return EXIT_OK
    if args.action == "get":
        status, payload = client.request("GET", f"/v2/incidents/{args.incident_id}")
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json)
        return EXIT_OK
    raise CliError(f"unknown incidents action: {args.action}", EXIT_USAGE)


def _cmd_approvals(client: ApiClient, args) -> int:
    if args.action == "list":
        status, payload = client.request("GET", "/v2/approvals",
                                         query={"limit": args.limit, "offset": args.offset,
                                                "status": args.status})
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json,
              human=_table(_page_rows(payload), ["approval_id", "agent_id", "action", "status"]))
        return EXIT_OK
    if args.action == "decide":
        if args.approve is None:
            raise CliError("decide requires --approve or --deny", EXIT_USAGE)
        if not _confirm(args, f"{'approve' if args.approve else 'deny'} approval "
                              f"{args.approval_id}"):
            return EXIT_USAGE
        status, payload = client.request("POST", f"/v2/approvals/{args.approval_id}/decide",
                                         body={"approved": bool(args.approve),
                                               "reason": args.reason or ""}, csrf=args.csrf)
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json, human=f"approval {args.approval_id} decided")
        return EXIT_OK
    raise CliError(f"unknown approvals action: {args.action}", EXIT_USAGE)


def _cmd_audit(client: ApiClient, args) -> int:
    if args.action == "list":
        status, payload = client.request("GET", "/v2/audit",
                                         query={"limit": args.limit, "offset": args.offset})
        if status != 200:
            return _fail(status, payload, args)
        _emit(payload, as_json=args.json,
              human=_table(_page_rows(payload), ["ts", "event", "actor_user_id", "outcome"]))
        return EXIT_OK
    if args.action == "verify":
        status, payload = client.request("GET", "/v2/audit/integrity")
        if status != 200:
            return _fail(status, payload, args)
        if args.json:
            _emit(payload, as_json=True)
        elif payload.get("available") is False:
            # Honest: the plane is not configured -- this is NOT a verification failure.
            print(f"audit integrity: UNAVAILABLE ({payload.get('reason', 'not configured')})")
        else:
            ok = payload.get("ok")
            print(f"audit integrity: {'OK' if ok else 'FAILED'}")
            for k in ("records", "verified", "first_bad", "reason"):
                if k in payload:
                    print(f"  {k}: {payload[k]}")
        if payload.get("available") is False:
            return EXIT_ERROR
        return EXIT_OK if payload.get("ok") else EXIT_ERROR
    raise CliError(f"unknown audit action: {args.action}", EXIT_USAGE)


def _cmd_health(client: ApiClient, args) -> int:
    status, payload = client.request("GET", "/v2/health")
    if status != 200:
        return _fail(status, payload, args)
    if args.json:
        _emit(payload, as_json=True)
    else:
        print(f"status: {payload.get('status')}")
        for d in payload.get("dependencies", []):
            print(f"  dep {d.get('name')}: {'up' if d.get('up') else 'DOWN'}")
        for name, ok in (payload.get("planes") or {}).items():
            print(f"  plane {name}: {'configured' if ok else 'not configured'}")
    return EXIT_OK if payload.get("status") == "ok" else EXIT_ERROR


def _cmd_metrics(client: ApiClient, args) -> int:
    path = "/v2/metrics/prometheus" if args.prometheus else "/v2/metrics"
    status, payload = client.request("GET", path)
    if status != 200:
        return _fail(status, payload, args)
    if args.prometheus:
        print(payload.get("raw", "") if isinstance(payload, dict) else payload)
    else:
        _emit(payload, as_json=args.json)
    return EXIT_OK


def _cmd_config(client: ApiClient, args) -> int:
    """Validate local CLI configuration and reachability (no secrets printed)."""
    problems = []
    if not client.base_url.startswith(("http://", "https://")):
        problems.append("base-url must start with http:// or https://")
    if not client.token:
        problems.append("no token configured (--token / $AGENTGUARD_TOKEN / --token-file)")
    reachable = False
    if not problems:
        try:
            status, _ = client.request("GET", "/v2/livez")
            reachable = status == 200
            if not reachable:
                problems.append(f"liveness probe returned {status}")
        except CliError as e:
            problems.append(str(e))
    out = {"base_url": client.base_url, "token_configured": bool(client.token),
           "reachable": reachable, "problems": problems, "ok": not problems}
    _emit(out, as_json=args.json,
          human=("configuration OK" if not problems else "configuration problems:\n  " +
                 "\n  ".join(problems)))
    return EXIT_OK if not problems else EXIT_USAGE


def _cmd_resources(client: ApiClient, args) -> int:
    status, payload = client.request("GET", "/v2/resources",
                                     query={"limit": args.limit, "offset": args.offset})
    if status != 200:
        return _fail(status, payload, args)
    _emit(payload, as_json=args.json,
          human=_table(_page_rows(payload), ["resource_id", "resource_type", "sensitivity", "owner"]))
    return EXIT_OK


def _cmd_tools(client: ApiClient, args) -> int:
    status, payload = client.request("GET", "/v2/tools",
                                     query={"limit": args.limit, "offset": args.offset})
    if status != 200:
        return _fail(status, payload, args)
    _emit(payload, as_json=args.json,
          human=_table(_page_rows(payload), ["tool_id", "name", "status", "capabilities"]))
    return EXIT_OK


def _cmd_events(client: ApiClient, args) -> int:
    status, payload = client.request("GET", "/v2/alerts",
                                     query={"limit": args.limit, "offset": args.offset,
                                            "state": args.state})
    if status != 200:
        return _fail(status, payload, args)
    _emit(payload, as_json=args.json,
          human=_table(_page_rows(payload), ["alert_id", "severity", "state", "rule_id"]))
    return EXIT_OK


# --------------------------------------------------------------------------- helpers
def _confirm(args, what: str) -> bool:
    if getattr(args, "yes", False):
        return True
    if getattr(args, "non_interactive", False):
        print(f"refusing to {what} in non-interactive mode without --yes", file=sys.stderr)
        return False
    if not sys.stdin.isatty():
        print(f"refusing to {what} without --yes (stdin is not a TTY)", file=sys.stderr)
        return False
    try:
        reply = input(f"About to {what}. Type 'yes' to confirm: ").strip().lower()
    except EOFError:
        return False
    return reply == "yes"


def _fail(status: int, payload: Any, args) -> int:
    code = _STATUS_TO_EXIT.get(status, EXIT_ERROR)
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        err = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(err, dict):
            print(f"error: {err.get('code')}: {err.get('message')}", file=sys.stderr)
        else:
            print(f"error: HTTP {status}", file=sys.stderr)
    return code


# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentguard",
                                description="AgentGuard management CLI (Phase 8).")
    p.add_argument("--version", action="version", version=f"agentguard {CLI_VERSION}")
    p.add_argument("--base-url", default=os.environ.get("AGENTGUARD_BASE_URL",
                                                        "http://127.0.0.1:8443"))
    p.add_argument("--token", default=None, help="bearer token (prefer $AGENTGUARD_TOKEN)")
    p.add_argument("--token-file", default=None, help="read the token from a file (mode 0600)")
    p.add_argument("--csrf", default=os.environ.get("AGENTGUARD_CSRF"), help="CSRF token")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--yes", action="store_true", help="confirm high-impact operations")
    p.add_argument("--non-interactive", action="store_true",
                   help="never prompt; refuse high-impact ops without --yes")
    p.add_argument("--timeout", type=float, default=30.0)
    sub = p.add_subparsers(dest="command", required=True)

    # login
    lg = sub.add_parser("login", help="authenticate and obtain a session token")
    lg.add_argument("--email", required=True)
    lg.add_argument("--password", required=True)
    lg.add_argument("--org-id", dest="org_id", default=None)
    lg.add_argument("--save-token", dest="save_token", default=None,
                    help="write the access token to this file (mode 0600)")
    lg.set_defaults(func=_cmd_login)

    sub.add_parser("session", help="show the current session").set_defaults(func=_cmd_session)

    # agents
    ag = sub.add_parser("agents", help="agent administration")
    ags = ag.add_subparsers(dest="action", required=True)
    a1 = ags.add_parser("list"); a1.add_argument("--limit", type=int, default=50)
    a1.add_argument("--offset", type=int, default=0); a1.add_argument("--status", default=None)
    a1.add_argument("--agent-type", dest="agent_type", default=None); a1.add_argument("--q", default=None)
    a1.set_defaults(func=_cmd_agents)
    a2 = ags.add_parser("get"); a2.add_argument("agent_id"); a2.set_defaults(func=_cmd_agents)
    a3 = ags.add_parser("health"); a3.add_argument("agent_id"); a3.set_defaults(func=_cmd_agents)
    a4 = ags.add_parser("suspend"); a4.add_argument("agent_id")
    a4.add_argument("--reason", default="administrative_action"); a4.set_defaults(func=_cmd_agents)

    # policies
    po = sub.add_parser("policies", help="policy administration")
    pos = po.add_subparsers(dest="action", required=True)
    p1 = pos.add_parser("list"); p1.add_argument("--limit", type=int, default=50)
    p1.add_argument("--offset", type=int, default=0); p1.set_defaults(func=_cmd_policies)
    p2 = pos.add_parser("versions"); p2.add_argument("policy_id"); p2.set_defaults(func=_cmd_policies)
    p3 = pos.add_parser("simulate"); p3.add_argument("policy_id")
    p3.add_argument("--version", type=int, required=True)
    p3.add_argument("--cases-file", dest="cases_file", required=True)
    p3.set_defaults(func=_cmd_policies)

    # resources / tools
    rs = sub.add_parser("resources", help="governed resources")
    rs.add_argument("--limit", type=int, default=50); rs.add_argument("--offset", type=int, default=0)
    rs.set_defaults(func=_cmd_resources)
    tl = sub.add_parser("tools", help="tool registry")
    tl.add_argument("--limit", type=int, default=50); tl.add_argument("--offset", type=int, default=0)
    tl.set_defaults(func=_cmd_tools)

    # events
    ev = sub.add_parser("events", help="security alerts / events")
    ev.add_argument("--limit", type=int, default=50); ev.add_argument("--offset", type=int, default=0)
    ev.add_argument("--state", default=None); ev.set_defaults(func=_cmd_events)

    # incidents
    inc = sub.add_parser("incidents", help="incident investigation")
    incs = inc.add_subparsers(dest="action", required=True)
    i1 = incs.add_parser("list"); i1.add_argument("--limit", type=int, default=50)
    i1.add_argument("--offset", type=int, default=0); i1.add_argument("--status", default=None)
    i1.set_defaults(func=_cmd_incidents)
    i2 = incs.add_parser("get"); i2.add_argument("incident_id"); i2.set_defaults(func=_cmd_incidents)

    # approvals
    ap = sub.add_parser("approvals", help="approval workflow")
    aps = ap.add_subparsers(dest="action", required=True)
    ap1 = aps.add_parser("list"); ap1.add_argument("--limit", type=int, default=50)
    ap1.add_argument("--offset", type=int, default=0); ap1.add_argument("--status", default=None)
    ap1.set_defaults(func=_cmd_approvals)
    ap2 = aps.add_parser("decide"); ap2.add_argument("approval_id")
    g = ap2.add_mutually_exclusive_group(required=True)
    g.add_argument("--approve", dest="approve", action="store_true", default=None)
    g.add_argument("--deny", dest="approve", action="store_false", default=None)
    ap2.add_argument("--reason", default=""); ap2.set_defaults(func=_cmd_approvals)

    # audit
    au = sub.add_parser("audit", help="audit records and integrity")
    aus = au.add_subparsers(dest="action", required=True)
    au1 = aus.add_parser("list"); au1.add_argument("--limit", type=int, default=50)
    au1.add_argument("--offset", type=int, default=0); au1.set_defaults(func=_cmd_audit)
    aus.add_parser("verify").set_defaults(func=_cmd_audit)

    # health / metrics / config
    sub.add_parser("health", help="system health").set_defaults(func=_cmd_health)
    me = sub.add_parser("metrics", help="operational metrics")
    me.add_argument("--prometheus", action="store_true"); me.set_defaults(func=_cmd_metrics)
    sub.add_parser("config", help="validate CLI configuration").set_defaults(func=_cmd_config)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        token = _resolve_token(args)
        client = ApiClient(args.base_url, token, timeout=args.timeout)
        return args.func(client, args)
    except CliError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":                                           # pragma: no cover
    sys.exit(main())
