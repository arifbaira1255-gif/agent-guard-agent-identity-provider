"""Step 8 unit tests: passwords, tokens, RBAC, sessions, auth service, OIDC validation, admin ops,
audit, and the enterprise HTTP surface. No external services required (MemoryStore + MemoryBackend).
"""
import base64
import json
import os
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

from agent_identity.core.clock import FixedClock
from agent_identity.core.errors import (AuthenticationError, ConflictError, CsrfError, ForbiddenError,
                                        NotFoundError, RateLimitedError, ValidationError)
from agent_identity.observability.logging import SecurityLogger
from agent_identity.security import (AdminOps, AuditLog, EnterpriseAuthConfig, EnterpriseAuthService,
                                     MemoryEnterpriseStore, TokenSigner)
from agent_identity.security import passwords as pw
from agent_identity.security import tokens as tok
from agent_identity.security import rbac
from agent_identity.security.admin_ops import bootstrap_platform_admin
from agent_identity.security.models import (EnterpriseUser, IdpConfig, IdpType, MembershipStatus,
                                            TenantMembership, UserStatus, ROLE_PLATFORM_ADMIN,
                                            ROLE_TENANT_ADMIN, ROLE_SECURITY_ANALYST,
                                            ROLE_SECURITY_OPERATOR, ROLE_DEVELOPER,
                                            ROLE_READONLY_AUDITOR)
from agent_identity.security.oidc import (LoginTxnStore, OidcClient, OidcError, make_pkce_pair,
                                         validate_id_token)
from agent_identity.security.permission_cache import PermissionCache
from agent_identity.security.redis_keys import SecurityKeys
from agent_identity.security.session_manager import SessionManager, csrf_token_for
from agent_identity.state.backend import MemoryBackend

GOOD_PW = "Corr3ct-Horse-Battery!"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class PasswordTests(unittest.TestCase):
    def test_hash_and_verify(self):
        h = pw.hash_password(GOOD_PW, n=2 ** 12)
        self.assertTrue(h.startswith("$scrypt$"))
        self.assertNotIn(GOOD_PW, h)                    # never store the plaintext
        self.assertTrue(pw.verify_password(GOOD_PW, h))
        self.assertFalse(pw.verify_password(GOOD_PW + "x", h))

    def test_malformed_hash_never_raises(self):
        for bad in ("", "not-a-hash", "$scrypt$n=1,r=1,p=1$aaa$bbb", None, "$scrypt$garbage$",):
            self.assertFalse(pw.verify_password(GOOD_PW, bad))

    def test_absurd_parameters_rejected(self):
        # a hostile stored hash with an enormous work factor must be refused (DoS guard)
        hostile = "$scrypt$n=99999999,r=8,p=1$" + b64u(b"0" * 16) + "$" + b64u(b"0" * 32)
        self.assertFalse(pw.verify_password(GOOD_PW, hostile))

    def test_needs_rehash(self):
        h = pw.hash_password(GOOD_PW, n=2 ** 12)
        self.assertTrue(pw.needs_rehash(h, n=2 ** 14))
        self.assertFalse(pw.needs_rehash(h, n=2 ** 12))

    def test_policy(self):
        self.assertIsNotNone(pw.password_policy_error("short"))
        self.assertIsNotNone(pw.password_policy_error("alllowercaseletters"))
        self.assertIsNotNone(pw.password_policy_error("AAAAaaaa1111"))   # only 2 classes
        self.assertIsNotNone(pw.password_policy_error("Abcd1234!xyz"))   # sequential run
        self.assertIsNone(pw.password_policy_error(GOOD_PW))


class TokenTests(unittest.TestCase):
    def setUp(self):
        self.signer = TokenSigner(b"k" * 32, environment="development")
        self.now = 1_800_000_000.0

    def _issue(self, **kw):
        d = dict(user_id="usr_1", session_id="sess_1", org_id="acme", roles=("developer",),
                 is_platform_admin=False, ttl_seconds=900, now=self.now)
        d.update(kw)
        return self.signer.issue(**d)

    def test_roundtrip(self):
        t = self._issue()
        claims = self.signer.verify(t, now=self.now + 10)
        self.assertEqual(claims["sub"], "usr_1")
        self.assertEqual(claims["org"], "acme")

    def test_tamper_detected(self):
        t = self._issue()
        head, body, sig = t.split(".")
        forged_body = b64u(br'{"sub":"attacker"}')
        forged = f"{head}.{forged_body}.{sig}"
        with self.assertRaises(AuthenticationError):
            self.signer.verify(forged, now=self.now)

    def test_expired(self):
        t = self._issue(ttl_seconds=1)
        with self.assertRaises(AuthenticationError):
            self.signer.verify(t, now=self.now + 100)

    def test_wrong_audience_and_issuer(self):
        t = self._issue()
        with self.assertRaises(AuthenticationError):
            self.signer.verify(t, now=self.now, audience="other-api")
        other = TokenSigner(b"k" * 32, issuer="not-agentguard", environment="development")
        with self.assertRaises(AuthenticationError):
            other.verify(t, now=self.now)

    def test_wrong_key_rejected(self):
        t = self._issue()
        attacker = TokenSigner(b"z" * 32, environment="development")
        with self.assertRaises(AuthenticationError):
            attacker.verify(t, now=self.now)

    def test_production_requires_secret(self):
        with self.assertRaises(AuthenticationError):
            TokenSigner(None, environment="production")

    def test_redact_never_returns_raw(self):
        t = self._issue()
        self.assertNotIn(t, tok.redact(t))
        self.assertTrue(tok.redact(t).startswith("sha256:"))


class RbacTests(unittest.TestCase):
    def test_matrix_is_closed_and_sane(self):
        for role, perms in rbac.ROLE_PERMISSIONS.items():
            self.assertTrue(perms.issubset(rbac.PERMISSIONS), role)
        # least privilege: the auditor can never mutate
        self.assertFalse(rbac.ROLE_PERMISSIONS[ROLE_READONLY_AUDITOR] & {
            rbac.P_AGENT_WRITE, rbac.P_CREDENTIAL_ISSUE, rbac.P_CREDENTIAL_REVOKE,
            rbac.P_SESSION_REVOKE, rbac.P_USER_WRITE})

    def test_tenant_admin_cannot_touch_platform(self):
        a = rbac.effective_access("u", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        self.assertFalse(a.has(rbac.P_PLATFORM_ADMIN))
        self.assertFalse(a.has(rbac.P_TENANT_CREATE))
        self.assertTrue(a.has(rbac.P_AGENT_WRITE))

    def test_developer_cannot_revoke(self):
        a = rbac.effective_access("u", "acme", tenant_roles=(ROLE_DEVELOPER,))
        self.assertTrue(a.has(rbac.P_CREDENTIAL_ISSUE))
        self.assertFalse(a.has(rbac.P_CREDENTIAL_REVOKE))
        self.assertFalse(a.has(rbac.P_SESSION_REVOKE))

    def test_explicit_deny_wins(self):
        a = rbac.effective_access("u", "acme", global_roles=(ROLE_PLATFORM_ADMIN,),
                                  deny=(rbac.P_PLATFORM_ADMIN, rbac.P_USER_DELETE))
        self.assertFalse(a.is_platform_admin)
        self.assertFalse(a.has(rbac.P_PLATFORM_ADMIN))
        self.assertFalse(a.has(rbac.P_USER_DELETE))

    def test_unknown_permission_denied(self):
        a = rbac.effective_access("u", "acme", global_roles=(ROLE_PLATFORM_ADMIN,))
        self.assertFalse(a.has("not:a:permission"))

    def test_tenant_membership_rejects_platform_role(self):
        with self.assertRaises(ForbiddenError):
            rbac.sanitize_tenant_roles((ROLE_TENANT_ADMIN, ROLE_PLATFORM_ADMIN))

    def test_global_role_requires_platform_admin(self):
        with self.assertRaises(ForbiddenError):
            rbac.sanitize_global_roles((ROLE_PLATFORM_ADMIN,), actor_is_platform_admin=False)
        self.assertEqual(rbac.sanitize_global_roles((ROLE_PLATFORM_ADMIN,),
                                                    actor_is_platform_admin=True),
                         (ROLE_PLATFORM_ADMIN,))

    def test_authorizer_tenant_boundary(self):
        a = rbac.effective_access("u", "acme", tenant_roles=(ROLE_TENANT_ADMIN,))
        rbac.Authorizer.require(a, rbac.P_AGENT_WRITE, org_id="acme")          # own tenant ok
        with self.assertRaises(ForbiddenError):
            rbac.Authorizer.require(a, rbac.P_AGENT_WRITE, org_id="globex")    # other tenant denied
        padmin = rbac.effective_access("p", None, global_roles=(ROLE_PLATFORM_ADMIN,))
        rbac.Authorizer.require(padmin, rbac.P_AGENT_WRITE, org_id="globex")   # cross-tenant allowed


def _service(clock=None, backend=None, **cfg):
    store = MemoryEnterpriseStore()
    logger = SecurityLogger(use_python_logging=False)
    clock = clock or FixedClock()
    config = EnterpriseAuthConfig(environment="development", session_secret=b"k" * 32,
                                  cookie_secure=False, **cfg)
    backend = backend if backend is not None else MemoryBackend()
    svc = EnterpriseAuthService(store, config, backend=backend, logger=logger, clock=clock)
    return svc, store, clock


def _user(store, *, email="admin@acme.test", global_roles=(), password=GOOD_PW,
          display_name="Admin", status=UserStatus.ACTIVE):
    from agent_identity.security.ids import new_id
    now = 1_800_000_000.0
    u = EnterpriseUser(user_id=new_id("usr"), email=email, display_name=display_name, status=status,
                       is_platform_admin=(ROLE_PLATFORM_ADMIN in global_roles),
                       global_roles=tuple(global_roles),
                       password_hash=(pw.hash_password(password, n=2 ** 12) if password else None),
                       password_changed_at=now, must_change_password=False, failed_login_count=0,
                       locked_until=None, last_login_at=None, created_at=now, created_by="t",
                       updated_at=now)
    store.put_user(u)
    return u


def _member(store, org, user, roles):
    now = 1_800_000_000.0
    store.put_membership(TenantMembership(org, user.user_id, tuple(roles),
                                          MembershipStatus.ACTIVE, now, "t", now))


class SessionTests(unittest.TestCase):
    def test_create_resolve_and_revoke(self):
        svc, store, clock = _service()
        u = _user(store)
        s, access, refresh, csrf = svc.sessions.create(u, org_id=None, auth_method="password")
        claims = svc.sessions.verify_access(access)
        self.assertEqual(claims.user_id, u.user_id)
        sess2, user2 = svc.sessions.resolve(access)
        self.assertEqual(user2.user_id, u.user_id)
        self.assertTrue(svc.sessions.revoke(s.session_id, "logout"))
        with self.assertRaises(AuthenticationError):
            svc.sessions.resolve(access)                     # revoked -> immediate effect

    def test_idle_and_absolute_expiry(self):
        svc, store, clock = _service(access_ttl_s=30, session_idle_ttl_s=60, session_absolute_ttl_s=120)
        u = _user(store)
        s, access, refresh, csrf = svc.sessions.create(u, org_id=None, auth_method="password")
        clock.advance(61)
        with self.assertRaises(AuthenticationError):
            svc.sessions.resolve(access)                     # idle timeout
        s2, access2, r2, c2 = svc.sessions.create(u, org_id=None, auth_method="password")
        clock.advance(121)
        with self.assertRaises(AuthenticationError):
            svc.sessions.resolve(access2)                    # absolute expiry

    def test_refresh_rotation_and_replay_detection(self):
        svc, store, clock = _service()
        u = _user(store)
        s, a1, r1, c1 = svc.sessions.create(u, org_id=None, auth_method="password")
        s2, u2, a2, r2, c2 = svc.sessions.rotate_refresh(r1)
        self.assertNotEqual(r1, r2)
        # replaying the CONSUMED r1 is treated as theft -> whole session revoked
        with self.assertRaises(AuthenticationError):
            svc.sessions.rotate_refresh(r1)
        with self.assertRaises(AuthenticationError):
            svc.sessions.rotate_refresh(r2)
        self.assertEqual(store.get_session(s.session_id).status, "revoked")

    def test_csrf_binding(self):
        svc, store, clock = _service()
        u = _user(store)
        s, access, refresh, csrf = svc.sessions.create(u, org_id=None, auth_method="password")
        self.assertEqual(csrf, csrf_token_for(s.session_id, s.csrf_secret))
        self.assertTrue(svc.check_csrf(access, csrf))
        self.assertFalse(svc.check_csrf(access, "forged"))
        self.assertFalse(svc.check_csrf(access, None))

    def test_token_substitution_rejected(self):
        # two sessions; a token for session A must not resolve against session B
        svc, store, clock = _service()
        u = _user(store)
        sA, aA, rA, cA = svc.sessions.create(u, org_id=None, auth_method="password")
        sB, aB, rB, cB = svc.sessions.create(u, org_id=None, auth_method="password")
        claims = svc.sessions.verify_access(aA)
        self.assertEqual(claims.session_id, sA.session_id)
        # forge a token that names B but is signed with our key: must be caught by session/user check
        forged = svc.signer.issue(user_id="someone-else", session_id=sB.session_id, org_id=None,
                                  roles=(), is_platform_admin=False, ttl_seconds=900, now=clock.now())
        with self.assertRaises(AuthenticationError):
            svc.sessions.resolve(forged)


class LoginTests(unittest.TestCase):
    def test_login_success_and_failure_uniform(self):
        svc, store, clock = _service()
        u = _user(store, global_roles=(ROLE_PLATFORM_ADMIN,))
        user, s, access, refresh, csrf = svc.login("admin@acme.test", GOOD_PW)
        self.assertEqual(user.user_id, u.user_id)
        with self.assertRaises(AuthenticationError) as a:
            svc.login("admin@acme.test", "wrong-password-xx")
        with self.assertRaises(AuthenticationError) as b:
            svc.login("nobody@nowhere.test", "wrong-password-xx")
        self.assertEqual(str(a.exception), str(b.exception))     # no user enumeration

    def test_lockout_after_repeated_failures(self):
        svc, store, clock = _service(max_failed_logins=3)
        _user(store)
        for _ in range(3):
            with self.assertRaises(AuthenticationError):
                svc.login("admin@acme.test", "bad-password-123")
        # a LOCKED account rejects even the CORRECT password (wrong password stays uniform/generic)
        with self.assertRaises(AuthenticationError) as e:
            svc.login("admin@acme.test", GOOD_PW)
        self.assertIn("locked", str(e.exception).lower())

    def test_suspended_account_cannot_login(self):
        svc, store, clock = _service()
        _user(store, status=UserStatus.SUSPENDED)
        with self.assertRaises(AuthenticationError):
            svc.login("admin@acme.test", GOOD_PW)

    def test_rate_limit(self):
        svc, store, clock = _service(login_burst=2, login_rate_per_min=1)
        _user(store)
        errs = []
        for _ in range(5):
            try:
                svc.login("admin@acme.test", "bad")
            except RateLimitedError:
                errs.append("rate")
            except AuthenticationError:
                pass
        self.assertTrue(errs)                                    # at least one 429-like refusal

    def test_tenant_resolution(self):
        svc, store, clock = _service()
        u = _user(store)
        _member(store, "acme", u, (ROLE_DEVELOPER,))
        user, s, a, r, c = svc.login("admin@acme.test", GOOD_PW)
        self.assertEqual(s.org_id, "acme")                       # single membership auto-selected

    def test_switch_tenant_requires_membership(self):
        svc, store, clock = _service()
        u = _user(store)
        _member(store, "acme", u, (ROLE_DEVELOPER,))
        _member(store, "globex", u, (ROLE_SECURITY_OPERATOR,))
        user, s, a, r, c = svc.login("admin@acme.test", GOOD_PW, org_id="acme")
        u2, s2, a2, r2, c2 = svc.switch_tenant(a, "globex")
        self.assertEqual(s2.org_id, "globex")
        with self.assertRaises(ForbiddenError):
            svc.switch_tenant(a2, "other-corp")

    def test_authorize_enforces_permission_and_tenant(self):
        svc, store, clock = _service()
        u = _user(store)
        _member(store, "acme", u, (ROLE_SECURITY_OPERATOR,))
        user, s, a, r, c = svc.login("admin@acme.test", GOOD_PW, org_id="acme")
        ctx = svc.authorize(a, permission=rbac.P_CREDENTIAL_ISSUE)
        self.assertEqual(ctx.org_id, "acme")
        with self.assertRaises(ForbiddenError):
            svc.authorize(a, permission=rbac.P_PLATFORM_ADMIN)     # operator lacks platform admin


class OidcValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        import jwt
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        jwk.update({"kid": "kid-1", "use": "sig", "alg": "RS256"})
        cls.jwks = {"keys": [jwk]}
        cls.issuer = "https://idp.acme.test"
        cls.client_id = "agentguard-client"

    def _token(self, soc="sub-1", aud=None, iss=None, nonce="n-1", exp_delta=300, email="a@acme.test",
               email_verified=True, alg="RS256", kid="kid-1", extra=None):
        import jwt
        now = int(1_800_000_000)
        claims = {"sub": soc, "aud": aud or self.client_id, "iss": iss or self.issuer,
                  "exp": now + exp_delta, "iat": now, "nonce": nonce, "email": email,
                  "email_verified": email_verified}
        if extra:
            claims.update(extra)
        return jwt.encode(claims, self.key, algorithm=alg, headers={"kid": kid})

    def test_happy_path(self):
        t = self._token()
        claims = validate_id_token(t, issuer=self.issuer, audience=self.client_id, jwks=self.jwks,
                                   nonce="n-1", now=1_800_000_010)
        self.assertEqual(claims["_email"], "a@acme.test")

    def test_wrong_nonce(self):
        with self.assertRaises(OidcError):
            validate_id_token(self._token(nonce="other"), issuer=self.issuer, audience=self.client_id,
                              jwks=self.jwks, nonce="n-1", now=1_800_000_010)

    def test_wrong_audience(self):
        with self.assertRaises(OidcError):
            validate_id_token(self._token(aud="someone-else"), issuer=self.issuer,
                              audience=self.client_id, jwks=self.jwks, nonce="n-1",
                              now=1_800_000_010)

    def test_wrong_issuer(self):
        with self.assertRaises(OidcError):
            validate_id_token(self._token(iss="https://evil.test"), issuer=self.issuer,
                              audience=self.client_id, jwks=self.jwks, nonce="n-1",
                              now=1_800_000_010)

    def test_expired(self):
        with self.assertRaises(OidcError):
            validate_id_token(self._token(exp_delta=-100), issuer=self.issuer, audience=self.client_id,
                              jwks=self.jwks, nonce="n-1", now=1_800_000_010)

    def test_alg_none_rejected(self):
        import jwt
        t = jwt.encode({"sub": "x", "aud": self.client_id, "iss": self.issuer, "exp": 1_800_000_999,
                        "iat": 1_800_000_000, "nonce": "n-1", "email": "a@acme.test"},
                       key="", algorithm="none", headers={"kid": "kid-1"})
        with self.assertRaises(OidcError):
            validate_id_token(t, issuer=self.issuer, audience=self.client_id, jwks=self.jwks,
                              nonce="n-1", now=1_800_000_010)

    def test_tampered_signature(self):
        t = self._token()
        head, body, sig = t.split(".")
        tampered = head + "." + body + "." + b64u(b"x" * 256)
        with self.assertRaises(OidcError):
            validate_id_token(tampered, issuer=self.issuer, audience=self.client_id, jwks=self.jwks,
                              nonce="n-1", now=1_800_000_010)

    def test_multi_audience_requires_azp(self):
        t = self._token(aud=[self.client_id, "other"])
        with self.assertRaises(OidcError):                       # azp missing
            validate_id_token(t, issuer=self.issuer, audience=self.client_id, jwks=self.jwks,
                              nonce="n-1", now=1_800_000_010)
        ok = self._token(aud=[self.client_id, "other"], extra={"azp": self.client_id})
        validate_id_token(ok, issuer=self.issuer, audience=self.client_id, jwks=self.jwks,
                          nonce="n-1", now=1_800_000_010)

    def test_email_policy(self):
        with self.assertRaises(OidcError):                       # unverified email refused
            validate_id_token(self._token(email_verified=False), issuer=self.issuer,
                              audience=self.client_id, jwks=self.jwks, nonce="n-1",
                              now=1_800_000_010)
        with self.assertRaises(OidcError):                       # domain not allowed
            validate_id_token(self._token(email="a@evil.test"), issuer=self.issuer,
                              audience=self.client_id, jwks=self.jwks, nonce="n-1",
                              now=1_800_000_010, allowed_email_domains=("acme.test",))

    def test_no_matching_kid(self):
        with self.assertRaises(OidcError):
            validate_id_token(self._token(kid="unknown"), issuer=self.issuer, audience=self.client_id,
                              jwks=self.jwks, nonce="n-1", now=1_800_000_010)


class OidcFlowTests(unittest.TestCase):
    def _idp(self, store, org=None):
        now = 1_800_000_000.0
        cfg = IdpConfig(idp_id="idp-1", org_id=org, idp_type=IdpType.OIDC, issuer="https://idp.acme.test",
                        client_id="agentguard-client", client_secret_ref="TEST_OIDC_SECRET",
                        scopes=("openid", "email"), redirect_uri="https://app.acme.test/cb",
                        jwks_uri="https://idp.acme.test/jwks",
                        authorization_endpoint="https://idp.acme.test/authorize",
                        token_endpoint="https://idp.acme.test/token", created_at=now, created_by="t",
                        updated_at=now)
        store.put_idp(cfg)
        return cfg

    def test_login_txn_single_use(self):
        keys = SecurityKeys("development")
        backend = MemoryBackend()
        txns = LoginTxnStore(backend, keys)
        idp = IdpConfig("idp-1", None, IdpType.OIDC, "https://i.test", "c", "ref", ("openid",),
                        "https://app/cb", "")
        txn = txns.create(idp, code_verifier="v", nonce="n", redirect_uri="https://app/cb",
                          return_to=None, ip=None, user_agent=None, now=100.0, ttl_s=600)
        got = txns.consume_for(None, txn.txn_id, now=101.0)
        self.assertEqual(got.nonce, "n")
        with self.assertRaises(OidcError):
            txns.consume_for(None, txn.txn_id, now=102.0)        # replayed state cannot be consumed

    def test_full_oidc_callback(self):
        svc, store, clock = _service()
        idp = self._idp(store, org=None)
        u = _user(store, email="sso@acme.test", password=None)
        _member(store, "acme", u, (ROLE_SECURITY_ANALYST,))

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        import jwt
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": "kid-1", "use": "sig", "alg": "RS256"})

        state_holder = {}

        def fetcher(url):
            if url.endswith("/.well-known/openid-configuration"):
                return {"issuer": idp.issuer, "authorization_endpoint": idp.authorization_endpoint,
                        "token_endpoint": idp.token_endpoint, "jwks_uri": idp.jwks_uri}
            if url == idp.jwks_uri:
                return {"keys": [jwk]}
            raise AssertionError(url)

        def poster(url, form, headers):
            self.assertEqual(url, idp.token_endpoint)
            self.assertEqual(form["code_verifier"], state_holder["verifier"])
            self.assertEqual(form["client_secret"], "s3cr3t")
            now = int(clock.now())
            it = jwt.encode({"sub": "sso-1", "aud": idp.client_id, "iss": idp.issuer,
                             "exp": now + 300, "iat": now, "nonce": state_holder["nonce"],
                             "email": "sso@acme.test", "email_verified": True},
                            key, algorithm="RS256", headers={"kid": "kid-1"})
            return {"id_token": it, "token_type": "Bearer"}

        os.environ["TEST_OIDC_SECRET"] = "s3cr3t"
        try:
            svc.oidc = OidcClient(fetcher=fetcher, poster=poster, clock=clock,
                                  environment="development")
            url, state = svc.start_oidc_login("idp-1")
            self.assertIn("code_challenge=", url)
            self.assertEqual(state, state_holder.get("state") or state)
            # recover the nonce/verifier the service stored: consume happens inside, so we capture
            # them by reading the transaction before completing.
            raw = svc.login_txns.backend.get(svc.keys.login_txn(None, state))
            d = json.loads(raw.decode())
            state_holder["verifier"] = d["code_verifier"]
            state_holder["nonce"] = d["nonce"]
            user, session, access, refresh, csrf, return_to = svc.complete_oidc_login(
                "idp-1", state, "auth-code-123")
            self.assertEqual(user.email, "sso@acme.test")
            self.assertEqual(session.auth_method, "oidc")
        finally:
            os.environ.pop("TEST_OIDC_SECRET", None)

    def test_callback_rejects_forged_state(self):
        svc, store, clock = _service()
        self._idp(store)
        with self.assertRaises(AuthenticationError):
            svc.complete_oidc_login("idp-1", "never-issued-state", "code")


class AdminOpsTests(unittest.TestCase):
    def _ops(self, svc, store):
        return AdminOps(store, svc.audit, svc.config, permission_cache=svc.permission_cache,
                        sessions=svc.sessions, clock=svc._clock)

    def test_create_user_and_tenant_role_escalation_blocked(self):
        svc, store, clock = _service()
        padmin = _user(store, email="padmin@acme.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        ops = self._ops(svc, store)
        actor = svc.access_for(padmin, None)
        u = ops.create_user(actor, email="dev@acme.test", display_name="Dev", password=GOOD_PW,
                            org_id="acme", tenant_roles=(ROLE_DEVELOPER,))
        self.assertEqual(u.email, "dev@acme.test")
        self.assertIsNotNone(store.get_membership("acme", u.user_id))
        with self.assertRaises(ForbiddenError):                 # platform role via membership denied
            ops.create_user(actor, email="x@acme.test", display_name="X", password=GOOD_PW,
                            org_id="acme", tenant_roles=(ROLE_PLATFORM_ADMIN,))

    def test_tenant_admin_cannot_grant_global_role(self):
        svc, store, clock = _service()
        tadmin = _user(store, email="ta@acme.test")
        _member(store, "acme", tadmin, (ROLE_TENANT_ADMIN,))
        ops = self._ops(svc, store)
        actor = svc.access_for(tadmin, "acme")
        with self.assertRaises(ForbiddenError):
            ops.set_global_roles(actor, tadmin.user_id, (ROLE_PLATFORM_ADMIN,))

    def test_last_platform_admin_cannot_be_removed(self):
        svc, store, clock = _service()
        only = _user(store, email="only@acme.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        ops = self._ops(svc, store)
        actor = svc.access_for(only, None)
        with self.assertRaises(ConflictError):
            ops.set_global_roles(actor, only.user_id, ())        # would remove the last padmin
        with self.assertRaises(ConflictError):
            ops.suspend_user(actor, only.user_id, "test")

    def test_suspend_revokes_sessions_and_invalidates_cache(self):
        svc, store, clock = _service()
        padmin = _user(store, email="p@acme.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        target = _user(store, email="t@acme.test")
        _member(store, "acme", target, (ROLE_DEVELOPER,))
        ops = self._ops(svc, store)
        actor = svc.access_for(padmin, None)
        s, access, _, _ = svc.sessions.create(target, org_id="acme", auth_method="password")
        ops.suspend_user(actor, target.user_id, "compromise")
        self.assertEqual(store.get_session(s.session_id).status, "revoked")
        with self.assertRaises(AuthenticationError):
            svc.sessions.resolve(access)

    def test_last_tenant_admin_cannot_be_demoted(self):
        svc, store, clock = _service()
        padmin = _user(store, email="p@acme.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        ta = _user(store, email="ta@acme.test")
        _member(store, "acme", ta, (ROLE_TENANT_ADMIN,))
        ops = self._ops(svc, store)
        actor = svc.access_for(padmin, None)
        with self.assertRaises(ConflictError):
            ops.set_membership_roles(actor, org_id="acme", user_id=ta.user_id,
                                     roles=(ROLE_DEVELOPER,))

    def test_cannot_manage_platform_admin_across_tenant(self):
        svc, store, clock = _service()
        tadmin = _user(store, email="ta@acme.test")
        _member(store, "acme", tadmin, (ROLE_TENANT_ADMIN,))
        padmin = _user(store, email="p@globex.test", global_roles=(ROLE_PLATFORM_ADMIN,))
        ops = self._ops(svc, store)
        actor = svc.access_for(tadmin, "acme")
        with self.assertRaises(ForbiddenError):
            ops.suspend_user(actor, padmin.user_id, "attempt")

    def test_bootstrap_is_one_time_and_policy_enforced(self):
        svc, store, clock = _service()
        with self.assertRaises(ValidationError):
            bootstrap_platform_admin(store, svc.audit, email="root@acme.test", password="weak")
        u = bootstrap_platform_admin(store, svc.audit, email="root@acme.test", password=GOOD_PW)
        self.assertTrue(u.is_platform_admin)
        self.assertTrue(u.must_change_password)
        with self.assertRaises(ConflictError):
            bootstrap_platform_admin(store, svc.audit, email="root2@acme.test", password=GOOD_PW)


class AuditTests(unittest.TestCase):
    def test_events_recorded_and_secret_free(self):
        svc, store, clock = _service()
        u = _user(store, global_roles=(ROLE_PLATFORM_ADMIN,))
        svc.login("admin@acme.test", GOOD_PW)
        events = store.list_audit(limit=50)
        self.assertTrue(any(e.event == "auth.login.succeeded" for e in events))
        # the structured logger must not carry raw secrets
        for rec in list(svc.logger.events):
            self.assertNotIn(GOOD_PW, json.dumps(rec))

    def test_failed_login_and_denied_are_audited(self):
        svc, store, clock = _service(max_failed_logins=2)
        _user(store)
        with self.assertRaises(AuthenticationError):
            svc.login("admin@acme.test", "bad")
        self.assertTrue(any(e.event == "auth.login.failed" for e in store.list_audit(limit=20)))


class PermissionCacheTests(unittest.TestCase):
    def test_namespacing_and_invalidation(self):
        keys = SecurityKeys("development")
        cache = PermissionCache(MemoryBackend(), keys, ttl_ms=10_000)
        calls = {"n": 0}

        def loader():
            calls["n"] += 1
            return rbac.effective_access("u1", "acme", tenant_roles=(ROLE_DEVELOPER,))

        a1 = cache.get_or_load("acme", "u1", loader)
        a2 = cache.get_or_load("acme", "u1", loader)          # served from cache
        self.assertEqual(calls["n"], 1)
        self.assertTrue(a1.has(rbac.P_CREDENTIAL_ISSUE))
        # a different tenant must NOT read acme's cached entry (separate namespaced key -> reload)
        def loader_globex():
            calls["n"] += 1
            return rbac.effective_access("u1", "globex", tenant_roles=(ROLE_READONLY_AUDITOR,))
        cache.get_or_load("globex", "u1", loader_globex)
        self.assertEqual(calls["n"], 2)
        cache.invalidate("acme", "u1")
        cache.get_or_load("acme", "u1", loader)
        self.assertEqual(calls["n"], 3)                       # evicted -> reload

    def test_cache_failure_falls_back_to_authoritative(self):
        class Broken:
            def get(self, k): raise RuntimeError("redis down")
            def set(self, *a, **k): raise RuntimeError("redis down")
            def delete(self, k): raise RuntimeError("redis down")

        cache = PermissionCache(Broken(), SecurityKeys("development"))
        a = cache.get_or_load("acme", "u1", lambda: rbac.effective_access(
            "u1", "acme", tenant_roles=(ROLE_DEVELOPER,)))
        self.assertTrue(a.has(rbac.P_CREDENTIAL_ISSUE))


class HttpSurfaceTests(unittest.TestCase):
    def _router(self, **cfg):
        svc, store, clock = _service(**cfg)
        ops = AdminOps(store, svc.audit, svc.config, permission_cache=svc.permission_cache,
                       sessions=svc.sessions, clock=clock)
        from agent_identity.api.enterprise_http import EnterpriseRouter
        return EnterpriseRouter(svc, ops, svc.config), svc, store, clock

    def test_login_session_csrf_and_logout(self):
        router, svc, store, clock = self._router()
        _user(store, global_roles=(ROLE_PLATFORM_ADMIN,))
        status, body, cookies = router.handle("POST", "/v1/auth/login",
                                              {"email": "admin@acme.test", "password": GOOD_PW},
                                              {}, {})
        self.assertEqual(status, 200)
        self.assertTrue(any(c.startswith("ag_session=") for c in cookies))
        self.assertTrue(any(c.startswith("ag_csrf=") for c in cookies))
        csrf = body["csrf_token"]
        access = body["access_token"]
        headers = {"Authorization": f"Bearer {access}", "X-CSRF-Token": csrf}
        s, sb, _ = router.handle("GET", "/v1/auth/session", {}, headers, {})
        self.assertEqual(s, 200)
        # missing CSRF on a state-changing route must be refused
        st, bd, _ = router.handle("POST", "/v1/admin/sessions/revoke", {"user_id": "x"}, 
                                  {"Authorization": f"Bearer {access}"}, {})
        self.assertEqual(st, 403)
        st2, bd2, ck = router.handle("POST", "/v1/auth/logout", {}, headers, {})
        self.assertEqual(st2, 200)

    def test_control_plane_permissions_map_is_complete(self):
        from agent_identity.api.enterprise_http import required_permission
        self.assertEqual(required_permission("POST", "/v1/organizations"), rbac.P_TENANT_CREATE)
        self.assertEqual(required_permission("POST", "/v1/agents"), rbac.P_AGENT_WRITE)
        self.assertEqual(required_permission("GET", "/v1/agents/abc"), rbac.P_AGENT_READ)
        self.assertEqual(required_permission("POST", "/v1/credentials/issue"), rbac.P_CREDENTIAL_ISSUE)


if __name__ == "__main__":
    unittest.main()
