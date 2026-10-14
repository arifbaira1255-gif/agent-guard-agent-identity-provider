"""AgentGuard Step 6 - production mTLS and service-to-service trust.

Built ON the Step 4 SPIFFE/SPIRE adapter (SpiffeIdentityProvider: X509Source, TrustBundleStore,
verify_x509_svid) - it adds no second workload-identity system. Authentication only; application
authorization (RBAC) is Step 8.
"""
from .authenticator import CertDenylist, PeerAuthenticator, PeerIdentity
from .config import SAFE_TLS12_CIPHERS, MtlsConfig
from .endpoint import MtlsEndpoint
from .errors import M, MtlsConfigError, MtlsError, PeerRejected, PlaintextForbidden
from .metrics import MtlsMetrics
from .policy import (PeerRules, PolicyHolder, TrustPolicy, load_signed_policy, sign_policy)
from .server import HealthServer, MtlsServer

__all__ = ["MtlsConfig", "SAFE_TLS12_CIPHERS", "MtlsEndpoint", "MtlsServer", "HealthServer", "TrustPolicy",
           "PeerRules", "PolicyHolder", "sign_policy", "load_signed_policy", "PeerAuthenticator",
           "PeerIdentity", "CertDenylist", "MtlsMetrics", "MtlsError", "MtlsConfigError",
           "PeerRejected", "PlaintextForbidden", "M"]
