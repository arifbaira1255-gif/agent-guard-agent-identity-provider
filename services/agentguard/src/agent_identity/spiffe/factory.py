"""Provider selection. Production never reaches the dev code path (validated + guarded twice)."""
from typing import Optional

from ..adapters.spiffe import IdentityProvider
from .config import SpireConfig
from .errors import ConfigError


def build_identity_provider(service, config: SpireConfig, *, transport=None, **kw) -> IdentityProvider:
    from .provider import SpiffeIdentityProvider
    config.validate()
    if transport is None:
        if config.provider == "dev":
            from .dev import DevSpireCA, DevWorkloadTransport
            transport = DevWorkloadTransport(config, DevSpireCA(config.trust_domain, service.clock))
        else:
            from .workload_api import GrpcTransport
            transport = GrpcTransport(config.socket_path, config.connect_timeout_seconds)
    return SpiffeIdentityProvider(service, config, transport, **kw)
