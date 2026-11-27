"""Paid providers. Stubs today: same interface, off until a key is configured.

Each stub documents the endpoints a full implementation would call, so adding
one is a matter of filling in candidates() (and ns_usage() for reverse-NS
providers). Respect each provider's terms on storing and redistributing data,
and never log the key.
"""

from __future__ import annotations

import logging

from ..models import Candidate
from .base import Source, SourceContext

log = logging.getLogger(__name__)


class _PaidStub(Source):
    paid = True
    key_env: str = ""

    def _key(self) -> str:
        return ""

    def enabled(self) -> bool:
        return bool(self._key())

    def disabled_reason(self) -> str:
        return f"no API key (set {self.key_env})"

    async def candidates(self, ctx: SourceContext) -> list[Candidate]:
        ctx.notes.append(f"{self.name}: key present but the integration is not implemented yet")
        return []


class SecurityTrailsSource(_PaidStub):
    """SecurityTrails (https://docs.securitytrails.com).

    Planned calls (header ``APIKEY``):
      * POST /v1/domains/list  {"filter": {"whois_organization": ORG}}   reverse WHOIS
      * POST /v1/domains/list  {"filter": {"ns": NS_HOST}}               reverse NS (+ count → ns_usage)
      * POST /v1/domains/list  {"filter": {"mx": MX_HOST}}               reverse MX
      * GET  /v1/domain/{seed}/associated                                 associated domains
    """

    name = "securitytrails"
    description = "SecurityTrails: reverse WHOIS / NS / MX, associated domains (paid)"
    key_env = "SECURITYTRAILS_API_KEY"

    def _key(self) -> str:
        return self.settings.securitytrails_key


class DomainToolsSource(_PaidStub):
    """DomainTools Iris Investigate (https://www.domaintools.com/resources/api-documentation/).

    Planned calls (api_username + api_key, HMAC-signed):
      * GET /v1/iris-investigate/?registrant_org=ORG                       reverse WHOIS
      * GET /v1/iris-investigate/?nameserver_host=NS                       NS pivot
      * GET /v1/iris-investigate/?email_domain=SEED                        email pivot
      * passive DNS via Farsight DNSDB where licensed
    """

    name = "domaintools"
    description = "DomainTools Iris: reverse WHOIS, NS/IP/email pivots, passive DNS (paid)"
    key_env = "DOMAINTOOLS_API_USERNAME + DOMAINTOOLS_API_KEY"

    def _key(self) -> str:
        return self.settings.domaintools_key if self.settings.domaintools_user else ""
