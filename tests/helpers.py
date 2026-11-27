"""Builders for ZDP-like fingerprints used across tests (data from the handoff)."""

from domainfinder.models import Candidate, Fingerprint, Netblock, RdapInfo, WebInfo

ZDP_NS = [
    "dns1.p01.nsone.net", "dns2.p01.nsone.net", "dns3.p01.nsone.net", "dns4.p01.nsone.net",
    "a1-199.akam.net", "a5-66.akam.net", "a9-67.akam.net", "a14-65.akam.net", "a18-66.akam.net", "a28-64.akam.net",
]
ZDP_MX = ["mxa-0099aa01.gslb.pphosted.com", "mxb-0099aa01.gslb.pphosted.com"]
CORENET = Netblock(handle="NET-198-18-0-0-1", name="ZDP-CORENET", start="198.18.0.0", end="198.18.255.255",
                 cidr="198.18.0.0/16", org="Zyntara Data Processing, Inc.", rir="arin")
AKAMAI = Netblock(handle="NET-23-0-0-0", name="AKAMAI", start="23.0.0.0", end="23.15.255.255",
                  cidr="23.0.0.0/12", org="Akamai Technologies, Inc.", rir="arin")


def rdap(registrar="Markmonitor Inc.", region="OH", country="US", org="", iana="292"):
    return RdapInfo(available=True, registrar=registrar, registrar_iana_id=iana, registrant_org=org,
                    registrant_region=region, registrant_country=country)


def seed_fp() -> Fingerprint:
    return Fingerprint(
        domain="zdp.com", brand_label="zdp", registered=True, ns=sorted(ZDP_NS), mx=ZDP_MX,
        mail_tenants=["proofpoint:0099aa01"], a=["198.18.93.56"], netblocks=[CORENET],
        spf_includes=["_spf.zdp.com"], verification_tokens=["MS=ms12345678"],
        soa_rname="hostmaster.zdp.com", rdap=rdap(),
        web=WebInfo(fetched=True, chain=["http://zdp.com/", "https://www.zdp.com/"],
                    final_url="https://www.zdp.com/", status=200, analytics_ids=["gtm:GTM-ABC1234"]),
    )


def fp(domain, **kw) -> Fingerprint:
    kw.setdefault("registered", True)
    return Fingerprint(domain=domain, brand_label=domain.split(".")[0], **kw)


def web(*chain, status=200, **kw) -> WebInfo:
    return WebInfo(fetched=True, chain=list(chain), final_url=chain[-1], status=status, **kw)


def cand(domain, *sources) -> Candidate:
    return Candidate(domain=domain, sources={s: "" for s in sources or ("test",)})
