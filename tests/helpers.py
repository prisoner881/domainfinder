"""Builders for ADP-like fingerprints used across tests (data from the handoff)."""

from domainfinder.models import Candidate, Fingerprint, Netblock, RdapInfo, WebInfo

ADP_NS = [
    "dns1.p01.nsone.net", "dns2.p01.nsone.net", "dns3.p01.nsone.net", "dns4.p01.nsone.net",
    "a1-199.akam.net", "a5-66.akam.net", "a9-67.akam.net", "a14-65.akam.net", "a18-66.akam.net", "a28-64.akam.net",
]
ADP_MX = ["mxa-0006eb01.gslb.pphosted.com", "mxb-0006eb01.gslb.pphosted.com"]
ESNET = Netblock(handle="NET-170-146-0-0-1", name="ADP-ESNET", start="170.146.0.0", end="170.146.255.255",
                 cidr="170.146.0.0/16", org="Automatic Data Processing, Inc.", rir="arin")
AKAMAI = Netblock(handle="NET-23-0-0-0", name="AKAMAI", start="23.0.0.0", end="23.15.255.255",
                  cidr="23.0.0.0/12", org="Akamai Technologies, Inc.", rir="arin")


def rdap(registrar="Markmonitor Inc.", region="NJ", country="US", org="", iana="292"):
    return RdapInfo(available=True, registrar=registrar, registrar_iana_id=iana, registrant_org=org,
                    registrant_region=region, registrant_country=country)


def seed_fp() -> Fingerprint:
    return Fingerprint(
        domain="adp.com", brand_label="adp", registered=True, ns=sorted(ADP_NS), mx=ADP_MX,
        mail_tenants=["proofpoint:0006eb01"], a=["170.146.93.56"], netblocks=[ESNET],
        spf_includes=["_spf.adp.com"], verification_tokens=["MS=ms96397460"],
        soa_rname="hostmaster.adp.com", rdap=rdap(),
        web=WebInfo(fetched=True, chain=["http://adp.com/", "https://www.adp.com/"],
                    final_url="https://www.adp.com/", status=200, analytics_ids=["gtm:GTM-MMKNHG5"]),
    )


def fp(domain, **kw) -> Fingerprint:
    kw.setdefault("registered", True)
    return Fingerprint(domain=domain, brand_label=domain.split(".")[0], **kw)


def web(*chain, status=200, **kw) -> WebInfo:
    return WebInfo(fetched=True, chain=list(chain), final_url=chain[-1], status=status, **kw)


def cand(domain, *sources) -> Candidate:
    return Candidate(domain=domain, sources={s: "" for s in sources or ("test",)})
