"""Is the supplied root domain really the organization's root domain?

Input lists are not always right. Strong findings mean the supplied domain is
almost certainly not the root to use; advisory findings point at a possible
parent domain. The run always continues with the supplied domain; the output
flags the problem and names the suggested real root.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from .collectors.web import chain_domains
from .data import load as load_data
from .domains import clean, label, registrable
from .models import Fingerprint


@dataclass
class RootCheck:
    supplied: str
    seed: str
    status: str = "ok"  # ok | wrong | advisory
    suggested: str = ""
    reasons: list[str] = field(default_factory=list)  # strong findings
    advisories: list[str] = field(default_factory=list)  # possible-parent hints
    corroboration: list[str] = field(default_factory=list)  # what else points at `suggested`
    normalized: str = ""  # "you supplied www.x.com; using x.com"

    @property
    def flagged(self) -> bool:
        return self.status != "ok"

    def headline(self) -> str:
        if self.status == "wrong":
            s = f"SUPPLIED ROOT DOMAIN {self.seed} LOOKS WRONG: " + "; ".join(self.reasons)
        elif self.status == "advisory":
            s = f"CHECK THE ROOT DOMAIN {self.seed}: " + "; ".join(self.advisories)
        else:
            return ""
        if self.suggested:
            s += f". Suggested real root: {self.suggested}"
            s += f" (corroborated: {'; '.join(self.corroboration)})" if self.corroboration else " (not corroborated: check manually)"
        return s

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["headline"] = self.headline()
        return d


def _brand_overlap(a: str, b: str) -> bool:
    la, lb = label(a).lower(), label(b).lower()
    return len(la) >= 3 and len(lb) >= 3 and (la in lb or lb in la)


def _corroborate(fp: Fingerprint, target: str) -> list[str]:
    from .collectors.tls import covers

    out = []
    if _brand_overlap(fp.domain, target):
        out.append("same brand in both names")
    if any(registrable(h) == target for h in fp.ns):
        out.append(f"{fp.domain}'s nameservers are under {target}")
    if any(registrable(h) == target for h in fp.mx):
        out.append(f"{fp.domain}'s mail servers are under {target}")
    if any(registrable(h) == target for h in fp.www_cname):
        out.append(f"www.{fp.domain} is an alias of {target}")
    if fp.cert.fetched and fp.cert.has_scts and (covers(fp.cert.sans, target) or covers(fp.cert.sans, "www." + target)):
        out.append(f"{fp.domain}'s TLS certificate also covers {target}")
    if target in fp.web.csp_domains:
        out.append(f"{fp.domain}'s Content-Security-Policy trusts {target}")
    return out


def check_root(supplied: str, fp: Fingerprint) -> RootCheck:
    from .verify import registrar_site

    data = load_data()
    seed = fp.domain
    rc = RootCheck(supplied=supplied, seed=seed)
    if clean(supplied) != seed:
        rc.normalized = f"supplied {supplied!r}; using its registrable domain {seed}"

    if fp.registered is False:
        rc.reasons.append("it is not registered (DNS says the name does not exist)")
        rc.status = "wrong"
        return rc

    hops = chain_domains(fp.web)
    later = [h for h in hops if h != seed]
    parking = [h for h in fp.ns + later if data.is_parking_host(h)]
    if parking or fp.web.parking_marker:
        why = parking[0] if parking else f"page says '{fp.web.parking_marker}'"
        rc.reasons.append(f"it is parked or for sale ({why})")
    held = bool(set(fp.a) & data.holding_ips) or (bool(fp.ns) and all(data.is_holding_ns(h) for h in fp.ns))
    to_registrar = bool(later) and registrar_site(later[-1], fp.rdap.registrar)
    if (held or to_registrar) and not (parking or fp.web.parking_marker):
        rc.reasons.append("it is a registrar holding page (registered but not in use)")
    elif later and not (parking or fp.web.parking_marker):
        target = later[-1]
        rc.reasons.append(f"its website redirects to {target}")
        rc.suggested = target

    canon = registrable(fp.web.canonical_url) if fp.web.canonical_url else None
    if canon and canon != seed and not (parking or held):
        if rc.suggested and canon == rc.suggested:
            rc.corroboration.append(f"its homepage declares {fp.web.canonical_url} as canonical")
        elif not rc.suggested:
            rc.reasons.append(f"its homepage declares its canonical address as {fp.web.canonical_url}")
            rc.suggested = canon

    if rc.reasons:
        rc.status = "wrong"
    else:
        # Advisory: DNS or mail run from another (non-shared) domain.
        parents: Counter[str] = Counter()
        for h in fp.ns:
            r = registrable(h)
            if r and r != seed and not data.is_shared_dns(h) and not data.is_selectable_dns(h):
                parents[r] += 1
        for h in fp.mx:
            r = registrable(h)
            if r and r != seed and not data.is_shared_mail(h):
                parents[r] += 1
        for parent, _ in parents.most_common():
            uses = [w for w, hosts in (("nameservers", fp.ns), ("mail servers", fp.mx))
                    if any(registrable(x) == parent for x in hosts)]
            # Only a hint worth showing when both DNS and mail agree, or the
            # names share the brand (keeps small mail/DNS providers out).
            if len(uses) == 2 or _brand_overlap(seed, parent):
                rc.advisories.append(f"its {' and '.join(uses)} are run from {parent} (a parent organization's domain?)")
                rc.suggested = rc.suggested or parent
                break
        if not fp.web.fetched and not fp.mx and not later:
            rc.advisories.append("it has no website and no mail (not in active use?)")
        if rc.advisories:
            rc.status = "advisory"

    if rc.suggested:
        rc.corroboration = _corroborate(fp, rc.suggested) + rc.corroboration
    return rc
