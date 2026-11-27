"""[3] Compare a candidate's fingerprint with the seed's and score it.

Every rule appends an Evidence item, so the output always says *why* a
domain was kept, sent to review or rejected. Weights live in WEIGHTS; the
classification rules are in classify().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .collectors.dnsinfo import rname_domain
from .collectors.web import chain_domains
from .data import load as load_data
from .domains import is_subdomain_of, label, registrable
from .models import Candidate, Classification, Evidence, Fingerprint, Netblock, Result, Strength
from .orgnames import any_match, is_meaningful, normalize, same_org
from .sources.base import CtOrgHit

S, M, W, N, I = Strength.STRONG, Strength.MEDIUM, Strength.WEAK, Strength.NEGATIVE, Strength.INFO

WEIGHTS = {
    "redirect": 60,
    "namespace": 50,
    "ns_set": 50,
    "ns_set_partial": 25,
    "mail_tenant": 50,
    "mx_host": 45,
    "netblock": 50,
    "token": 50,
    "cert_org": 50,
    "rdap_org": 60,
    "ct_org_current": 45,
    "ct_org_historic": 15,
    "analytics": 25,
    "spf_seed": 35,
    "spf_shared": 20,
    "soa_rname": 25,
    "registrar_region": 10,
    "held_brand": 55,
    "held": 40,
    "held_brand_registrar": 35,
    "brand_label": 5,
    "brand_org": 10,
    "subsidiary": 10,
    "seed_link": 5,
    "seed_link_brand": 35,
    "parked": -50,
    "different_org_rdap": -40,
    "different_org_cert": -20,
    "foreign_redirect": -10,
}
# Strong evidence that comes from shared *infrastructure* (vs. paperwork).
INFRA_KINDS = {"redirect", "namespace", "ns_set", "mail_tenant", "mx_host", "netblock", "token"}


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def registrar_site(target: str, registrar: str) -> bool:
    """Is `target` the registrar's own website? Derived from the registrar's
    name, not a list: "Markmonitor Inc." → markmonitor.com, "GoDaddy.com, LLC"
    → godaddy.com, "CSC Corporate Domains, Inc." → csc*.com."""
    lab = label(target).lower()
    # "GoDaddy.com" → "godaddy": a trailing ".com" is part of the brand, not a word.
    toks = [t for t in normalize(registrar).split() if t not in ("com", "net", "org", "co", "io")]
    if not lab or not toks:
        return False
    compact = "".join(toks)
    first = toks[0]
    return lab == compact or lab == first or (len(first) >= 3 and lab.startswith(first) and len(toks) > 1
                                              and lab != first and len(lab) <= len(first) + 8)


def initials(name: str) -> str:
    return "".join(t[0] for t in normalize(name).split() if t)


def plausible_org_for_label(org: str, brand: str) -> bool:
    """'Automatic Data Processing, Inc.' is plausible for 'adp' (initials)."""
    n = normalize(org).replace(" ", "")
    return bool(brand) and (brand in n or initials(org) == brand or n.startswith(brand))


@dataclass
class SeedProfile:
    fp: Fingerprint
    org_names: list[str]
    brand_labels: list[str]
    infra_orgs: list[str] = field(default_factory=list)
    netblocks: list[Netblock] = field(default_factory=list)
    ns_shared_override: bool = False  # a paid source says the NS set is mass-used

    @classmethod
    def build(cls, fp: Fingerprint, org_names: list[str], brand_labels: list[str]) -> "SeedProfile":
        data = load_data()
        p = cls(fp=fp, org_names=org_names, brand_labels=brand_labels)
        for nb in fp.netblocks:
            if nb.org and not data.is_shared_hosting_org(nb.org):
                p.netblocks.append(nb)
                if nb.org not in p.infra_orgs:
                    p.infra_orgs.append(nb.org)
            elif nb.org and any_match(nb.org, org_names):
                p.netblocks.append(nb)
        return p


class Scorer:
    def __init__(
        self,
        seed: SeedProfile,
        high_threshold: int = 70,
        review_threshold: int = 40,
        ct_org_domains: dict[str, CtOrgHit] | None = None,
        subsidiary_names: dict[str, str] | None = None,
    ):
        self.seed = seed
        self.high = high_threshold
        self.review = review_threshold
        self.ct = ct_org_domains or {}
        self.subs = subsidiary_names or {}
        self.data = load_data()

    # ------------------------------------------------------------------ util
    def _ours(self, domain: str | None, verified: set[str]) -> bool:
        return bool(domain) and (domain == self.seed.fp.domain or domain in verified)

    def _host_ours(self, host: str, verified: set[str], self_domain: str) -> str | None:
        rd = registrable(host)
        if rd and rd != self_domain and self._ours(rd, verified):
            return rd
        return None

    # ----------------------------------------------------------------- rules
    def evidence(self, fp: Fingerprint, cand: Candidate, verified: set[str]) -> tuple[list[Evidence], dict]:
        ev: list[Evidence] = []
        flags = {"parked": False, "held": False, "different_org": "", "registration_match": False,
                 "redirect_target": ""}
        seed = self.seed.fp
        d = fp.domain
        data = self.data

        def add(kind, strength, detail, points=None):
            ev.append(Evidence(kind, strength, WEIGHTS.get(kind, 0) if points is None else points, detail))

        if fp.registered is False:
            add("unregistered", N, "not registered (NXDOMAIN)", 0)
            return ev, flags

        # --- redirects ------------------------------------------------------
        hops = chain_domains(fp.web)
        later = [h for h in hops if h != d]
        ours = [h for h in later if self._ours(h, verified)]
        if ours:
            add("redirect", S, f"redirects to {ours[0]}")
        elif later:
            target = later[-1]
            flags["redirect_target"] = target
            if any(data.is_parking_host(h) for h in later):
                pass  # handled by the parking rule
            elif registrar_site(target, fp.rdap.registrar):
                # Registrars park unused client domains by redirecting them to
                # their own site: a holding signal, not an unrelated company.
                flags["registrar_redirect"] = target
                add("registrar_redirect", I, f"redirects to its registrar's own site ({target}): registered, unused", 0)
            else:
                add("foreign_redirect", N, f"redirects to unrelated {target}")

        # --- infrastructure in the seed's own namespace ---------------------
        ns_ours = sorted({r for r in (self._host_ours(h, verified, d) for h in fp.ns) if r})
        mx_ours = sorted({r for r in (self._host_ours(h, verified, d) for h in fp.mx) if r})
        cn_ours = sorted({r for r in (self._host_ours(h, verified, d) for h in fp.www_cname) if r})
        bits = []
        if ns_ours:
            bits.append(f"nameservers under {ns_ours[0]}")
        if mx_ours:
            bits.append(f"MX under {mx_ours[0]}")
        if cn_ours:
            bits.append(f"www CNAME to {cn_ours[0]}")
        if bits:
            add("namespace", S, "; ".join(bits))

        # --- nameserver set ---------------------------------------------------
        seed_ns, cand_ns = set(seed.ns), set(fp.ns)
        if seed_ns and cand_ns and not ns_ours:
            inter = seed_ns & cand_ns
            j = jaccard(seed_ns, cand_ns)
            own = {h for h in inter if not data.is_shared_dns(h) and not data.is_selectable_dns(h)}
            sel = {h for h in inter if data.is_selectable_dns(h)}
            if self.seed.ns_shared_override:
                if inter:
                    add("ns_shared", I, "NS set is used by very many domains (paid source); ignored", 0)
            elif own and j >= 0.5:
                add("ns_set", S, f"same dedicated nameservers ({len(inter)}/{len(seed_ns)} shared, e.g. {sorted(own)[0]})")
            elif len(sel) >= 3 and j >= 0.75:
                add("ns_set", S, f"same managed-DNS nameserver set ({len(inter)}/{len(seed_ns)} hosts, Jaccard {j:.2f})")
            elif len(sel) >= 3 and j >= 0.5:
                add("ns_set_partial", M, f"overlapping managed-DNS nameserver set (Jaccard {j:.2f})")
            elif inter:
                add("ns_shared", I, f"shares only mass-hosting nameservers ({sorted(inter)[0]}); ignored", 0)

        # --- mail -------------------------------------------------------------
        tenants = set(seed.mail_tenants) & set(fp.mail_tenants)
        if tenants:
            add("mail_tenant", S, f"same mail tenant {sorted(tenants)[0]}")
        else:
            dedicated = {
                h for h in set(seed.mx) & set(fp.mx)
                if not data.is_shared_mail(h) and registrable(h) not in (d,) and not mx_ours
            }
            if dedicated:
                add("mx_host", S, f"same dedicated MX host {sorted(dedicated)[0]}")

        # --- netblocks ----------------------------------------------------------
        for nb in fp.netblocks:
            om = any_match(nb.org, self.seed.org_names) if nb.org else None
            same_handle = any(nb.handle and nb.handle == s.handle and nb.start == s.start for s in self.seed.netblocks)
            infra = any_match(nb.org, self.seed.infra_orgs) if nb.org else None
            if om:
                add("netblock", S, f"IP in {nb.label()}")
                break
            if not data.is_shared_hosting_org(nb.org) and (same_handle or infra):
                add("netblock", S, f"IP in seed's netblock {nb.label()}")
                break

        # --- TXT tokens -------------------------------------------------------
        toks = set(seed.verification_tokens) & set(fp.verification_tokens)
        if toks:
            t = sorted(toks)[0]
            add("token", S, f"same TXT verification token {t[:60]}")

        # --- organization names -------------------------------------------------
        if fp.cert.subject_org and is_meaningful(fp.cert.subject_org):
            if any_match(fp.cert.subject_org, self.seed.org_names):
                add("cert_org", S, f"TLS certificate O={fp.cert.subject_org}")
            elif self._brand_org(fp.cert.subject_org):
                add("brand_org", W, f"TLS certificate O={fp.cert.subject_org} carries the brand name")
            elif not data.is_shared_hosting_org(fp.cert.subject_org):
                flags["different_org"] = flags["different_org"] or fp.cert.subject_org
                add("different_org_cert", N, f"TLS certificate issued to {fp.cert.subject_org}")
        rorg = fp.rdap.registrant_org
        if rorg and is_meaningful(rorg) and data.is_proxy_registrant(rorg, fp.rdap.registrar):
            add("proxy_registrant", I, f"RDAP registrant '{rorg}' is the registrar or a proxy; ignored", 0)
        elif rorg and is_meaningful(rorg):
            if any_match(rorg, self.seed.org_names):
                add("rdap_org", S, f"RDAP registrant {rorg}")
                flags["registration_match"] = True
            elif self._brand_org(rorg):
                add("brand_org", W, f"RDAP registrant {rorg} carries the brand name")
            else:
                flags["different_org"] = rorg
                add("different_org_rdap", N, f"RDAP registrant is {rorg}")

        hit = self.ct.get(d)
        if hit and not any(e.kind == "cert_org" for e in ev):
            if hit.current:
                add("ct_org_current", S, f"CT: current certificate O={hit.org} (valid to {hit.latest_not_after[:10]})")
            else:
                add("ct_org_historic", W, f"CT: only expired certificates O={hit.org} (last {hit.latest_not_after[:10]})")

        # --- web tags -------------------------------------------------------------
        ids = set(seed.web.analytics_ids) & set(fp.web.analytics_ids)
        if ids:
            add("analytics", M, f"same analytics/tag ID {sorted(ids)[0]}")

        # --- SPF ------------------------------------------------------------------
        spf_ours = [i for i in fp.spf_includes if self._host_ours(i, verified, d)]
        if spf_ours:
            add("spf_seed", M, f"SPF includes {spf_ours[0]}")
        else:
            common = [
                i for i in set(seed.spf_includes) & set(fp.spf_includes)
                if not data.is_shared_spf(i)
            ]
            if common:
                add("spf_shared", M, f"same org-specific SPF include {sorted(common)[0]}")

        # --- SOA ------------------------------------------------------------------
        rd = rname_domain(fp.soa_rname)
        if rd and rd != d and self._ours(rd, verified):
            add("soa_rname", M, f"SOA contact is at {rd}")

        # --- registration -----------------------------------------------------------
        sr, cr = seed.rdap, fp.rdap
        same_registrar = bool(sr.registrar and cr.registrar) and (
            (sr.registrar_iana_id and sr.registrar_iana_id == cr.registrar_iana_id)
            or normalize(sr.registrar) == normalize(cr.registrar)
        )
        # A proxy registrant (CSC's own name, DNStination, ...) comes with the
        # proxy's address, so its region says nothing about the owner.
        same_region = (
            bool(sr.region_key()) and sr.region_key() == cr.region_key()
            and not data.is_proxy_registrant(sr.registrant_org, sr.registrar)
            and not data.is_proxy_registrant(cr.registrant_org, cr.registrar)
        )
        brand_registrar = self.data.is_brand_registrar(cr.registrar)
        if same_registrar and same_region:
            flags["registration_match"] = True
            if brand_registrar:
                add("registrar_region", W, f"same registrar ({cr.registrar}) and registrant region ({cr.region_key()})")
            else:
                add("registrar_region", I, f"same registrar ({cr.registrar}) and region ({cr.region_key()}); mass-market registrar", 0)

        # --- holding page (registered, unused) ---------------------------------------
        held = bool(set(fp.a) & self.data.holding_ips) or (
            bool(fp.ns) and all(self.data.is_holding_ns(h) for h in fp.ns)
        ) or bool(flags.get("registrar_redirect") and brand_registrar)
        brand = self._brand_in(d)
        if held:
            flags["held"] = True
            if same_registrar and same_region and brand_registrar:
                brand_org = any(e.kind == "brand_org" for e in ev)
                if brand or hit or brand_org:
                    why = ("brand name" if brand else "past certificates in the seed's name" if hit
                           else "registrant carries the brand name")
                    add("held_brand", S, f"held/inactive at the seed's brand-protection registrar, same registrant region, {why}")
                else:
                    add("held", M, "held/inactive at the seed's brand-protection registrar, same registrant region")
            elif same_registrar and brand_registrar and brand:
                add("held_brand_registrar", M, "held/inactive at the seed's brand-protection registrar, brand name "
                    f"(registrant region {cr.region_key() or 'unknown'} ≠ {sr.region_key() or 'unknown'})")
            else:
                add("held_other", I, "registrar holding page", 0)

        # --- parking --------------------------------------------------------------------
        park = [h for h in fp.ns if data.is_parking_host(h)]
        park += [h for h in later if data.is_parking_host(h)]
        if park or fp.web.parking_marker:
            flags["parked"] = True
            why = f"parking/for-sale service {park[0]}" if park else f"parking page ('{fp.web.parking_marker}')"
            add("parked", N, why)

        # --- weak corroboration ------------------------------------------------------------
        if brand:
            add("brand_label", W, f"brand '{brand}' in name")
        if d in self.subs:
            add("subsidiary", W, f"matches SEC subsidiary {self.subs[d]}")
        if "seed-links" in cand.sources:
            if brand:
                # The seed's own site points at a domain carrying its brand:
                # worth a human look (athletics, campaigns), never enough alone.
                add("seed_link_brand", M, cand.sources["seed-links"] + " and carries the brand")
            else:
                add("seed_link", W, cand.sources["seed-links"])
        for h in cand.hints:
            ev.append(h)
        return ev, flags

    def _brand_org(self, org: str) -> bool:
        """'ADP, Inc.' / 'ADP France' for brand 'adp': likely the seed's own
        entity under its short name. Neither a match nor a conflict — 'Groupe ADP'
        or 'Aéroports de Paris' do not start with the brand and stay conflicts."""
        toks = normalize(org).split()
        return bool(toks) and any(len(b) >= 3 and toks[0] == b for b in self.seed.brand_labels)

    def _brand_in(self, domain: str) -> str:
        lab = label(domain)
        for b in self.seed.brand_labels:
            if b and len(b) >= 3 and b in lab:
                return b
        return ""

    # ------------------------------------------------------------ classify
    def classify(self, fp: Fingerprint, ev: list[Evidence], flags: dict) -> tuple[int, Classification, str]:
        status = self.status(fp, flags)
        if fp.registered is False:
            return 0, Classification.REJECTED, status
        strong = {e.kind for e in ev if e.strength is Strength.STRONG}
        infra = strong & INFRA_KINDS
        if flags["different_org"] and len(infra) >= 2:
            # Two independent infrastructure matches outweigh a different legal
            # name: acquisitions keep their old registrant and certificate names.
            for e in ev:
                if e.kind.startswith("different_org"):
                    e.strength, e.points = Strength.INFO, 0
                    e.detail += " (likely subsidiary/acquisition: infrastructure matches)"
        raw = sum(e.points for e in ev)
        score = max(0, min(100, raw))

        if flags["parked"]:
            # Parked yet registered like the seed (e.g. a defensive registration
            # pointed at a marketplace) → a human should look; otherwise reject.
            if flags["registration_match"] or infra:
                return max(min(score, self.high - 1), self.review), Classification.REVIEW, status
            return min(score, self.review - 1), Classification.REJECTED, status

        if flags["different_org"] and len(infra) < 2:
            # Names another organization: never auto-accept without two
            # independent infrastructure matches (acquisitions keep old names).
            if infra or strong:
                # Strong evidence for the seed *and* another organization's
                # name: a person should decide (acquisitions keep old names).
                return max(min(score, self.high - 1), self.review), Classification.REVIEW, status
            return min(score, self.review - 1), Classification.REJECTED, status

        if score >= self.high and strong:
            return score, Classification.OWNED, status
        if score >= self.review and (strong or any(e.strength is Strength.MEDIUM for e in ev)):
            return min(score, self.high - 1), Classification.REVIEW, status
        return min(score, self.review - 1), Classification.REJECTED, status

    def status(self, fp: Fingerprint, flags: dict) -> str:
        if fp.registered is False:
            return "unregistered"
        if flags.get("parked"):
            return "parked"
        if flags.get("held"):
            return "held/inactive"
        hops = chain_domains(fp.web)
        later = [h for h in hops if h != fp.domain]
        if later:
            return f"redirects to {later[-1]}"
        if fp.web.fetched and fp.web.status:
            return f"active (HTTP {fp.web.status})"
        if fp.a or fp.aaaa:
            return "resolves, no web response"
        if fp.mx:
            return "mail only"
        return "registered, no web/mail"

    def score(self, fp: Fingerprint, cand: Candidate, verified: set[str]) -> Result:
        ev, flags = self.evidence(fp, cand, verified)
        score, cls, status = self.classify(fp, ev, flags)
        return Result(
            domain=fp.domain, score=score, classification=cls, status=status,
            evidence=ev, sources=dict(cand.sources), fingerprint=fp,
        )


def score_all(scorer: Scorer, items: list[tuple[Fingerprint, Candidate]], max_rounds: int = 4) -> list[Result]:
    """Score everything, then re-score with newly verified domains until stable.

    "Redirects to a verified domain" and "NS under a verified domain" only
    become visible once the target itself is verified.
    """
    verified: set[str] = set()
    results: list[Result] = []
    for _ in range(max_rounds):
        results = [scorer.score(fp, c, verified - {fp.domain}) for fp, c in items]
        now = {r.domain for r in results if r.classification is Classification.OWNED}
        if now == verified:
            break
        verified = now
    return results
