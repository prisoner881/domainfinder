"""GLEIF (Global Legal Entity Identifier Foundation): who belongs to the
seed organization's corporate family.

GLEIF lists no domains, so it never finds any. It is used for names:

* the seed's own entity (found only by one exact legal-name match, checked
  against the seed's registrant country when several entities share a
  name) and the legal names of the companies it consolidates (its
  "ultimate children"), which then count as the organization's names;
* whether a name found on one of our domains belongs to the family before it
  drives the acquisition search (a joint-venture partner does not);
* whether the seed's entity is itself a subsidiary of another organization,
  which the report states loudly. The family only goes down: a parent and its
  other subsidiaries are not the seed's organization.

Free JSON API, no key: https://api.gleif.org/api/v1
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from ..http import Http, json_answer
from ..orgnames import is_meaningful, normalize

API = "https://api.gleif.org/api/v1"
TTL = 7 * 86400
PAGE = 200
MAX_CHILDREN = 1000
DEAD = {"RETIRED", "ANNULLED", "DUPLICATE", "MERGED"}


@dataclass
class Entity:
    lei: str
    legal_name: str
    other_names: list[str] = field(default_factory=list)
    country: str = ""
    status: str = ""

    def to_dict(self) -> dict:
        return {"lei": self.lei, "legal_name": self.legal_name, "other_names": self.other_names,
                "country": self.country, "status": self.status}


@dataclass
class Family:
    """The seed's entity, its parents (if any) and its consolidated subsidiaries."""

    entity: Entity
    children: list[Entity] = field(default_factory=list)
    direct_parent: Entity | None = None
    ultimate_parent: Entity | None = None

    def names(self) -> list[str]:
        """Names that count as the organization's: the entity's other names
        and its subsidiaries' legal and other names."""
        out: list[str] = []
        seen: set[str] = set()
        for n in [self.entity.legal_name, *self.entity.other_names] + [
                x for c in self.children for x in (c.legal_name, *c.other_names)]:
            k = normalize(n)
            if n and k not in seen and is_meaningful(n):
                seen.add(k)
                out.append(n)
        return out

    def leis(self) -> set[str]:
        return {self.entity.lei} | {c.lei for c in self.children}

    def parent(self) -> Entity | None:
        return self.ultimate_parent or self.direct_parent


def _entity(rec: dict) -> Entity | None:
    a = rec.get("attributes") if isinstance(rec, dict) else None
    if not isinstance(a, dict):
        return None
    e = a.get("entity") or {}
    others = [o.get("name", "") for o in (e.get("otherNames") or []) + (e.get("transliteratedOtherNames") or [])
              if isinstance(o, dict) and o.get("name")]
    return Entity(lei=a.get("lei", ""), legal_name=(e.get("legalName") or {}).get("name", ""), other_names=others,
                  country=((e.get("legalAddress") or {}).get("country") or ""),
                  status=((a.get("registration") or {}).get("status") or ""))


# Legal-form words only (not "group" or "holdings", which name different
# entities): 'Example Corp, Inc.' and 'Example Corp' are one name, 'Example
# Corp Group' another.
LEGAL_FORMS = {"inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation", "co", "company", "plc", "lp",
               "llp", "sa", "ag", "se", "nv", "bv", "gmbh", "kg", "srl", "spa", "sas", "sarl", "lda", "oy", "ab", "as",
               "aps", "pte", "pty", "kk", "sl", "sau", "unlimited"}


def _loose(name: str) -> str:
    toks = re.sub(r"[^a-z0-9]+", " ", unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore")
                  .decode().lower()).split()
    while toks and toks[-1] in LEGAL_FORMS:
        toks.pop()
    return " ".join(toks)


def _strict(name: str) -> str:
    """Letters and digits only, legal suffixes kept: 'Example Corp, Inc.' ≠
    'Example Corp Limited' (normalize() would make them equal)."""
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


async def _get(http: Http, path: str, params: dict | None = None) -> dict | None:
    r = await http.get(f"{API}/{path}", params=params, headers={"Accept": "application/vnd.api+json"}, ttl=TTL,
                       timeout=30, retries=2, valid=lambda resp: json_answer(resp, "data"))
    if not r.ok:
        return None
    try:
        d = r.json()
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


async def find_entity(http: Http, name: str, country: str = "") -> tuple[Entity | None, str]:
    """The one entity whose legal (or other) name is exactly `name`, or None
    with the reason. GLEIF's name filter is fuzzy, so exactness is checked
    here: first with legal suffixes kept, then with them stripped and the
    seed's registrant country breaking ties. Several equally good matches
    count as none."""
    d = await _get(http, "lei-records", {"filter[entity.legalName]": name, "page[size]": "50"})
    if d is None:
        return None, "GLEIF did not answer"
    ents = [e for e in (_entity(x) for x in d.get("data") or []) if e and e.lei and e.status not in DEAD]

    def names(e: Entity) -> list[str]:
        return [e.legal_name, *e.other_names]

    strict = [e for e in ents if any(_strict(n) == _strict(name) for n in names(e))]
    loose = [e for e in ents if _loose(name) and any(_loose(n) == _loose(name) for n in names(e))]
    for pool in (strict, loose):
        if country and len(pool) > 1:
            same = [e for e in pool if e.country.upper() == country.upper()]
            pool = same or pool
        if len(pool) == 1:
            return pool[0], ""
        if len(pool) > 1:
            return None, f"{len(pool)} entities named {name!r}; none chosen"
    return None, f"no entity named exactly {name!r}"


async def family(http: Http, entity: Entity) -> Family:
    fam = Family(entity=entity)
    for rel in ("direct-parent", "ultimate-parent"):
        d = await _get(http, f"lei-records/{entity.lei}/{rel}")
        p = _entity(d.get("data")) if d else None
        if p and p.lei and p.lei != entity.lei:
            setattr(fam, rel.replace("-", "_"), p)
    page = 1
    while len(fam.children) < MAX_CHILDREN:
        d = await _get(http, f"lei-records/{entity.lei}/ultimate-children",
                       {"page[size]": str(PAGE), "page[number]": str(page)})
        if not d:
            break
        fam.children += [e for e in (_entity(x) for x in d.get("data") or []) if e and e.status not in DEAD]
        last = ((d.get("meta") or {}).get("pagination") or {}).get("lastPage") or 1
        if page >= last:
            break
        page += 1
    return fam


async def seed_family(http: Http, org_names: list[str], country: str = "") -> tuple[Family | None, str]:
    """Find the seed's entity from its organization names (first exact hit)
    and load its family. Returns (family or None, note)."""
    reasons = []
    for name in org_names[:3]:
        ent, why = await find_entity(http, name, country)
        if ent:
            fam = await family(http, ent)
            return fam, ""
        reasons.append(why)
    return None, "; ".join(dict.fromkeys(reasons)) or "no organization name to look up"


async def name_outside_family(http: Http, name: str, fam: Family) -> Entity | None:
    """The entity `name` exactly names, if GLEIF places it outside the family
    (its own ultimate parent, or a parent that is not ours). None when GLEIF
    does not know the name, or it is in the family."""
    ent, _ = await find_entity(http, name)
    if ent is None or ent.lei in fam.leis():
        return None
    return ent
