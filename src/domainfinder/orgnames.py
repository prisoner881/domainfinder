"""Organization-name normalization and comparison."""

from __future__ import annotations

import re
import unicodedata

LEGAL_SUFFIXES = {
    "inc", "incorporated", "llc", "llp", "lp", "ltd", "limited", "corp", "corporation", "co",
    "company", "gmbh", "mbh", "ag", "kg", "sa", "sas", "sarl", "srl", "spa", "bv", "nv", "plc",
    "pty", "pte", "oy", "oyj", "ab", "as", "asa", "aps", "kk", "kabushiki", "kaisha", "sl",
    "sro", "zoo", "sp", "ltda", "cv", "de", "the", "holdings", "holding", "group", "intl",
    "international", "pvt", "private", "se", "lda", "bhd", "sdn", "tbk",
}


def normalize(name: str) -> str:
    """'Automatic Data Processing, Inc.' → 'automatic data processing'."""
    if not name:
        return ""
    s = unicodedata.normalize("NFKD", name)
    s = "".join(ch for ch in s if not unicodedata.combining(ch)).lower()
    s = s.replace("&", " and ")
    s = re.sub(r"[^a-z0-9]+", " ", s)
    toks = s.split()
    while toks and toks[-1] in LEGAL_SUFFIXES:
        toks.pop()
    while toks and toks[0] == "the":
        toks.pop(0)
    return " ".join(toks)


def tokens(name: str) -> list[str]:
    return normalize(name).split()


def same_org(a: str, b: str) -> bool:
    """True when two organization names plausibly name the same company.

    Exact match after normalization, or one name's tokens are a leading run of
    the other's with at least two tokens ("Automatic Data Processing" vs
    "Automatic Data Processing Limited"). A single short token ("ADP") only
    matches exactly, so "ADP" ≠ "Aéroports de Paris".
    """
    na, nb = normalize(a), normalize(b)
    if not na or not nb:
        return False
    if na == nb:
        return True
    ta, tb = na.split(), nb.split()
    short, long_ = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    if len(short) < 2 and len("".join(short)) < 10:
        return False
    return long_[: len(short)] == short


def any_match(name: str, names: list[str]) -> str | None:
    for n in names:
        if same_org(name, n):
            return n
    return None


def is_meaningful(name: str) -> bool:
    n = normalize(name)
    return len(n) >= 3 and n not in {"none", "n a", "na", "null", "private", "personal", "individual"}
