"""Live-certificate links: SAN overlap, shared public key, identical certificate, and their guards."""

import datetime

from helpers import ADP_NS, cand, fp, rdap, seed_fp, web

from domainfinder.collectors.tls import covers, has_scts, parse_der
from domainfinder.models import CertInfo
from domainfinder.models import Classification as C
from domainfinder.verify import Scorer, SeedProfile, score_all

ORG = "Automatic Data Processing, Inc."
SEED_CERT = CertInfo(fetched=True, sans=["adp.com", "www.adp.com"], sha256="seedcert", spki_sha256="seedkey",
                     has_scts=True)


def scorer(seed_cert=SEED_CERT):
    s = seed_fp()
    s.cert = seed_cert
    return Scorer(SeedProfile.build(s, [ORG], ["adp"]))


def cert(*sans, sha="c1", key="k1", scts=True):
    return CertInfo(fetched=True, sans=list(sans), sha256=sha, spki_sha256=key, has_scts=scts)


def link(r):
    return next((e.detail for e in r.evidence if e.kind == "cert_link"), "")


def test_covers():
    assert covers(["example.com"], "example.com")
    assert covers(["*.example.com"], "www.example.com")
    assert not covers(["*.example.com"], "example.com")  # a wildcard does not cover the apex
    assert not covers(["*.example.com"], "a.b.example.com")
    assert not covers(["other.com"], "example.com")


def test_parse_der_fingerprints_and_sct_detection():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    now = datetime.datetime(2026, 1, 1)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), False)
         .sign(key, hashes.SHA256()))
    info = parse_der(c.public_bytes(serialization.Encoding.DER))
    assert info.sans == ["example.com"] and len(info.sha256) == 64 and len(info.spki_sha256) == 64
    assert info.has_scts is False  # self-signed / intercepted style: no CT timestamps
    assert has_scts(b"xx" + bytes.fromhex("060a2b06010401d679020402") + b"yy")


def test_candidate_cert_covering_the_seed_is_strong():
    r = scorer().score(fp("adpportal.com", cert=cert("adpportal.com", "www.adpportal.com", "adp.com")),
                       cand("adpportal.com"), set())
    assert "also covers adp.com" in link(r)


def test_seed_cert_presented_for_a_name_it_does_not_cover_proves_nothing():
    """Someone points their DNS at ADP's server: the server shows ADP's own certificate."""
    r = scorer().score(fp("typo-adp.com", cert=cert("adp.com", "www.adp.com", sha="seedcert", key="seedkey")),
                       cand("typo-adp.com"), set())
    assert link(r) == ""


def test_identical_certificate_that_covers_the_candidate():
    seed_cert = CertInfo(fetched=True, sans=["adp.com", "myadp.com"], sha256="multi", spki_sha256="seedkey",
                         has_scts=True)
    r = scorer(seed_cert).score(fp("myadp.com", cert=cert("adp.com", "myadp.com", sha="multi", key="seedkey")),
                                cand("myadp.com"), set())
    assert link(r) == "serves the same TLS certificate as adp.com"  # one item, not three


def test_shared_public_key_with_a_different_certificate():
    r = scorer().score(fp("adpworld.de", cert=cert("adpworld.de", "www.adpworld.de", sha="other", key="seedkey")),
                       cand("adpworld.de"), set())
    assert "same public key as adp.com's" in link(r)


def test_no_ct_timestamps_means_no_certificate_evidence():
    """TLS interception: the proxy's certificates (and maybe one key) for every site."""
    proxied_seed = CertInfo(fetched=True, sans=["adp.com"], sha256="p0", spki_sha256="proxykey", has_scts=False)
    r = scorer(proxied_seed).score(
        fp("random.com", cert=cert("random.com", "adp.com", key="proxykey", scts=False)), cand("random.com"), set())
    assert link(r) == ""


def test_shared_hosting_certificate_is_ignored_but_corporate_multidomain_counts():
    unrelated = [f"customer{i}.com" for i in range(10)]
    r = scorer().score(fp("smallshop.com", cert=cert("smallshop.com", "adp.com", *unrelated)),
                       cand("smallshop.com"), set())
    assert link(r) == ""
    ours = ["adp.ca", "adp.co.uk", "adp.nl", "adp.ch"]
    r2 = scorer().score(fp("adp.pl", cert=cert("adp.pl", "adp.com", *ours, "partner.com")),
                        cand("adp.pl"), set(ours))
    assert "also covers" in link(r2)


def test_seed_certificate_covering_the_candidate():
    seed_cert = CertInfo(fetched=True, sans=["adp.com", "adp.ca"], sha256="s", spki_sha256="sk", has_scts=True)
    r = scorer(seed_cert).score(fp("adp.ca"), cand("adp.ca"), set())
    assert link(r) == "adp.com's TLS certificate also covers it"
    shared_seed = CertInfo(fetched=True, sans=["adp.com", "adp.ca"] + [f"x{i}.com" for i in range(10)],
                           sha256="s", spki_sha256="sk", has_scts=True)
    assert link(scorer(shared_seed).score(fp("adp.ca"), cand("adp.ca"), set())) == ""


def test_key_shared_with_a_verified_domain_is_found_in_the_next_round():
    s = scorer()
    items = [
        # workmarket.com: verified on infrastructure; its certificate uses key "wmkey"
        (fp("workmarket.com", ns=sorted(ADP_NS), mail_tenants=["proofpoint:0006eb01"],
            cert=cert("workmarket.com", key="wmkey")), cand("workmarket.com")),
        # wm.solutions: only link is a certificate with the same key + registration
        (fp("wm.solutions", rdap=rdap(), cert=cert("wm.solutions", key="wmkey", sha="c2")), cand("wm.solutions")),
    ]
    res = {r.domain: r for r in score_all(s, items)}
    assert res["workmarket.com"].classification is C.OWNED
    assert "same public key as workmarket.com's" in link(res["wm.solutions"])
