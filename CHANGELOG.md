# Changelog

All notable changes to domainfinder. Versions follow `0.9.x`: every change
gets the next patch number.

## 0.9.1 — 2026-11-26

### Added
- `--import FILE` imports candidate domains found by other processes. Entries
  are separated by commas and/or newlines (CSV quoting understood); `#` starts
  a comment; `-` reads standard input; the option can be repeated. Each entry
  is reduced to its registrable domain (URLs and host names allowed),
  duplicates are merged, and entries that are not domain names are skipped and
  reported. Imported domains are verified exactly like discovered ones, are
  listed with the source `import`, and are never dropped by
  `--max-candidates`.
- `--candidate` accepts comma-separated lists.
- This changelog.

## 0.9 — 2026-11-26

First numbered version. Everything below shipped together as 0.9.

### Added
- Every run prints `domainfinder <version>` first (on stderr, so `--json`
  output stays clean); `--version` prints the same. The version lives in one
  place (`src/domainfinder/__init__.py`).
- WHOIS (port 43) fallback for TLDs without RDAP, used for `.edu` (EDUCAUSE),
  whose records name the institution as registrant. `--no-whois` turns it off.
- A domain linked from the seed's homepage that also carries the brand goes to
  *needs review* instead of being rejected.
- Internationalized domain names are written in readable form by default
  (`adp.信息` rather than `adp.xn--vuq861b`); `--idn punycode` switches back.
  CSV and JSON always carry both forms in `domain_unicode` / `domain_ascii`.
  CSV is written with a UTF-8 byte-order mark so Excel shows it correctly.

### Fixed
- A registrant named after the registrar, a brand-protection registrar or a
  privacy service (CSC writes "CSC Corporate Domains, Inc." into the registrant
  fields it manages) is treated as a proxy: never the owner's name, never an
  ownership match or conflict, and its region is ignored. Previously the
  `globalpayments.com` run credited CSC's own domains to the seed.
- Managed web hosts (Pantheon, Acquia, Kinsta, …) no longer count as
  organization-owned netblocks.
- crt.sh: when one URL form of a query fails (it intermittently answers large
  queries with 404), other forms are tried; failed answers are never cached.
- Silenced a cryptography deprecation warning for certificates with
  non-positive serial numbers.
- The User-Agent no longer links to an unrelated GitHub account.

### Initial release
- Fingerprinting of the seed and every candidate: RDAP (registry, then the
  registrar's server), NS set, MX mail tenant, IP netblock owner, TXT tokens,
  SPF, SOA, homepage redirect chain and tag IDs, TLS certificate O=.
- Free candidate sources: crt.sh by organization and by SANs, ccTLD sweep,
  seed links and CSP, SEC EDGAR Exhibit 21, HackerTarget and ViewDNS reverse
  NS. Paid stubs: SecurityTrails, WhoisXML API, DomainTools.
- Evidence-based scoring with owned / needs review / rejected classes; table,
  CSV and JSON output; on-disk cache; polite per-host rate limits.
