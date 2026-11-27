# Changelog

All notable changes to domainfinder. Versions follow `0.9.x`: every change
gets the next patch number.

## 0.9.9 — 2026-11-27

### Added
- `start-venv.sh`: `source start-venv.sh` activates the project's virtual
  environment, creating `.venv` and installing domainfinder (with test
  extras) on first use. Run directly instead of sourced, it says to source
  it, since activation in a child shell would not last.

## 0.9.8 — 2026-11-27

### Changed
- The start-of-run line is now a framed, coloured banner: the name and
  version, plus a line each on what the tool does and how. It is printed on
  stderr as before. When stderr isn't a terminal (logs, pipes, CI) it stays
  the plain `domainfinder <version>` line.

## 0.9.7 — 2026-11-27

### Added
- Root-domain check: before anything else, the tool checks that the supplied
  domain really is the organization's root.
  - **Looks wrong:** not registered; parked or for sale; a registrar holding
    page; the website redirects to another domain; or the homepage declares
    its canonical address on another domain.
  - **Advisory:** nameservers and mail run from another domain, or from a
    same-brand domain (a parent organization?); or no website and no mail.
  - **Suggested real root:** the redirect target, then the canonical
    address, then the parent domain, listed with what corroborates it (or a
    note that nothing does). It is also verified as a candidate.
  - The run is never interrupted. Flagged in a red banner at the top and
    bottom of the table, a top-level `root_check` object in JSON, a
    `root_warning` column plus a first `seed` row in CSV, a stderr banner when
    writing JSON or files, and exit code 3.
- The homepage's canonical address (`<link rel="canonical">` / `og:url`) is
  recorded for every domain.

### Changed
- CSV has a new last column, `root_warning`.
- Exit code 3 when the supplied root looks wrong (previously always 0 on
  success).

## 0.9.6 — 2026-11-27

### Added
- Live TLS certificate links as strong evidence (one item per domain, so a
  single certificate is never counted twice). The certificate served for a
  candidate also covers the seed or a verified domain; or the seed's
  certificate covers the candidate; or the candidate serves the identical
  certificate; or its certificate uses the same public key as the seed's or a
  verified domain's.
- Guards against false links:
  - Only certificates carrying Certificate Transparency timestamps count.
    Publicly trusted certificates do; certificates minted by TLS-intercepting
    proxies normally don't. When the seed's certificate has none, comparisons
    are skipped and the notes say so.
  - A certificate only counts if it covers the name it was served for. A
    server's default certificate, shown because someone else's DNS points at
    that server, proves nothing.
  - Shared hosting/CDN certificates (more than three other registrable
    domains, fewer than half of them the seed's or verified) are ignored.
- Certificate details recorded per domain: certificate and public-key
  fingerprints, and whether CT timestamps are present.

## 0.9.5 — 2026-11-27

### Added
- A candidate's own Content-Security-Policy is now evidence. A CSP that
  trusts two or more domains that are the seed or already verified is
  strong; trusting only the seed is medium on a brand-named domain and weak
  otherwise (customers sometimes whitelist a vendor's domains). Example:
  `jamfcloud.com` trusts `jamf.com` and `jamfsoftware.com`.
- CSP discovery, one hop out: domains named in the CSP of owned and
  needs-review domains become candidates, are verified like any other, and
  scoring runs again. It counts toward `--max-candidates`; `--no-csp` (or
  `DOMAINFINDER_CSP=0`) turns it off. Example: `jamf.com` without `--org`
  now finds `jamfsoftware.com` (owned) and `jamf.one` (needs review).

## 0.9.4 — 2026-11-27

### Added
- WhoisXML API reverse WHOIS (`whoisxml` source), active when
  `WHOISXML_API_KEY` is set (a free account includes 500 credits). It finds
  domains whose registrant organization is exactly one of the seed's
  organization names (plus punctuation variants), in current and historic
  WHOIS. A current match is strong evidence (like an RDAP registrant match);
  a historic-only match is weak. Credit-thrifty: a free preview first, a
  1-credit purchase only when the preview finds domains, a week-long cache,
  and one 10,000-domain page per search by default.
  `--whoisxml-search current|historic|both` and
  `DOMAINFINDER_WHOISXML_MAX_PAGES` control the searches.
- HTTP layer: cached JSON POST requests (the cache key excludes secrets).

## 0.9.3 — 2026-11-27

### Changed
- All documentation now lives in `docs/`: `README.md` and this changelog
  moved there, next to the `adp.com` sample run. `LICENSE` stays at the
  repository root, where GitHub and Python packaging look for it.

### Fixed
- Strong evidence of ownership plus another organization's name now always
  goes to *needs review* instead of being rejected when the conflict pulls
  the score below the review threshold. Example: `springcm.com` has a current
  certificate with O=DocuSign, while its live certificate still says
  "SpringCM, Inc." (acquired by DocuSign in 2018).
- A redirect to the registrar's own website (MarkMonitor parking a client
  domain by redirecting to `markmonitor.com`) is no longer penalized as an
  "unrelated" redirect. It is recognized from the registrar's name, not a
  list; at a brand-protection registrar it marks the domain held/inactive.
  Example: `arx.com`.
- Redaction placeholders in the registrant region or country ("REDACTED FOR
  PRIVACY") are treated as unknown instead of being shown and compared as a
  region. Example: `docusign.tw`.

## 0.9.2 — 2026-11-26

### Added
- `gtld` source: the brand label is now also checked across common generic
  TLDs (`.net`, `.org`, `.info`, `.biz`, `.name`, `.pro`, `.mobi`, `.io`,
  `.ai`, `.me`, `.tv`, `.cc`, `.app`, `.dev`, `.cloud`, `.tech`, `.online`,
  and more; `data/gtlds.txt`), with the same NS/SOA existence check and full
  verification as the ccTLD sweep. `.com`, `.net` and `.org` moved here from
  the ccTLD list.
- `--all-tlds` (or `DOMAINFINDER_ALL_TLDS=1`) sweeps every TLD in IANA's list
  instead, fetched live and cached for a week, so the exhaustive check needs
  no list maintenance. Falls back to the common set if the list is
  unavailable.

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
