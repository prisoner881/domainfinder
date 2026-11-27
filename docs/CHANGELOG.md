# Changelog

All notable changes to domainfinder.

Versioning: bug fixes bump the last number (1.0.1, 1.0.2, …); significant new
features bump the middle number (1.1.0, 1.2.0, …) and reset the last.

## 1.2.0 — 2026-11-27

### Added
- **crt.sh's public database first, its web API second.** Every crt.sh
  search (`crtsh-org`, `crtsh-san`, `acq-ct`, the seed's organization name
  and the certificates it is read from) first goes to crt.sh's read-only
  PostgreSQL database (`guest@crt.sh:5432/certwatch`), using the same SQL
  crt.sh's own search runs. Any failure sends that search to the web API as
  before.
  - Up to 50,000 rows per search instead of the web API's 10,000
    (`DOMAINFINDER_CRTSH_DB_LIMIT`), so large organizations are no longer
    truncated as often; the truncation note names the limit that applied.
  - A refused or blocked connection (port 5432 is often blocked) turns the
    database off for the rest of the run after one attempt; one failed query
    falls back for that query, two turn the database off.
  - One connection per run, one query at a time; results are cached like
    the web API's.
  - A `-v` note says how many searches the database answered, or why the
    web API was used.
  - `--no-crtsh-db` or `DOMAINFINDER_CRTSH_DB=0` for the web API only.
- New dependency: `psycopg[binary]` (without it, the web API is used).

## 1.1.3 — 2026-11-27

### Fixed
- Evidence wording: a domain named after the organization now reads "named
  after the organization" instead of "brand 'automaticdataprocessing' in
  name". Scores are unchanged.

## 1.1.2 — 2026-11-27

### Fixed
- **A held domain named exactly after the organization counts like the
  brand.** automaticdataprocessing.com (held at the seed's brand-protection
  registrar, same registrant region) stayed in "needs review" because its
  name doesn't contain the brand label "adp". The organization's name run
  together now counts, as an exact match only, never a partial one.

## 1.1.1 — 2026-11-27

### Fixed
- **Vendor-hosted certificates no longer link unrelated domains.** When an
  owned domain is hosted by a vendor (adpunemploymentclaims.com on an
  Experian certificate), the vendor's other customers sharing that
  certificate's public key reached "needs review". A public key now links
  domains only when its certificate is not a shared one (mostly other
  organizations' names) and the key is not served for many domains that are
  mostly not ours (a host reusing one key across customers). The same guard
  applies to a key shared with the seed.
- **The certificate hop skips vendor certificates.** A certificate naming
  more than three other domains, none of them known to be ours, no longer
  feeds `cert-san` candidates (it added two dozen Experian domains for ADP).
- **EDGAR finds Exhibit 21 under any file name.** Names such as
  `exhibit21.htm` were missed ("latest 10-K has no Exhibit 21 file"); when
  no file name matches, the filing index is read for the document declared
  as type EX-21. An unreachable index is now reported as such.
- **Wikidata 403 explained.** The note now carries Wikimedia's reason, and
  the optional `DOMAINFINDER_CONTACT` setting adds contact details to the
  User-Agent for Wikidata queries only (Wikimedia's robot policy asks for
  them). Refusals are never cached.

## 1.1.0 — 2026-11-27

### Added
- **Certificate links from CT logs.** A current certificate in crt.sh that
  covers both a candidate and the seed is strong evidence: one party proved
  control of both to the CA. It works where the live check can't (holding
  pages without HTTPS, bot blocking, TLS interception), uses the same
  shared-certificate guard, and is not added when the live certificate
  already links the domain.
- **DMARC reporting addresses.** Strong when a domain's reports go to the
  seed (or a verified domain) *and* that domain's own DNS specifically
  authorizes them (RFC 7489 external-destination record, wildcards
  detected). Weak when merely addressed there, since anyone can write the
  address. Medium for the same customer-specific address at a DMARC vendor;
  generic vendor mailboxes don't count.
- **Sister domains from certificates.** Names on the publicly trusted TLS
  certificates of owned and needs-review domains join the second-pass
  candidates (`cert-san`).
- **Acquired companies' names, learned from evidence.** When an owned domain
  proven by two or more infrastructure matches carries another company's
  name on its certificate or registration, crt.sh is searched for that name
  too (`acq-ct`, up to five names, exact matches). Certificates in that name
  count like the seed's own CT evidence; everything found is still fully
  verified. `DOMAINFINDER_ACQUISITIONS=0` turns it off.
- **Wikidata subsidiaries.** The organization whose official website is
  exactly the seed is looked up on Wikidata; its subsidiaries' official
  websites become candidates (`wikidata`). `DOMAINFINDER_WIKIDATA=0` turns
  it off.

### Changed
- The second pass (CSP, certificate names, acquisition names) reports what
  it found in one `second pass:` note.

## 1.0.0 — 2026-11-27

First stable release.

### Fixed
- A redirect was counted more than once. The homepage collector follows
  redirects, so a domain redirecting to the seed picked up the seed's own
  analytics/tag ID and CSP header as if they were its own. The redirect (60)
  plus the inherited tag (25) and CSP (35) put a typosquat that redirects to
  the real site on the main list. Analytics IDs, CSP evidence and CSP
  discovery now only use a page that belongs to the candidate's own domain.
  A redirect alone reaches *needs review*; with one independent link
  (registrar and region, nameservers, mail tenant, certificate, registrant)
  it is owned. Some genuine domains whose only evidence is a redirect and
  the brand name (e.g. country domains without public registration data)
  move from owned to needs review.

## 0.9.10 — 2026-11-27

### Fixed
- The root-check banner was printed twice at the bottom of the table when
  writing a file (`-o`): once in the table and once on stderr. It now goes
  to stderr only when it isn't already on screen (JSON output, or the table
  redirected to a file or pipe).
- Shared DNS infrastructure is now detected from reverse-NS data instead of
  only from lists. A nameserver whose host serves 200+ domains is treated
  as shared:
  - its domains are not pulled in as candidates (the `oraclecloud.com` run
    had merged 500 unrelated Akamai DNS customers);
  - "nameservers under it" is no longer evidence;
  - it can only match as a whole set.
  The reverse lookup now queries one host per nameserver domain. This also
  covers a seed that sells DNS hosting itself (Oracle's `oraclecloud.net`).
- SEC EDGAR: subsidiary names are read only from each Exhibit 21 table's
  name column (the leftmost regularly filled column). Jurisdiction cells
  are no longer read as names, which produced guesses such as
  `bermuda.com` and `delaware.com`.

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
