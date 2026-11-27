# Changelog

All notable changes to domainfinder.

Versioning: bug fixes bump the last number (1.0.1, 1.0.2, …); significant new
features bump the middle number (1.1.0, 1.2.0, …) and reset the last.

## 1.7.0 — 2026-11-27

### Added
- **GLEIF corporate family.** The seed's legal entity is looked up in GLEIF
  (one exact legal-name match only, the registrant country breaking ties;
  otherwise not used). The legal and other names of the companies it
  consolidates count as the organization's names, so a domain registered to
  a subsidiary is a match, not a conflict. Names GLEIF confirms get full
  weight in the acquisition certificate search; GLEIF lags on acquisitions,
  so unlisted names are never penalized. `--no-gleif` / `DOMAINFINDER_GLEIF=0`.
- **Parent organization warning.** When GLEIF says the seed's organization
  is itself a subsidiary, a banner at the top and bottom of the table (and on
  stderr), `PARENT ORGANIZATION: …` in every CSV row's `root_warning` column
  plus a seed row, and `parent_warning` / `gleif` in JSON name the parent
  (and the direct parent when it differs). The family only goes down: the
  parent and its other subsidiaries are not treated as the seed's.

## 1.6.0 — 2026-11-27

### Added
- **Attested domains** (`--attested FILE`, `--attested-domain`): domains the
  organization itself states it owns. Always owned (source `attested`),
  whatever the evidence says; contradictions (not registered, parked or for
  sale, another organization's registration or certificate) become
  `warning: …` notes instead of reclassification. Links to attested domains
  count from the first round like links to the seed, candidates are compared
  with their dedicated nameservers, mail tenant, tokens, network and
  analytics ID, and their registrant names count as the organization's.
  No discovery runs from them; above 200 they get light fingerprints.
- **WHOIS fallback for registrar data.** When a registrar's RDAP refuses, the
  registrar's WHOIS server (named in the registry's WHOIS) is asked for the
  registrant fields and contacts (`--no-whois` turns it off).

### Changed
- **Registrars that rate limit are left alone.** A 429 from a registrar's RDAP
  stops all lookups there until the time it names ("retry after 24 hours";
  Retry-After; one hour by default), for this run and later ones (kept in
  the cache); cached answers are used meanwhile, and there is no second try.
  In test runs one registrar blocked the user's address for a day after
  repeated large runs, and every further request risked extending it.
- **Registrar lookups only where they can change a result.** Not for domains
  already owned through two independent infrastructure matches, nor for
  domains with name evidence only; registry lookups are unchanged. This cuts
  registrar lookups substantially on large organizations.
- **Failures say why.** The `-v` note counts registrar lookups made and not
  needed, and gives the reason per registrar ("HTTP 429 (rate limited) ×1,
  backing off ×158") and the back-off end time.
- The registry's record is now parsed before the registrar's; registrar data
  fills what the registry lacks.

## 1.5.3 — 2026-11-27

### Fixed
- **Registrar evidence missing in run after run.** A few domains lost their
  registrant contact emails identically across runs. A registrar that is
  rate limiting can answer with HTTP 200 and a body that is valid JSON but
  not a domain record; such an answer passed the cache check, was stored
  for 3 days and replayed. RDAP answers are now cached only when they are
  real RDAP objects (a domain record, with entities for a registrar's
  answer; an IP network for IP lookups); anything else counts as a failed
  lookup and gets the slower second try. Cached answers are re-checked
  before use, so stubs stored by earlier versions are ignored.
- **A misleading review note.** A domain whose strong evidence is on its
  website (for example a Content-Security-Policy trusting the seed's
  domains) was labeled "registration similarity only". It now gets a
  `no_control` note naming the evidence ("only links, Content-Security-Policy
  or tags on its website"); `registration_only` is kept for registration
  similarity.

## 1.5.2 — 2026-11-27

### Fixed
- **Registrar RDAP rate limits lost registration evidence.** The registrar's
  RDAP carries the registrant organization and contact emails the registry
  lacks; in test runs it refused bursts (one registrar for 29 domains of one
  seed), so domains lost their registrant match or contact email and some
  dropped from the main list. Failed registrar lookups now get a slower
  second try before scoring (one request at a time per registrar, a second
  apart), and RDAP servers get gentler default pacing (3 at a time, 150 ms
  apart). A `-v` note reports how many failed and how many the retry
  recovered.
- **Why a domain was held back was invisible in the CSV and table.** The
  `operated_for_client`, `redirect_only` and `registration_only` notes carry
  no points, and only point-carrying evidence was printed. They now appear
  in the CSV (`review: …` at the end of the evidence) and lead the table's
  evidence column.

### Changed
- `--max-candidates` defaults to 3000 (was 1000). The tool runs on
  organizations of unknown size; a large one hit the old cap, and which
  candidates were verified then varied from run to run.

## 1.5.1 — 2026-11-27

### Fixed
- **Client sites the seed hosts were listed as the seed's own.** A
  financial-technology processor's run listed about 25 credit unions' and
  banks' main domains as owned: the processor hosts their websites (its
  certificate) and sends their mail (its servers in their SPF), but the
  credit unions registered the domains themselves at other registrars. When
  the seed's certificate is the only evidence of control, nothing ties the
  domain's DNS, network, inbound mail, verification tokens or registration
  to the seed, and the published registration is at a different registrar,
  the domain now stops at needs review with an `operated_for_client` note.
  Domains the seed registered itself stay owned; brand-named domains and
  domains without published registration data are not affected.

## 1.5.0 — 2026-11-27

### Changed
- **The cache moved to the run directory.** It is now
  `domainfinder-cache.sqlite` in the directory the tool runs from (it was
  `~/.cache/domainfinder/cache.sqlite`, which can be deleted).
  `DOMAINFINDER_CACHE_DIR` still chooses another directory.
- **Cached values are compressed** (stored web pages shrink about tenfold),
  and entries older than 30 days are deleted when the cache is opened.
- **Several runs can share the cache at once** (SQLite WAL mode, 30-second
  busy timeout). A write that still cannot get the file is skipped instead of
  ending the run with "database is locked".

### Added
- **Older answers when a fresh lookup fails.** Answers past their freshness
  are kept for up to 30 days (`DOMAINFINDER_CACHE_MAX_STALE_DAYS`). When crt.sh,
  an RDAP server, HackerTarget, Wikidata, SEC EDGAR, WhoisXML or WHOIS fails
  (timeout, rate limit, outage), the older answer is used and a `-v` note
  names the hosts. Websites and DNS never fall back.
- A `-v` note with the cache's path, size, answers supplied and stored.

### Fixed
- **Error answers sent with HTTP 200 were cached.** HackerTarget's quota
  message and WhoisXML error payloads could be cached for a week and replayed
  without asking again; crt.sh, Wikidata, RDAP and ViewDNS answers are now
  checked the same way before they are stored.
- **DNS-over-HTTPS answers never expired.** When the system resolver did not
  answer, DNS-over-HTTPS replies were cached with "lifetime 0", which the cache
  read as "never expires", so DNS answers on such networks never refreshed.
  They are no longer stored by the HTTP layer (the resolver keeps the parsed
  answer for 6 hours).

## 1.4.2 — 2026-11-27

Fixes from test runs on four more organizations (a hardware maker, a
financial-technology processor, a networking company and a European
subsidiary of a business-information company).

### Fixed
- **A redirect plus the name reached the main list.** A domain registered
  months ago at a consumer registrar behind a privacy service, redirecting
  to the seed and named after one of its SEC subsidiaries, scored 72 and was
  owned: redirect (60) plus name evidence. The brand in the name and an SEC
  subsidiary name are chosen by whoever registers the domain, so they no
  longer count as the independent link a redirect needs. Such domains stop
  at needs review with a `redirect_only` note.
- **Organization names whose first words spell the brand counted as another
  organization.** "Informa D&B SA" for brand `informadb` was a conflict
  (−20); it is now the brand-named entity (neutral, like "Example, Inc." for
  `example`). Whole leading words only.
- **Registrar RDAP failures were silent.** The registrar's RDAP, which often
  carries the registrant contacts the registry lacks, is now retried twice,
  and a `-v` note counts the domains per registrar it did not answer for.

### Added
- `registrar_brand` (weak, 5): the same brand-protection registrar as the
  seed when the registrant region is not published. Corporate registrars
  serve only their clients; with no region there is nothing to contradict
  it. It is the independent link that keeps the seed's own redirecting
  domains at its registrar on the main list.
- `redirect-target` second-pass source: the domain an owned domain redirects
  to becomes a candidate when not already known (in one run, an owned
  domain redirected to the organization's new platform brand, which no
  source had found).

## 1.4.1 — 2026-11-27

Fixes from test runs on five organizations of different shapes (a payroll
company, an e-signature company, a payments processor, a device-management
software company and a university).

### Fixed
- **Certificate hop pulled in a vendor's customers.** Two needs-review
  domains on one vendor certificate (a university's two athletics sites on
  an athletics vendor's shared certificate) vouched for each other, and
  the certificate's ~50 other college athletics domains were verified as
  candidates. Only the seed and owned domains now vouch for a certificate.
- **Certificates in an "acquired" company's name counted like the seed's.**
  The name learned for the `acq-ct` search can be a joint-venture partner:
  a payments processor's joint-venture domain carries its partner bank's
  name, and the bank's own domains scored +45 strong. Such certificates are now
  their own evidence: `ct_org_acquired` (medium, 25) and
  `ct_org_acquired_historic` (weak, 5), not evidence of control.
- **Held ccTLD domains redirecting to the seed stayed in needs review.**
  Registries such as .ae, .be, .ch and .co.nz publish no registration data,
  so the tool could not see the registrar. A domain parked on the holding
  infrastructure of the seed's own brand-protection registrar (MarkMonitor's
  nameservers or holding address) now counts as at that registrar: in one
  test run, 25 ccTLD domains redirecting to the seed became owned. Without a
  redirect such a domain still needs review.

## 1.4.0 — 2026-11-27

### Changed
- **Evidence is grouped into channels, so one fact is no longer counted
  several times.** Items from one underlying fact (one mail setup: tenant,
  MX, SPF, DMARC; one WHOIS record: organization, email, phone, street; one
  certificate: live link, organization, CT) share a channel. Within a
  channel the strongest item counts in full, the second at 50% and the rest
  at 25%. Channels (delegation, zone, mail, hosting, token, certificate,
  website, registration, name) add up in full. Example: a company served by
  the seed's small dedicated mail host, with the host's SPF include and the
  brand in its name, scored 70 (owned); it now scores 60 (needs review).
- **Agreement earns a bonus.** When two or more independent channels carry
  medium or strong evidence (and one item is strong), a `corroboration`
  item adds 5 points per agreeing channel beyond the first, up to 15.
- The points shown per evidence item are the counted points and still add
  up to the score; discounted items say so.
- "Nameservers / MX / www CNAME under the seed's domain" are now separate
  evidence items (`namespace`, `namespace_mx`, `namespace_www`) in their own
  channels.
- "Two independent infrastructure matches" (which excuse a different
  registrant name, and select acquisition names for the `acq-ct` search)
  now means matches in two different channels.
- Registration-only results in needs review carry the `registration_only`
  note at any score, not only at 70 and above.

### Check against an audited run
Replaying the evidence of an audited run for a large company: the 363 domains with control
evidence stay owned (only two score under 85), the 16 registration-only
domains stay in needs review (now 65–69), and nothing else moves.

## 1.3.0 — 2026-11-27

### Changed
- **"High confidence" now requires evidence that the organization operates
  the domain.** An audit of every result scoring 70 or more for a large company found no
  false positives among domains with control evidence (DNS on its own
  nameservers, mail tenant, netblock, certificate link, redirect, registrant
  match), but about 16–20 owned results rested on registration similarity
  alone: parked at MarkMonitor in the seed's registrant region, with the brand in the
  name or old certificates. Those are probably the company's but unproven, and a
  higher threshold would also have dropped certain ccTLD domains. Such
  results now stop at *needs review* (score capped at 69) with a
  `registration_only` evidence note. Control kinds are listed in
  `verify.py → CONTROL_KINDS`.

### Added
- **WHOIS/RDAP contact data points.** Contact emails, phone numbers and
  street addresses are read from RDAP vCards (registrant, administrative,
  technical, billing) and `.edu` WHOIS.
  - A contact email at the seed's (or a verified) domain: strong (50) and
    counts as control evidence; registrars verify registrant email, and an
    outsider cannot receive mail at the seed's domain.
  - The same email (off the seed's domain), phone or street address as the
    seed's registrant/admin contacts: medium (25 each), supporting only.
  - Registrar, abuse-desk, reseller and privacy-proxy contacts and
    redaction placeholders are ignored; technical contacts are not compared
    with the seed's. Evidence text names no email address or phone number.
  - Most gTLD contacts are redacted, so these fire mainly for ccTLDs, `.edu`
    and registrars that publish contacts.

## 1.2.4 — 2026-11-27

### Fixed
- **crt.sh database searches work again.** crt.sh's connection pooler runs
  in statement-pooling mode: it refuses transactions ("transaction blocks
  not allowed in statement pooling mode", every search failed in 1.2.3),
  and each statement can reach a different server connection. The tool now
  sends only the search itself: no transaction and no `SET`. (The `SET
  statement_timeout` of 1.2.1 could have landed on a server connection
  serving someone else.) The time limit (`DOMAINFINDER_CRTSH_DB_TIMEOUT`,
  300 s) is enforced by the tool, which cancels a query that runs too long
  and keeps the connection.

## 1.2.3 — 2026-11-27

### Fixed
- **Nameserver evidence no longer changes from run to run.** A resolver may
  answer an NS query with a registry's delegation, which for some ccTLDs
  lists only part of the set: several ccTLD domains matched the seed's ten
  nameservers on one run and five or six on the next, and dropped to needs review. When a domain's set (or the seed's)
  shares some but not all nameservers with the seed, the tool now asks one
  of the domain's own nameservers directly and uses its authoritative
  answer. The comparison itself is unchanged (a partial set still only
  "overlaps").
  - Only authoritative answers are accepted; any failure keeps the
    resolver's answer. After five failures in a row (port 53 blocked or
    intercepted), the check stops for the run.
  - A `-v` note: "dns: N nameserver set(s) only partly matching the seed's
    re-read from the domains' own nameservers; M changed".

## 1.2.2 — 2026-11-27

### Fixed
- **crt.sh's connection pooler.** The acquisitions search failed with
  "client_idle_timeout": crt.sh closes connections left idle while
  candidates are verified. A connection unused for 30 seconds is now
  replaced before the next query, and a query whose connection was closed
  under it is retried once on a new one without counting as a failure.
- **The time limit reaches the right connection.** Through a pooler, a
  `SET` and the query after it can land on different server connections;
  the limit is now `SET LOCAL` inside the query's own transaction.
- **Database searches get their own time limit**, 300 seconds by default
  (`DOMAINFINDER_CRTSH_DB_TIMEOUT`). A large company's full certificate history did
  not finish in the web API's 120 seconds.

## 1.2.1 — 2026-11-27

### Fixed
- **A passing database failure no longer turns the database off for the
  run.** After a slow query, reconnecting failed (the note showed an IPv6
  address and "Network is unreachable") and the database was treated like a
  blocked port. Now only a first connection that fails means "blocked";
  later failures count toward three in a row.
- **IPv4 first.** crt.sh's addresses are tried IPv4 first, then IPv6, so a
  network without working IPv6 still connects. Each address's error is kept.
- **Slow queries are stopped by crt.sh itself** (`SET statement_timeout`
  matching the tool's own timeout), so the connection stays usable and no
  abandoned query keeps running on crt.sh; a healthy connection is kept, a
  broken one replaced.
- **The note says what failed:** each failed search and its reason, not only
  the last error, cut off mid-sentence. "crt.sh's web" now reads "crt.sh's
  web API".

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
  brand.** A domain spelling out the organization's full name (held at the seed's
  brand-protection registrar, same registrant region) stayed in "needs
  review" because its name doesn't contain the short brand label. The organization's name run
  together now counts, as an exact match only, never a partial one.

## 1.1.1 — 2026-11-27

### Fixed
- **Vendor-hosted certificates no longer link unrelated domains.** When an
  owned domain is hosted by a vendor (a claims portal on its vendor's
  certificate), the vendor's other customers sharing that
  certificate's public key reached "needs review". A public key now links
  domains only when its certificate is not a shared one (mostly other
  organizations' names) and the key is not served for many domains that are
  mostly not ours (a host reusing one key across customers). The same guard
  applies to a key shared with the seed.
- **The certificate hop skips vendor certificates.** A certificate naming
  more than three other domains, none of them known to be ours, no longer
  feeds `cert-san` candidates (it added two dozen of a vendor's customer domains in one run).
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
  - its domains are not pulled in as candidates (one cloud provider's run
    had merged 500 unrelated Akamai DNS customers);
  - "nameservers under it" is no longer evidence;
  - it can only match as a whole set.
  The reverse lookup now queries one host per nameserver domain. This also
  covers a seed that sells DNS hosting itself.
- SEC EDGAR: subsidiary names are read only from each Exhibit 21 table's
  name column (the leftmost regularly filled column). Jurisdiction cells
  are no longer read as names, which turned jurisdictions such as
  Bermuda or Delaware into domain guesses.

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
  otherwise (customers sometimes whitelist a vendor's domains). Example: a
  company's cloud-service domain trusts its main and former domains.
- CSP discovery, one hop out: domains named in the CSP of owned and
  needs-review domains become candidates, are verified like any other, and
  scoring runs again. It counts toward `--max-candidates`; `--no-csp` (or
  `DOMAINFINDER_CSP=0`) turns it off. Example: a software company's seed
  without `--org` now finds its former domain (owned) and a brand ccTLD
  (needs review).

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
  moved there, next to a sample run (since removed). `LICENSE` stays at the
  repository root, where GitHub and Python packaging look for it.

### Fixed
- Strong evidence of ownership plus another organization's name now always
  goes to *needs review* instead of being rejected when the conflict pulls
  the score below the review threshold. Example: an acquired company's domain
  has a current certificate in the parent's name, while its live
  certificate still names the acquired company.
- A redirect to the registrar's own website (MarkMonitor parking a client
  domain by redirecting to `markmonitor.com`) is no longer penalized as an
  "unrelated" redirect. It is recognized from the registrar's name, not a
  list; at a brand-protection registrar it marks the domain held/inactive.
- Redaction placeholders in the registrant region or country ("REDACTED FOR
  PRIVACY") are treated as unknown instead of being shown and compared as a
  region.

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
  (`example.信息` rather than `example.xn--vuq861b`); `--idn punycode` switches back.
  CSV and JSON always carry both forms in `domain_unicode` / `domain_ascii`.
  CSV is written with a UTF-8 byte-order mark so Excel shows it correctly.

### Fixed
- A registrant named after the registrar, a brand-protection registrar or a
  privacy service (CSC writes "CSC Corporate Domains, Inc." into the registrant
  fields it manages) is treated as a proxy: never the owner's name, never an
  ownership match or conflict, and its region is ignored. Previously one
  test run credited CSC's own domains to the seed.
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
