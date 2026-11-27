# domainfinder

Give it one root domain (`adp.com`). It returns a list of other domains run by the same company, each with a score and the evidence behind it.

```
domainfinder adp.com
```

No public source lists everything a company owns, so the tool does not try to be complete. It aims for **precision**: a domain reaches the main list only when independent evidence ties it to the seed. A domain that only *looks* related goes to a separate **needs review** list (for example, a name match plus a parking page). It never reaches the main list.

Current version: **0.9.4** (see [CHANGELOG.md](CHANGELOG.md)). Every run starts by printing `domainfinder 0.9.4` (on stderr, so `--json` output stays clean); `domainfinder --version` prints the same.

Free sources work out of the box. WhoisXML API's reverse WHOIS turns on with an API key (a free account includes 500 credits). SecurityTrails and DomainTools are built in as switched-off stubs that turn on once their keys are configured.

## Results for `adp.com`

[adp-sample-run.md](adp-sample-run.md) compares a run against the handoff's acceptance list. Free sources alone found 370 high-confidence domains, put 16 in needs review and rejected 105. Every expected-rejected domain was rejected (`adp.fr` = Aéroports de Paris, parked look-alikes, Broadridge's ex-ADP domains). The 33 expected-owned domains the free sources discovered were all classified owned.

## Install

Python 3.11+.

```bash
pip install -e .            # or: pip install -e '.[dev]' for the tests
cp .env.example .env        # optional: keys and settings
```

## Usage

```
domainfinder adp.com                         # table on stdout
domainfinder adp.com -o results.csv          # also write CSV (add -v to include rejected rows)
domainfinder adp.com -o results.json         # also write JSON (everything, with fingerprints)
domainfinder adp.com --json                  # JSON on stdout
domainfinder adp.com --min-score 80          # stricter main list
domainfinder adp.com -v                      # also show rejected domains, sources and notes
domainfinder adp.com --org "Automatic Data Processing, Inc."   # set the legal name yourself
domainfinder adp.com --candidate elabor.com  # verify extra domains you already suspect
domainfinder adp.com --import found.csv      # also verify domains found by other processes
domainfinder --list-sources                  # which sources are on, and why others are off
```

### Importing candidate domains

`--import FILE` adds domains that other processes found — an asset inventory, a
spreadsheet, another tool's output — as candidates. They are checked exactly like
the domains domainfinder discovers itself, so an imported domain reaches the main
list only on evidence.

* Entries are separated by commas and/or newlines, so a one-line list, one domain
  per line, or a simple CSV export all work. CSV quoting is understood and `#`
  starts a comment.
* URLs and host names are reduced to their registrable domain
  (`https://mail.example.co.uk/x` → `example.co.uk`); duplicates are merged;
  entries that are not domain names (a header line, an IP address) are skipped
  and reported.
* `--import` can be repeated, and `--import -` reads standard input. `--candidate`
  also takes comma-separated lists for a few domains on the command line.
* Imported domains carry the source `import` in the output and are never dropped
  by `--max-candidates`.

```
cat found.csv
# from the asset inventory
adpworld.de, workforcenow.com
https://www.celergo.com/about
domainfinder adp.com --import found.csv
```

### Internationalized domain names

Some domains use non-Latin scripts: `adp.信息` is ADP's domain under `.信息`, Chinese for "information". DNS itself only carries ASCII, so on the wire the name is written as Punycode: `adp.xn--vuq861b`. Both strings are the same domain.

* By default the output shows the readable form in the `domain` field, the table, statuses and evidence text. `--idn punycode` (or `DOMAINFINDER_IDN=punycode`) writes the ASCII form instead, for tools that only accept ASCII host names.
* CSV and JSON always carry both forms in fixed columns, `domain_unicode` and `domain_ascii`, whatever `--idn` says. A downstream parser can rely on those instead of the `domain` field.
* CSV files are written as UTF-8 with a byte-order mark, so Excel displays `信息` correctly. The raw `fingerprint` objects in JSON keep the ASCII form, since they record DNS data as DNS returned it.
* Unicode input works too: `domainfinder adp.信息` or `--candidate adp.信息`.

Other options: `--all-tlds` (sweep every TLD, not just the common ones), `--brand` (extra brand labels for the ccTLD sweep), `--sources` / `--skip` (pick sources), `--max-candidates` (default 1000), `--concurrency`, `--dns auto|system|doh`, `--no-tls`, `--no-whois`, `--no-cache`, `--cache-ttl HOURS`, `--high-threshold`, `--review-threshold`, `--no-hackertarget`, `--debug`.

Output has three sections:

| Section | Rule |
|---|---|
| **High-confidence** | score ≥ 70 (`DOMAINFINDER_HIGH_THRESHOLD`) and at least one *strong* piece of evidence |
| **Needs review** | score ≥ 40, or a conflict a person should resolve (parked but registered like the seed; another company's name on infrastructure the seed uses) |
| **Rejected** (`-v`) | everything else, with the reason |

Each row also has a status: `active`, `redirects to …`, `held/inactive` (a registrar holding page: registered but unused), `parked`, `unregistered`, `mail only`, and so on.

## How it works

```
seed ─► [1] fingerprint ─► [2] candidate sources ─► [3] fingerprint + score each candidate ─► [4] output
```

### 1. Fingerprint

The same collector runs on the seed and on every candidate. It uses only passive lookups:

* **RDAP**: registrar, registrant org/region/country, creation date. The registry is found through the IANA bootstrap files (rdap.org is the fallback). The tool then follows the registry's `related` link to the registrar's RDAP server, because that server often carries registrant fields the registry leaves out. vCards are parsed defensively. For TLDs with no RDAP service at all, the registry's WHOIS server is asked instead (port 43). Today that is `.edu` (EDUCAUSE), whose records name the institution as registrant.
* **DNS**: the full NS set, MX hosts, A/AAAA records, TXT and SOA. From these it derives:
  * the mail **tenant ID** (Proofpoint `mxa-0006eb01…` → `proofpoint:0006eb01`; Cisco IronPort and Barracuda too)
  * SPF includes
  * verification tokens (`google-site-verification=`, `MS=`, `atlassian-domain-verification=`, …)
  * the SOA contact address
* **IP → netblock** via RDAP (ARIN, RIPE, APNIC, LACNIC, AFRINIC): netblock name, handle, range and owner.
* **Homepage**: one fetch, following redirects hop by hop to record the chain. It reads analytics and tag IDs (GA4, UA, GTM, Adobe Launch, Facebook pixel, Hotjar, OneTrust), outbound links and the CSP header.
* **TLS certificate**: Subject `O=` and the SANs.
* **Organization name**: taken from `--org`, the live certificate's `O=`, the `O=` of the seed's recent OV/EV certificates in CT logs (downloaded from crt.sh), a registrant org that isn't a privacy proxy, or a netblock owner whose name fits the brand (for example, the initials of "Automatic Data Processing" spell `adp`).

DNS uses the system resolver. If the system resolver does not answer, it switches to DNS-over-HTTPS (dns.google, then Cloudflare).

### 2. Candidate sources

| Source | Free | What it does |
|---|---|---|
| `crtsh-org` | ✓ | crt.sh certificates whose Subject `O=` is the seed's organization: current and expired, with recency recorded. The strongest free source. |
| `crtsh-san` | ✓ | Other registrable domains in the SANs of the seed's current certificates. |
| `cctld` | ✓ | The brand label on ~80 country-code suffixes (`data/cctlds.txt`). An NS/SOA lookup first; only registered names go on to verification. |
| `gtld` | ✓ | The brand label on ~35 common generic TLDs (`data/gtlds.txt`: `.net`, `.org`, `.info`, `.biz`, `.io`, `.ai`, `.app`, `.dev`, …), checked the same way. `--all-tlds` uses IANA's list of every TLD instead (about 1,400, fetched live and cached for a week). |
| `seed-links` | ✓ | Domains linked from the seed's homepage, its CSP header and its live certificate. |
| `edgar` | ✓ | SEC EDGAR Exhibit 21 subsidiaries → `<name>.com` guesses. Needs `DOMAINFINDER_SEC_USER_AGENT` (SEC policy). |
| `hackertarget` | ✓ | Reverse NS (`findshareddns`). For managed-DNS pools it intersects several of the seed's NS hosts, which approximates "same NS set". Small daily quota; turn it off with `--no-hackertarget`. |
| `viewdns` | free key | Reverse NS and reverse MX. Needs `VIEWDNS_API_KEY`. |
| `securitytrails` | paid | Stub: reverse WHOIS / NS / MX, associated domains. |
| `whoisxml` | free key / paid | Reverse WHOIS: domains whose registrant organization is *exactly* the seed's (plus punctuation variants), in current and historic WHOIS. A current match is strong evidence; a historic-only match is weak. See [WhoisXML reverse WHOIS](#whoisxml-reverse-whois). |
| `domaintools` | paid | Stub: Iris reverse WHOIS, NS/IP/email pivots, passive DNS. |

### 3. Scoring

Each rule adds an evidence item with points (the weights are in `verify.py → WEIGHTS`):

| Evidence | Strength | Points |
|---|---|---|
| Redirect chain reaches the seed or an already-verified domain | strong | 60 |
| NS / MX / `www` CNAME hosted under the seed's (or a verified) domain | strong | 50 |
| Same **dedicated** NS set (Jaccard ≥ 0.5 on own hosts; ≥ 0.75 and ≥ 3 hosts on managed-DNS pools such as Akamai or NS1) | strong | 50 |
| Same mail tenant ID / same dedicated MX host | strong | 50 / 45 |
| IP in a netblock registered to the seed's organization (or the seed's own non-CDN netblock) | strong | 50 |
| Same TXT verification token | strong | 50 |
| Live TLS certificate `O=` matches the seed's organization | strong | 50 |
| RDAP registrant org matches | strong | 60 |
| CT: a current certificate with `O=` the seed's org | strong | 45 |
| CT: only expired certificates with that `O=` (divested? e.g. broadridge.com) | weak | 15 |
| Same analytics/tag ID | medium | 25 |
| SPF includes the seed's own include / a shared org-specific include | medium | 35 / 20 |
| SOA contact at the seed's domain | medium | 25 |
| Registrar holding page + same brand-protection registrar and registrant region + brand in name or past certificates in the seed's name | strong | 55 |
| Holding page + same brand-protection registrar and region (no brand, no past certificates) / + brand but another region | medium | 40 / 35 |
| Same registrar **and** registrant region (brand-protection registrars only) | weak | 10 |
| Registrant or certificate org starting with the brand ("ADP, Inc.", "ADP France"): neither a match nor a conflict | weak | 10 |
| Linked from the seed's homepage *and* carries the brand (athletics, campaign sites) | medium | 35 |
| Brand label in the name; SEC subsidiary match; linked from the seed site | weak | 5–10 |
| Parking or for-sale service (NS, redirect or page text) | negative | −50 |
| RDAP registrant / certificate names a different organization | negative | −40 / −20 |
| Redirects to an unrelated domain (a redirect to the registrar's own site counts as "held" instead) | negative | −10 |

Guards that keep false positives out:

* **Shared infrastructure never counts.** NS hosts at mass providers are listed in `data/shared_dns_providers.txt`: Cloudflare, GoDaddy `domaincontrol.com`, Route 53 `awsdns-*`, Azure, Google, Wix, Squarespace, registrar defaults and more. Managed-DNS pools (Akamai `akam.net`, NS1, UltraDNS, Dyn) are only compared as a *whole set*. Netblocks owned by clouds and CDNs are ignored (`data/shared_hosting_orgs.txt`). Shared MX and SPF targets only count when they carry a tenant ID. If a paid reverse-NS source reports that an NS host serves more than `DOMAINFINDER_SHARED_NS_THRESHOLD` domains, NS matching is turned off.
* **Weak evidence is never enough.** The main list needs at least one strong item.
* **A name match is not ownership.** A registrant or certificate that names another organization blocks the main list, unless two independent infrastructure matches agree (acquisitions keep their old legal names). With any strong evidence for the seed, such a conflict goes to *needs review* rather than being rejected.
* **Parked domains** go to *needs review* when their registration matches the seed's (a possible defensive registration), and are rejected otherwise.
* **Holding pages.** Brand-protection registrars park unused client domains (MarkMonitor: `15.197.70.98`, `ns*.markmonitor.com`). Such a domain is classed as owned (`held/inactive`) only when the registrar and registrant region match the seed's *and* either the brand is in the name or CT logs show past certificates issued to the seed's organization. A held domain with only the registrar and region in common goes to *needs review*, as does a brand-named one at the same registrar but in another region.
* **Second pass.** After the first round, scoring repeats with the newly verified domains, so "redirects to workmarket.com" counts once workmarket.com itself is verified.

## Adding paid keys

Put the keys in `.env` (or the environment):

```
SECURITYTRAILS_API_KEY=...
WHOISXML_API_KEY=...
DOMAINTOOLS_API_USERNAME=...
DOMAINTOOLS_API_KEY=...
```

`domainfinder --list-sources` shows which providers are on. SecurityTrails and DomainTools in `src/domainfinder/sources/paid.py` are stubs today: each docstring lists the endpoints a full implementation would call. To implement one, fill in `candidates()`; for reverse-NS providers, also fill in `ns_usage()` so the shared-NS threshold works. Domains a source returns go through the same verification as every other candidate, so a paid source cannot add unverified domains. Keys are never logged, and `Settings` hides them from its `repr`. Follow each provider's terms on storing and redistributing data.

To add any other source, subclass `sources.base.Source` and list it in `sources/__init__.py`.

### WhoisXML reverse WHOIS

Sign up at whoisxmlapi.com (a free account includes 500 credits) and set `WHOISXML_API_KEY` in `.env`. The source then searches WHOIS for domains whose **registrant organization is exactly** one of the seed's organization names, plus small punctuation variants (`Inc.` / `Inc`, with or without the comma). Loose matches are not used: a generic name like "Global Payments" would pull in unrelated companies.

* **Current WHOIS match**: strong evidence, the same as an RDAP registrant match. On its own it can put a domain on the main list. That matters for held domains whose only other link is the registrar, such as the MarkMonitor holding pages in the `adp.com` run.
* **Historic-only match**: weak evidence. The domain was registered to the seed once, but may have been sold since (Broadridge's ex-ADP domains).
* **Credits**: every search first runs a free *preview* (a count). The 1-credit *purchase* of the list (up to 10,000 domains) happens only when the count is above zero. Answers are cached for a week, so rerunning a seed costs nothing. The `-v` notes report what each search found and how many credits the run spent. By default, current and historic WHOIS are both searched, for up to two organization names × four variants. `--whoisxml-search current|historic` (or `DOMAINFINDER_WHOISXML_SEARCH`) limits that, and `DOMAINFINDER_WHOISXML_MAX_PAGES` (default 1) sets how many 10,000-domain pages a search may buy.
* **Failures**: the key travels only in the request body; it is never put in a URL, the cache or a log, and is scrubbed from error messages. On an error (bad key, no credits left) the source stops and says why in the notes; the rest of the run carries on.

## Data files

`src/domainfinder/data/`:

* `cctlds.txt` and `gtlds.txt`
* `shared_dns_providers.txt` and `selectable_dns_providers.txt`
* `shared_mail_providers.txt`
* `shared_spf_includes.txt`
* `shared_hosting_orgs.txt`
* `parking_providers.txt` and `parking_markers.txt`
* `holding_pages.txt`
* `brand_protection_registrars.txt`
* `privacy_proxies.txt`
* `common_third_party.txt` (domains never offered as candidates)

Each file has one entry per line, and `#` starts a comment.

## Caching, etiquette and safety

* Passive lookups only: DNS, RDAP, CT logs, one homepage fetch and one TLS handshake per domain. No port scanning.
* The User-Agent identifies the tool. Each host gets its own concurrency limit and request spacing (crt.sh: 2 at a time, 1 s apart). On 429/5xx the tool backs off exponentially and honours `Retry-After` (capped at 60 s).
* Responses are cached in an sqlite file under `~/.cache/domainfinder/` (`DOMAINFINDER_CACHE_DIR`). The default lifetime is 24 hours; RDAP and CT responses are kept 3 days and the IANA bootstrap files 7 days. Use `--no-cache` to bypass the cache.

## Known limitations

* **Many acquisition domains are only reachable with reverse WHOIS, reverse NS or reverse MX**, which in practice means the paid sources. Expect the free version to miss some. The [`adp.com` sample run](adp-sample-run.md) shows which source would have found each miss.
* **ccTLD RDAP is patchy.** Many ccTLDs have no public RDAP, or answer 403/404 (seen: .de, .es, .it, .co.jp, .ie, .be, .ch, .com.au). For those the tool relies on DNS, IP, certificate and redirect evidence alone. WHOIS over port 43 is used only for `.edu`, which has no RDAP; some networks block port 43, in which case `.edu` registrations are invisible too.
* **Registrant data is usually redacted** to a region ("NJ, US"). `DNStination Inc.` is MarkMonitor's privacy proxy, not the owner. CSC goes further and writes its own name and Delaware address into the registrant fields of domains it manages. A registrant named after the registrar, a brand-protection registrar or a privacy service is therefore treated as a proxy: its name never counts as the owner's, and its region is ignored.
* **crt.sh is slow and flaky** (502s on large queries) and caps a result set at 10,000 rows. Queries are retried and cached; failures show up under `-v` notes.
* **Live TLS `O=` needs a direct connection.** Behind a TLS-intercepting proxy, the certificate the tool sees is the proxy's, so that check yields nothing. The CT-log evidence (`crtsh-org`) still works.
* **Bot protection** on some sites answers the homepage fetch with 403. The redirect chain up to that point is still used.
* **Sites behind shared hosting and bot protection.** University athletics and campaign sites often run on shared hosts behind a bot-blocking firewall, with privacy-protected registrations. The tool then sees no shared infrastructure; when the seed's homepage links to such a domain and the name carries the brand, it lands in *needs review*.
* **"Operated by" is not "owned by."** A current certificate with the seed's `O=` can mean a site the seed hosts for a client (ADP runs benefits portals for its customers). Such domains usually land in *needs review*.

## Development

```bash
pip install -e '.[dev]'
pytest
```

The tests use recorded RDAP fixtures and mocked HTTP (`respx`). A guard in `tests/conftest.py` makes any real network connection fail.

## License

MIT
