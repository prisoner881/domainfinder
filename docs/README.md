# domainfinder

Give it one root domain (`adp.com`). It returns a list of other domains run by the same company, each with a score and the evidence behind it.

```
domainfinder adp.com
```

No public source lists everything a company owns, so the tool does not try to be complete. It aims for **precision**: a domain reaches the main list only when independent evidence ties it to the seed. A domain that only *looks* related goes to a separate **needs review** list (for example, a name match plus a parking page). It never reaches the main list.

Current version: **1.1.0** (see [CHANGELOG.md](CHANGELOG.md)). Every run starts with a small framed banner naming the tool and its version, printed on stderr so `--json` output stays clean. When stderr isn't a terminal (logs, pipes, CI), the banner is the plain line `domainfinder 1.1.0`. `domainfinder --version` prints that line too.

Free sources work out of the box. WhoisXML API's reverse WHOIS turns on with an API key (a free account includes 500 credits). SecurityTrails and DomainTools are built in as switched-off stubs that turn on once their keys are configured.

## Results for `adp.com`

[adp-sample-run.md](adp-sample-run.md) compares a run made with an early 0.9 build against the handoff's acceptance list; later versions add sources and evidence, so current numbers differ somewhat. Free sources alone found 370 high-confidence domains, put 16 in needs review and rejected 105. Every expected-rejected domain was rejected (`adp.fr` = Aéroports de Paris, parked look-alikes, Broadridge's ex-ADP domains). The 33 expected-owned domains the free sources discovered were all classified owned.

## Install

Python 3.11+.

```bash
pip install -e .            # or: pip install -e '.[dev]' for the tests
cp .env.example .env        # optional: keys and settings
```

Or let `start-venv.sh` do it. It activates the project's virtual environment (`.venv`), creating it and installing domainfinder with the test extras the first time. Source it rather than running it, so the environment stays active in your shell. Run it as `./start-venv.sh` and it just tells you that.

```bash
source start-venv.sh        # from anywhere: source ~/domainfinder/start-venv.sh
deactivate                  # to leave the venv
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

### Root-domain check

Input lists are not always right, so before anything else the tool checks that the supplied domain really is the organization's root domain. The run always continues with the domain as supplied. If the check fails, the output says so loudly and names the suggested real root.

The supplied root **looks wrong** when:
* it isn't registered;
* it's parked or for sale;
* it's a registrar holding page (registered but unused);
* its website **redirects to another domain**;
* its homepage declares its canonical address (`<link rel="canonical">` or `og:url`) on another domain.

**Check the root** (an advisory, shown in yellow) appears when:
* its nameservers and mail servers are both run from another domain, or from another domain carrying the same brand (a parent organization?);
* it has no website and no mail at all.

The suggested real root is the redirect target first, then the canonical address, then that parent domain. Next to it, the tool lists what else corroborates it: the same brand in both names, the supplied domain's DNS, mail or `www` alias pointing at it, its TLS certificate or CSP covering it. When nothing corroborates the suggestion, it says so. A login portal that redirects to a third-party sign-in service shouldn't be presented as owned by that service.

The suggested root is also added as a candidate, so its verification shows up in the results. Where the flag appears:

* **Table:** a red banner at the top *and* the bottom.
* **JSON:** a top-level `root_check` object (`status`: `ok` / `wrong` / `advisory`, plus `suggested`, `reasons`, `advisories`, `corroboration` and `headline`).
* **CSV:** a `root_warning` column filled on every row, and a first row for the supplied root itself (classification `seed`), so the warning survives even when no other domain qualifies.
* **stderr:** a banner when writing JSON or a file.
* **Exit code:** `3` when the root looks wrong (the run still completes), instead of `0`.

A supplied host name (`www.example.com`) is reduced to its registrable domain and noted.

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

Other options: `--all-tlds` (sweep every TLD, not just the common ones), `--brand` (extra brand labels for the ccTLD sweep), `--sources` / `--skip` (pick sources), `--max-candidates` (default 1000), `--concurrency`, `--dns auto|system|doh`, `--no-tls`, `--no-whois`, `--no-crtsh-db`, `--no-csp`, `--no-cache`, `--cache-ttl HOURS`, `--high-threshold`, `--review-threshold`, `--no-hackertarget`, `--debug`.

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

**Nameserver sets are double-checked when they only partly match the seed's.** A resolver sometimes answers an NS query with the registry's delegation, which for some ccTLDs lists only part of the set, so the same domain could match 10/10 on one run and 6/10 on the next. When a domain (or the seed itself) shares some but not all nameservers with the seed, the tool asks one of the domain's own nameservers directly and uses its authoritative answer. This never loosens the comparison; it only makes sure the full set is compared. If direct DNS queries (port 53) are blocked or intercepted on your network, the check gives up after five failures and the resolver's answer is used as before. A `-v` note says how many sets were re-read and how many changed.

### crt.sh: database first, web API second

Every crt.sh search (`crtsh-org`, `crtsh-san`, `acq-ct`, and the seed's organization name) goes first to crt.sh's public, read-only PostgreSQL database (`guest@crt.sh:5432`, database `certwatch`), using the same SQL crt.sh's own search runs. If that fails for any reason, the same search goes to crt.sh's web API.

* **Why:** the web API stops every search at 10,000 rows and its front end is often overloaded (404/502/504). The database fetches only the columns needed and allows up to 50,000 rows per search (`DOMAINFINDER_CRTSH_DB_LIMIT`). Each database search may take up to 300 seconds (`DOMAINFINDER_CRTSH_DB_TIMEOUT`); a large organization's full certificate history needs minutes.
* **Falling back:** if the first connection is refused or blocked (many networks block outbound port 5432), the database is off for the rest of the run (about 10 seconds lost at most). After that, a failed query or reconnect falls back for that search only; three failures in a row turn the database off. crt.sh's pooler works statement by statement (no transactions, no session settings), so the time limit is enforced by the tool: a query that runs too long is cancelled and the connection kept. IPv4 addresses are tried before IPv6. crt.sh's connection pooler closes idle connections, so a connection unused for 30 seconds is replaced, and a query whose connection was closed under it is retried once on a new one. A missing `psycopg` driver also means web API only.
* **What you see:** with `-v`, a note says how many searches the database answered, lists the searches that failed and why, and says why the database was turned off, if it was. `crtsh-org`'s truncation note names the limit that applied.
* **Turning it off:** `--no-crtsh-db` or `DOMAINFINDER_CRTSH_DB=0`.
* It is the same data from the same operator: when crt.sh is down entirely, both routes fail.

### 2. Candidate sources

| Source | Free | What it does |
|---|---|---|
| `crtsh-org` | ✓ | crt.sh certificates whose Subject `O=` is the seed's organization: current and expired, with recency recorded. The strongest free source. |
| `crtsh-san` | ✓ | Other registrable domains in the SANs of the seed's current certificates. |
| `cctld` | ✓ | The brand label on ~80 country-code suffixes (`data/cctlds.txt`). An NS/SOA lookup first; only registered names go on to verification. |
| `gtld` | ✓ | The brand label on ~35 common generic TLDs (`data/gtlds.txt`: `.net`, `.org`, `.info`, `.biz`, `.io`, `.ai`, `.app`, `.dev`, …), checked the same way. `--all-tlds` uses IANA's list of every TLD instead (about 1,400, fetched live and cached for a week). |
| `seed-links` | ✓ | Domains linked from the seed's homepage, its CSP header and its live certificate. |
| `csp` | ✓ | A second pass, one hop out: domains named in the Content-Security-Policy of owned and needs-review domains become candidates and are verified like any other. Turn it off with `--no-csp`. |
| `cert-san` | ✓ | Same second pass: domains on the (publicly trusted) TLS certificate of owned and needs-review domains. A certificate naming more than three other domains is skipped unless one of them is the seed or an owned domain (needs-review domains don't count: two of them on one vendor certificate prove nothing). |
| `acq-ct` | ✓ | Same second pass: when an owned domain proven by two or more infrastructure matches carries another company's name on its certificate or registration (an acquisition), crt.sh is searched for certificates in that name too. Up to five names. Such a certificate shows that the named company controls a domain, not that the seed does (the name may belong to a joint-venture partner or a client), so it is medium evidence and never enough for the main list by itself. Turn it off with `DOMAINFINDER_ACQUISITIONS=0`. |
| `edgar` | ✓ | SEC EDGAR Exhibit 21 subsidiaries → `<name>.com` guesses. Needs `DOMAINFINDER_SEC_USER_AGENT` (SEC policy). |
| `wikidata` | ✓ | Wikidata: finds the organization whose official website is exactly the seed, then its subsidiaries' official websites ("has subsidiary", "parent organization", "owned by"; one level). Turn it off with `DOMAINFINDER_WIKIDATA=0`. If Wikidata answers HTTP 403, set `DOMAINFINDER_CONTACT` (Wikimedia asks automated clients for contact details; sent to Wikidata only). |
| `hackertarget` | ✓ | Reverse NS (`findshareddns`). For managed-DNS pools it intersects several of the seed's NS hosts, which approximates "same NS set". Small daily quota; turn it off with `--no-hackertarget`. |
| `viewdns` | free key | Reverse NS and reverse MX. Needs `VIEWDNS_API_KEY`. |
| `securitytrails` | paid | Stub: reverse WHOIS / NS / MX, associated domains. |
| `whoisxml` | free key / paid | Reverse WHOIS: domains whose registrant organization is *exactly* the seed's (plus punctuation variants), in current and historic WHOIS. A current match is strong evidence; a historic-only match is weak. See [WhoisXML reverse WHOIS](#whoisxml-reverse-whois). |
| `domaintools` | paid | Stub: Iris reverse WHOIS, NS/IP/email pivots, passive DNS. |

### 3. Scoring

Each rule adds an evidence item with points (the weights are in `verify.py → WEIGHTS`). The table lists each item's full weight; how items combine is described under [Evidence channels](#evidence-channels).

| Evidence | Strength | Points |
|---|---|---|
| Redirect chain reaches the seed or an already-verified domain | strong | 60 |
| NS / MX / `www` CNAME hosted under the seed's (or a verified) domain | strong | 50 |
| Same **dedicated** NS set (Jaccard ≥ 0.5 on own hosts; ≥ 0.75 and ≥ 3 hosts on managed-DNS pools such as Akamai or NS1) | strong | 50 |
| Same mail tenant ID / same dedicated MX host | strong | 50 / 45 |
| IP in a netblock registered to the seed's organization (or the seed's own non-CDN netblock) | strong | 50 |
| Same TXT verification token | strong | 50 |
| Live TLS certificate `O=` matches the seed's organization | strong | 50 |
| Live TLS certificate shared with the seed or a verified domain: it also covers one of them, the seed's certificate covers the candidate, it is the identical certificate, or it uses the same public key | strong | 55 |
| A current certificate in CT logs covers both the candidate and the seed (same shared-certificate guard; not added twice when the live certificate already links) | strong | 50 |
| DMARC reports go to the seed (or a verified domain) **and** that domain's DNS specifically authorizes them (`<domain>._report._dmarc.<host>`, not a wildcard) | strong | 50 |
| Same customer-specific DMARC reporting address at a vendor as the seed | medium | 25 |
| DMARC reports addressed to the seed without specific authorization (anyone can write the address) | weak | 10 |
| RDAP registrant org matches | strong | 60 |
| A WHOIS/RDAP contact email (registrant, admin, technical, billing) at the seed's or a verified domain | strong | 50 |
| Same contact email (off the seed's domain), phone or street address as the seed's registrant/admin contacts | medium | 25 each |
| CT: a current certificate with `O=` the seed's org | strong | 45 |
| CT: only expired certificates with that `O=` (divested? e.g. broadridge.com) | weak | 15 |
| CT: current / only expired certificates in an acquired company's name (`acq-ct`) | medium / weak | 25 / 5 |
| The candidate's own Content-Security-Policy (from its own page) trusts two or more domains that are the seed or already verified | strong | 50 |
| Its CSP trusts only the seed, and the name carries the brand / and it doesn't | medium / weak | 35 / 10 |
| Same analytics/tag ID (on the candidate's own page) | medium | 25 |
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

#### Evidence channels

Several evidence items often come from one underlying fact: one mail setup gives the mail tenant, the SPF include and the DMARC address, and one WHOIS record gives the registrant organization, contact email, phone and street. Simply adding their points would count one fact several times. So each item belongs to a channel (`verify.py → CHANNELS`):

| Channel | Evidence |
|---|---|
| delegation | nameservers under the seed's domain, same NS set |
| zone | SOA contact (the authoritative servers actually serve the zone) |
| mail | mail tenant, dedicated MX host, MX under the seed's domain, SPF, DMARC |
| hosting | netblock, `www` CNAME under the seed's domain |
| token | TXT verification token |
| certificate | live certificate link or organization, CT co-certificate, CT organization |
| website | redirect, CSP, analytics ID, link from the seed's site |
| registration | registrant organization (RDAP, WhoisXML), WHOIS contacts, registrar and region, holding page, brand-named registrant |
| name | brand in the name, SEC subsidiary |

Within a channel, the strongest item counts in full, the second at 50% and the rest at 25%. Channels are run by different people through different systems, so they add up in full. When two or more channels (not counting *name*) carry medium or strong evidence, and at least one item is strong, a `corroboration` item adds 5 points per agreeing channel beyond the first, up to 15. The points shown in the output are the counted points, so they still add up to the score; a discounted item says so ("more mail evidence: 50% counted").

Guards that keep false positives out:

* **Shared infrastructure never counts.** NS hosts at mass providers are listed in `data/shared_dns_providers.txt`: Cloudflare, GoDaddy `domaincontrol.com`, Route 53 `awsdns-*`, Azure, Google, Wix, Squarespace, registrar defaults and more. Managed-DNS pools (Akamai `akam.net`, NS1, UltraDNS, Dyn) are only compared as a *whole set*. Netblocks owned by clouds and CDNs are ignored (`data/shared_hosting_orgs.txt`). Shared MX and SPF targets only count when they carry a tenant ID. Nameservers that aren't on either list are checked with reverse-NS data. One whose host serves 200 or more domains is treated as shared DNS infrastructure (a DNS provider, or a company's public DNS service such as Oracle's `oraclecloud.net`). Its domains aren't pulled in as candidates, "nameservers under it" doesn't count as evidence, and it can only match as a whole set. If a paid reverse-NS source reports that an NS host serves more than `DOMAINFINDER_SHARED_NS_THRESHOLD` domains, NS matching is turned off.
* **Certificate links only count when they prove control.** A certificate counts only if it carries Certificate Transparency timestamps. Publicly trusted certificates do; certificates minted by a TLS-intercepting proxy normally don't. It must also cover the name it was served for, because a server's default certificate shown for a name that someone else's DNS points at it proves nothing. A certificate covering more than three other registrable domains counts only when at least half of them are the seed's or verified, which excludes CDN and hosting certificates shared by unrelated customers.
* **A redirect is counted once.** Analytics IDs and the CSP header only count when they come from the candidate's own page. After a redirect to the seed, the page is the seed's, and counting its tags would score the redirect twice. A typosquat that redirects to the real site would otherwise inherit the real site's evidence. A redirect alone (60) reaches *needs review*; one independent link (registrar and region, nameservers, mail tenant, certificate, registrant) puts it on the main list.
* **Weak evidence is never enough.** The main list needs at least one strong item.
* **Owned means operated, not just registered.** The main list also needs at least one item showing the organization *controls* the domain: its DNS, mail, network, a verification token, a certificate link or certificate in its name, a redirect into its sites, a registrant organization match, or a contact email at its domain (`verify.py → CONTROL_KINDS`). Registration similarity alone (same brand-protection registrar and region, holding page, brand in the name, past certificates, matching phone or street address) stops at *needs review* with a `registration_only` note, however high it adds up. In an audit of an ADP run, every owned domain with control evidence was confirmed; the parked, registration-only ones were probably ADP's but could not be proven.
* **Contact data is used only where it is published.** Most gTLD contacts are redacted since 2018; placeholders ("REDACTED FOR PRIVACY", web-form URLs) are ignored. The registrar's, its abuse desk's and privacy-proxy contacts never count, technical contacts (often the registrar's or a DNS host's) are not compared with the seed's, and evidence text never prints an email address or phone number.
* **A name match is not ownership.** A registrant or certificate that names another organization blocks the main list, unless two independent infrastructure matches (in different channels) agree (acquisitions keep their old legal names). With any strong evidence for the seed, such a conflict goes to *needs review* rather than being rejected.
* **Parked domains** go to *needs review* when their registration matches the seed's (a possible defensive registration), and are rejected otherwise.
* **Holding pages.** Brand-protection registrars park unused client domains (MarkMonitor: `15.197.70.98`, `ns*.markmonitor.com`). Since 1.3.0 a held domain is owned only with control evidence (for example a contact email at the seed's domain or a current certificate in its name); when the registrar and registrant region match the seed's *and* the brand is in the name or CT logs show past certificates issued to the seed's organization, it scores just under the threshold (69) in *needs review*. A held domain with only the registrar and region in common goes to *needs review*, as does a brand-named one at the same registrar but in another region. Where the registry publishes no registration data (many ccTLDs), a domain parked on the holding infrastructure of the seed's own brand-protection registrar counts as at that registrar (`data/holding_pages.txt` names the registrar of each holding address and nameserver domain): with a redirect to the seed it is owned, without one it needs review.
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
* crt.sh's database is used with one connection per run, one query at a time, as its read-only `guest` account intends.
* The User-Agent identifies the tool. Each host gets its own concurrency limit and request spacing (crt.sh: 2 at a time, 1 s apart). On 429/5xx the tool backs off exponentially and honours `Retry-After` (capped at 60 s).
* Responses are cached in an sqlite file under `~/.cache/domainfinder/` (`DOMAINFINDER_CACHE_DIR`). The default lifetime is 24 hours; RDAP and CT responses are kept 3 days and the IANA bootstrap files 7 days. Use `--no-cache` to bypass the cache.

## Known limitations

These two are deliberate. The main list is consumed automatically, so it uses only high-confidence technical evidence of control, never corporate records alone:

* **Newly acquired companies appear only once their infrastructure links them.** A company the seed has just acquired usually keeps its own DNS, mail, certificates and registration for months or years. Until something technical connects it to the seed, its domains aren't found or don't qualify. Example: Global Payments completed its Worldpay acquisition in January 2026, and a November 2026 run lists no Worldpay domains. Acquisition filings (SEC 8-K, Exhibit 21, press releases) name legal entities, not domains. Mapping a name to a domain means guessing, and similarly named companies make that unreliable, so the tool doesn't try. As an acquired company moves onto the seed's infrastructure, its domains qualify through the normal evidence.
* **Domains of divested businesses stay on the list while the seller still controls them.** After a sale, the seller often keeps a business's domains registered, served and certified in its own name, typically while it runs systems for the buyer during a transition. The tool reports who controls a domain, not who owns the business, so these domains stay owned until the registration, DNS and certificates move to the buyer. Example: Global Payments still controls domains of its divested payroll, Issuer Solutions and gaming businesses; heartlandplusone.com is registered to Global Payments and on its DNS, but already redirects to the buyer's auris.io.

* **Many acquisition domains are only reachable with reverse WHOIS, reverse NS or reverse MX**, which in practice means the paid sources. Expect the free version to miss some. The [`adp.com` sample run](adp-sample-run.md) shows which source would have found each miss.
* **ccTLD RDAP is patchy.** Many ccTLDs have no public RDAP, or answer 403/404 (seen: .de, .es, .it, .co.jp, .ie, .be, .ch, .com.au). For those the tool relies on DNS, IP, certificate and redirect evidence alone. WHOIS over port 43 is used only for `.edu`, which has no RDAP; some networks block port 43, in which case `.edu` registrations are invisible too.
* **Registrant data is usually redacted** to a region ("NJ, US"). `DNStination Inc.` is MarkMonitor's privacy proxy, not the owner. CSC goes further and writes its own name and Delaware address into the registrant fields of domains it manages. A registrant named after the registrar, a brand-protection registrar or a privacy service is therefore treated as a proxy: its name never counts as the owner's, and its region is ignored.
* **crt.sh is slow and flaky.** Its web API answers large queries with 502s and caps a result set at 10,000 rows. The tool queries crt.sh's public database first (50,000 rows per search) and falls back to the web API; web queries are retried, everything is cached, and failures show up under `-v` notes. Networks that block outbound port 5432 get the web API only.
* **Live TLS evidence needs a direct connection.** Behind a TLS-intercepting proxy, the certificate the tool sees is the proxy's. The tool notices (no CT timestamps) and skips live-certificate comparisons, saying so in the notes. The CT-log evidence (`crtsh-org`) still works.
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
