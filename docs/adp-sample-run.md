# Sample run: `adp.com` (2026-11-26)

Two files sit next to this report:

* [`adp-sample-run.txt`](adp-sample-run.txt): the full table output (`-v`, so rejected rows are included).
* [`adp-sample-run.csv`](adp-sample-run.csv): the CSV export (owned and needs review).

The run used free sources only. The paid stubs, `edgar` (no SEC User-Agent configured) and `viewdns` (no key) were off.

```bash
domainfinder adp.com -v -o adp-sample-run.csv \
  --candidate adpportal.com --candidate sora.co …   # the §7 domains the free sources did not find
```

The `--candidate` flags force the handoff's §7 domains through verification even when no free source finds them. That tests discovery and classification separately. Without the flags, the run is identical except that the 21 domains no source found are absent (`workforcesoftware.com` is found by `seed-links` anyway).

## Totals

| | |
|---|---|
| Seed organization (from CT: Subject O= of adp.com's OV/EV certificates) | Automatic Data Processing, Inc. |
| Seed fingerprint | NS = 4 × `p01.nsone.net` + 6 × `akam.net`; MX tenant `proofpoint:0006eb01`; ARIN `ADP-ESNET` 170.146.0.0/16; MarkMonitor, registrant region NJ, US |
| Candidates found / verified | 491 / 491 (470 from sources, 21 more forced from §7) |
| **High-confidence (owned)** | **370** (231 active, 43 redirecting, 61 registered without web or mail, 15 held/inactive, 12 resolving without a web response, 8 mail only) |
| Needs review | 16 |
| Rejected | 105 |
| Run time | about 5–6 min with a cold cache, about 1 min warm |

Contributions by source among the owned domains (a domain can come from several sources):

* `hackertarget` reverse NS (intersection of three of ADP's managed-DNS hosts): 251
* `crtsh-org`: 156
* `cctld`: 21
* `crtsh-san`: 6
* `seed-links`: 4

Most owned domains share ADP's exact 10-host nameserver set *and* name `hostmaster@adp.com` in the SOA. These are defensive registrations (`adp.bio`, `adp.careers`, `adp-payroll.com`, …) and client portals ADP runs on its own DNS, network and certificates.

## §7 scorecard

| | Expected | Discovered by free sources | Classified correctly |
|---|---|---|---|
| Owned | 43 | 33 | 33 of 33 discovered (37 of 43 once all are forced through verification) |
| Rejected | 18 | 8 (the ccTLD sweep) | 18 of 18 |
| Needs review | 1 (`adpvantage.com`) | 0 | 1 of 1 |

**No false positives:** none of the 18 expected-rejected domains reached the main list. Other domains kept off the main list include:

* Broadridge (spun off from ADP in 2007): `broadridge.com`, `proxyvote.com` and others have only pre-2009 certificates with O=ADP and are now registered to Broadridge.
* Client-branded benefit portals whose registrant is the client (CarMax, JPMorgan Chase, United Airlines, Aon, …).
* `formyinfo.com` (registered to Sempra Energy, though it redirects to adp.com) and `mymetlifebenefitsonline.com` (on ADP's netblock, but registered to MetLife). Both went to *needs review*: two signals disagree, so a person should decide.

### Expected owned

| Domain | Result | Score | Found by (free) | Main evidence |
|---|---|---|---|---|
| adp.ca | owned | 100 | crtsh-org, cctld, seed-links, hackertarget | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); IP in ARIN ADP-ESNET 170.146.0.0/16 (Automatic Data Processing, Inc.) |
| adpchina.com | owned | 100 | crtsh-org, seed-links | IP in ARIN ADP-ESNET 170.146.0.0/16 (Automatic Data Processing, Inc.); CT: current certificate O=Automatic Data Processing, Inc. (valid to 2027-02-24) |
| adpemploymentreport.com | owned | 100 | crtsh-org, hackertarget | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); CT: current certificate O=Automatic Data Processing, Inc. (valid to 2027-04-11) |
| adp.net | owned | 100 | cctld, hackertarget | www CNAME to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adppayroll.com.au | owned | 100 | crtsh-org, hackertarget | MX under adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adpportal.com | owned | 100 | — (not discovered; given with --candidate) | redirects to adp.com; held/inactive at the seed's brand-protection registrar, same registrant region, brand name |
| adpselect.com | owned | 100 | crtsh-org, hackertarget | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); CT: current certificate O=Automatic Data Processing, Inc. (valid to 2027-02-13) |
| adpworld.de | owned | 100 | crtsh-org, hackertarget | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); same mail tenant proofpoint:0006eb01 |
| myadp.com | owned | 100 | crtsh-org | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| oneadp.com | owned | 100 | crtsh-org, crtsh-san | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); CT: current certificate O=Automatic Data Processing, Inc. (valid to 2027-04-30) |
| pequity.com | owned | 100 | crtsh-org | same mail tenant proofpoint:0006eb01; CT: current certificate O=Automatic Data Processing, Inc. (valid to 2027-02-18) |
| workforcesoftware.com | owned | 100 | seed-links | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); same mail tenant proofpoint:0006eb01 |
| sora.co | owned | 100 | — (not discovered; given with --candidate) | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| securtime.com | needs review | 50 | — (not discovered; given with --candidate) | held/inactive at the seed's brand-protection registrar, same registrant region; same registrar (Markmonitor Inc.) and registrant region (NJ, US) |
| securtime.in | owned | 75 | — (not discovered; given with --candidate) | held/inactive at the seed's brand-protection registrar, same registrant region, registrant carries the brand name; RDAP registrant ADP, Inc. carries the brand name |
| securax.com | needs review | 50 | — (not discovered; given with --candidate) | held/inactive at the seed's brand-protection registrar, same registrant region; same registrar (Markmonitor Inc.) and registrant region (NJ, US) |
| celergo.com | owned | 100 | — (not discovered; given with --candidate) | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); same mail tenant proofpoint:0006eb01 |
| workmarket.com | owned | 100 | crtsh-org | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); same mail tenant proofpoint:0006eb01 |
| globalcashcard.com | owned | 100 | crtsh-org | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); same mail tenant proofpoint:0006eb01 |
| tmbc.com | owned | 100 | crtsh-org | redirects to adp.com; held/inactive at the seed's brand-protection registrar, same registrant region, past certificates in the seed's name |
| marcusbuckingham.com | needs review | 50 | — (not discovered; given with --candidate) | held/inactive at the seed's brand-protection registrar, same registrant region; same registrar (Markmonitor Inc.) and registrant region (NJ, US) |
| workscape.com | owned | 80 | crtsh-org | held/inactive at the seed's brand-protection registrar, same registrant region, past certificates in the seed's name; CT: only expired certificates O=Automatic Data Processing, Inc. (last 2019-03-12) |
| asparity.com | owned | 100 | crtsh-org | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); same mail tenant proofpoint:0006eb01 |
| airsdirectory.com | owned | 100 | crtsh-org, hackertarget | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); same mail tenant proofpoint:0006eb01 |
| mastertax.com | owned | 100 | crtsh-org | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); IP in ARIN ADP-ESNET 170.146.0.0/16 (Automatic Data Processing, Inc.) |
| virtualedge.com | owned | 80 | crtsh-org | held/inactive at the seed's brand-protection registrar, same registrant region, past certificates in the seed's name; CT: only expired certificates O=Automatic Data Processing, Inc. (last 2019-12-18) |
| mywisely.com | owned | 100 | crtsh-org | MX under adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| activatewisely.com | owned | 100 | crtsh-org, hackertarget | redirects to mywisely.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| wiselypay.com | owned | 100 | crtsh-org | redirects to adp.com; MX under adp.com |
| alinecard.com | needs review | 50 | — (not discovered; given with --candidate) | held/inactive at the seed's brand-protection registrar, same registrant region; same registrar (Markmonitor Inc.) and registrant region (NJ, US) |
| rollbyadp.com | owned | 100 | crtsh-org | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); IP in ARIN ADP-ESNET 170.146.0.0/16 (Automatic Data Processing, Inc.) |
| adptotalsource.com | owned | 100 | crtsh-org, hackertarget | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adpresearch.com | owned | 100 | crtsh-org, seed-links, hackertarget | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); CT: current certificate O=Automatic Data Processing, Inc. (valid to 2027-03-26) |
| adpri.org | owned | 100 | crtsh-org, hackertarget | redirects to adpresearch.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adpventures.com | needs review | 40 | — (not discovered; given with --candidate) | held/inactive at the seed's brand-protection registrar, brand name (registrant region CA, US ≠ NJ, US); brand 'adp' in name |
| workforcenow.com | needs review | 50 | — (not discovered; given with --candidate) | held/inactive at the seed's brand-protection registrar, same registrant region; same registrar (Markmonitor Inc.) and registrant region (NJ, US) |
| elabor.com | owned | 100 | crtsh-org | same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00); CT: current certificate O=Automatic Data Processing, Inc. (valid to 2027-03-11) |
| adp.co.uk | owned | 100 | crtsh-org, cctld, hackertarget | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adp.com.br | owned | 100 | crtsh-org, crtsh-san, cctld, hackertarget | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adp.in | owned | 100 | crtsh-org, cctld, hackertarget | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adp.nl | owned | 100 | crtsh-org, cctld, hackertarget | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adp.ch | owned | 100 | crtsh-org, cctld, hackertarget | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |
| adp.pl | owned | 100 | crtsh-org, cctld, hackertarget | redirects to adp.com; same managed-DNS nameserver set (10/10 hosts, Jaccard 1.00) |

### The six that did not reach the main list, and why

They are all MarkMonitor holding-page domains: `ns*.markmonitor.com` / `ha*.markmonitor.zone` nameservers, IP 15.197.70.98, no web content of their own.

* **`securtime.com`, `securax.com`, `alinecard.com`, `marcusbuckingham.com`, `workforcenow.com`**: the only link to ADP is "MarkMonitor + registrant region NJ, US". The handoff ranks registrar + region as *weak, never sufficient alone*, and MarkMonitor has many New Jersey clients. So these stay in *needs review* (score 50). The tool moves one of them to the main list when the brand is in the name, when CT shows past certificates issued to ADP, or when the registrant reads "ADP, …" (that is how `securtime.in`, `workscape.com`, `virtualedge.com` and `adpportal.com` got there).
* **`adpventures.com`**: data drift. Its RDAP registrant is now DNStination (MarkMonitor's privacy proxy) with region **CA**, US, not NJ. Brand in the name + MarkMonitor + holding page puts it in *needs review* (score 40).

To find (and confirm) these, use **historic reverse WHOIS** on "Automatic Data Processing": WhoisXML API (historic search) or DomainTools Iris. Holding-page domains share MarkMonitor's nameservers with every other MarkMonitor client, so reverse NS cannot single them out.

### Expected owned that free sources did not discover

The handoff predicted acquisition domains would need paid sources. In this run, `crtsh-org` (current *and* expired certificates with O=ADP) found `elabor.com`, `asparity.com`, `workscape.com`, `virtualedge.com`, `mastertax.com`, `airsdirectory.com`, `globalcashcard.com` and `pequity.com`. The ten domains below were found by none of the free sources:

| Domain | Would be found by |
|---|---|
| `celergo.com`, `sora.co` | **Reverse NS** on ADP's NS set (SecurityTrails, DomainTools, ViewDNS with a key). HackerTarget's free tier truncates large result sets, so its intersection missed them. Verification then classifies both as owned (same NS set, same mail tenant / redirect to adp.com). |
| `adpportal.com` | **Reverse WHOIS** (WhoisXML historic / DomainTools); it is on MarkMonitor's holding NS. Verification: owned (redirects to adp.com). |
| `securtime.com`, `securtime.in`, `securax.com`, `alinecard.com`, `marcusbuckingham.com`, `workforcenow.com`, `adpventures.com` | **Historic reverse WHOIS** only (see above). |

### Expected rejected / needs review

| Domain | Result | Found by (free) | Why |
|---|---|---|---|
| adpworkforce.com | rejected | — (given with --candidate) | parking/for-sale service ns1.parkingcrew.net |
| adpemployment.com | rejected | — (given with --candidate) | not registered (NXDOMAIN) |
| therightthing.com | rejected | — (given with --candidate) | parking/for-sale service ns1.afternic.com |
| rightthing.com | rejected | — (given with --candidate) | parking/for-sale service ns1.atom.com |
| lifion.com | rejected | — (given with --candidate) | parking/for-sale service ns1.afternic.com |
| trysora.com | rejected | — (given with --candidate) | parking/for-sale service ns1.afternic.com |
| adpmarketplace.com | rejected | — (given with --candidate) | RDAP registrant is HugeDomains.com; parking/for-sale service nsg1.namebrightdns.com |
| adp.fr | rejected | cctld | redirects to unrelated parisaeroport.fr; RDAP registrant is Aéroports de Paris |
| adp.de | rejected | cctld | active (HTTP 200) |
| adp.es | rejected | cctld | parking/for-sale service ns1.sedoparking.com |
| adp.it | rejected | cctld | redirects to unrelated retepreghierapapa.it |
| adp.co.jp | rejected | cctld | active (HTTP 503) |
| adp.ie | rejected | cctld | active (HTTP 200) |
| adp.com.au | rejected | cctld | active (HTTP 200) |
| adp.be | rejected | cctld | parking/for-sale service 0v2j4i.ns3.nameshift.com |
| adpfoundation.org | rejected | — (given with --candidate) | active (HTTP 200) |
| adpfoundation.com | rejected | — (given with --candidate) | parking page ('this domain may be for sale') |
| nationalemploymentreport.com | rejected | — (given with --candidate) | active (HTTP 200) |
| adpvantage.com | needs review | — (given with --candidate) | parking/for-sale service ns1.abovedomains.com |

The free sources did not discover most of the expected-rejected domains at all, which is fine: they were forced through verification only to prove the rejection logic. `adp.de`, `adp.ie`, `adp.com.au`, `adp.co.jp` and `nationalemploymentreport.com` show no ownership evidence (their score is the brand label's 5 points at most). `adpfoundation.org` (American Dental Partners Foundation) likewise.

## Environment notes for this run

* The run was made from a sandbox whose egress proxy re-signs TLS certificates. As a result, the *live* certificate check never saw a real Subject O= in this run, and all certificate-organization evidence came from CT logs (`crtsh-org`). Run locally, the live check adds evidence for the active sites.
* The sandbox's system resolver does not answer, so DNS went over DNS-over-HTTPS (dns.google), as the `auto` mode intends.
* crt.sh's organization query hit its 10,000-row cap (noted in the output). Current certificates are queried separately (`exclude=expired`), so the cap only truncates the historic tail.
