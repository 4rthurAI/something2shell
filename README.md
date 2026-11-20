# Something2shell

A defensive tracker for the 2026 wave of "\*2Shell" vulnerabilities: critical remote code execution bugs and exploit chains with a "&lt;something&gt;2Shell" nickname. The repo also hosts [`something2shell_check.py`](something2shell_check.py), a detection script that checks whether a Linux host runs an affected version. See [Detection script](#detection-script) to run it.

**Last updated:** 2026-11-20
**Maintainer:** 4rthur

> **Defensive use only.** This repo contains no exploit code and no exploitation steps, and it does not link to exploit repositories. Where a public proof of concept (PoC) exists, the tracker says so and names who published it. References point to vendor advisories, CVE records, CISA and research write-ups.

---

## Tracker

Newest first. Status and KEV columns reflect the date above.

| Name | CVE(s) | Product | Disclosed | Status | CISA KEV added |
|---|---|---|---|---|---|
| [Ruby2Shell](#ruby2shell) | CVE-2026-132825 | Ruby | 2026-11-18 | Patched | — |
| [NGINX2Shell](#nginx2shell) | CVE-2026-123007, CVE-2026-123633, CVE-2026-123634, CVE-2026-121810, CVE-2026-113425 | nginx / NGINX Plus | 2026-11-18 | Public PoC | — |
| [Java2Shell](#java2shell) | CVE-2026-114938 | OpenJDK and Java distributions | 2026-11-17 | Patched | — |
| [4EverAble2Shell](#4everable2shell) | CVE-2026-90436 (first stage only) | N-able N-central / Apache Axis 1.x | 2026-11-12 | **Exploited** | 2026-11-18 |
| [Able2Shell](#able2shell) | CVE-2026-125878 to CVE-2026-125883, CVE-2026-91000 | N-able N-central | 2026-11-09 | Public PoC | — |
| [Node2Shell](#node2shell) | CVE-2026-111497 | Google Brotli (Node.js, Python, Bun, .NET, Envoy, Istio) | 2026-10-21 | **Exploited** | 2026-10-27 |
| [PHP2Shell](#php2shell) | CVE-2026-109618, CVE-2026-109619 | PHP | 2026-10-20 | **Exploited** | 2026-10-26 |
| [Plex2Shell](#plex2shell) | CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656 | Plex Media Server | 2026-10-16 | **Exploited** | 2026-10-20 |
| [Comment2Shell](#comment2shell) | CVE-2026-93485 | WordPress core | 2026-09-21 | Public PoC | — |
| [KindaRails2Shell](#kindarails2shell) | CVE-2026-66066 | Ruby on Rails (Active Storage) | 2026-07-29 | Public PoC | — |
| [WP2Shell](#wp2shell) | CVE-2026-63030, CVE-2026-60137 | WordPress core | 2026-07-17 | **Exploited** | 2026-07-21 |

### Status legend

- **Exploited**: exploitation in the wild has been reported by CISA (KEV) or by the vendor.
- **Public PoC**: a working proof of concept is public; no confirmed exploitation in the wild.
- **Patched**: a fix is available; no public PoC and no known exploitation.

A dash in the KEV column means the CVE is not in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Where sources disagree on status, the entry below says so.

---

## Entries

### Ruby2Shell

- **CVE:** CVE-2026-132825 (GHSA-34m4-m9fh-gqp5). Named by Veria Labs.
- **Affected:** Ruby 3.3.0–3.3.13, 3.4.0–3.4.12 and 4.0.0–4.0.9. The bug dates back to Ruby 2.4.0, and end-of-life branches up to 3.2 get no fix.
- **Bundled in:** Veria Labs lists affected Ruby runtimes in GitLab 19.6.0, GitHub Enterprise Server 3.22.5, Mastodon 4.7.5, OpenProject 17.9.7, Discourse 2026.10.1 and Chatwoot 4.20.0. Check each vendor for a fixed release.
- **Fixed in:** Ruby 3.3.14, 3.4.13, 4.0.10 (released 2026-11-18).
- **Notes:** Default Rails and classic-style Sinatra apps are reachable without authentication; only strings in legacy single-byte encodings trigger it, not UTF-8. Severity sources disagree (the GHSA rates it Critical; the CNA score is 7.4). Veria Labs says it will publish a PoC about a week after disclosure.
- **References:** [Ruby security announcement](https://www.ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/) · [GHSA-34m4-m9fh-gqp5](https://github.com/ruby/ruby/security/advisories/GHSA-34m4-m9fh-gqp5) · [Veria Labs](https://verialabs.com/ruby2shell/) · [NVD](https://nvd.nist.gov/vuln/detail/cve-2026-132825)

### NGINX2Shell

- **CVEs:** CVE-2026-123007 is the headline bug. CVE-2026-123633, CVE-2026-123634, CVE-2026-121810 and CVE-2026-113425 were fixed in the same release and are tracked here too.
- **Affected:** CVE-2026-123007 affects nginx 1.9.5–1.31.8 with HTTP/2 enabled. Across all five CVEs, nginx 0.5.33–1.31.8 is affected depending on configuration (HTTP/2, HTTP/3, resolver, mail proxy).
- **Fixed in:** nginx 1.31.9 (mainline) and 1.30.7 (stable), released 2026-11-18. NGINX Plus 37.3.0.1 / 37.0.8.1 (CVE-2026-123007) and 37.2.0.1 / 37.0.7.1 (CVE-2026-123633).
- **Distribution packages:** as of 2026-11-19, Alpine, Ubuntu and Amazon Linux had shipped fixes; Debian and RHEL had not. The retired ingress-nginx controller will not get a fix.
- **Mitigation:** turning off HTTP/2 closes CVE-2026-123007 and CVE-2026-123633 only.
- **Status notes:** Rapid7 (Stephen Fewer) published a PoC for CVE-2026-123007. CERT-EU reports no exploitation in the wild.
- **References:** [F5 K000163926](https://my.f5.com/manage/s/article/K000163926) · [Xint](https://xint.io/blog/nginx2root-remote-code-execution) · [Wiz](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities) · [CERT-EU 2026-022](https://cert.europa.eu/publications/security-advisories/2026-022/)

### Java2Shell

- **CVE:** CVE-2026-114938. Reported by Calif.
- **Affected:** OpenJDK 17.0.6 and later, plus the 21, 25 and 27 lines, across distributions, but only on x86-64 CPUs with AVX-512 VBMI. Oracle also lists Java SE 8 Enterprise Performance Pack and GraalVM. Standard Java 8 and 11 are not affected.
- **Fixed in:** Oracle and OpenJDK builds 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1 (released 2026-11-17). Oracle Java SE 8 Enterprise Performance Pack is fixed in 8u513-perf; the affected build is 8u511b33-perf. Other distributions ship on their own schedule; check your vendor.
- **Interim mitigation:** third parties, including Calif and Tenable, describe disabling the affected intrinsic with `-XX:-UseBASE64Intrinsics`. Neither Oracle nor OpenJDK has published a workaround.
- **Status notes:** no exploitation reported; monitoring providers report probing. Calif is holding back application-specific details. CISA issued an alert urging immediate patching.
- **References:** [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17) · [Oracle CSPU Nov 2026](https://www.oracle.com/security-alerts/cspunov2026.html) · [Calif](https://calif.io/java4shell) · [CISA alert](https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching)

### 4EverAble2Shell

- **CVE:** no CVE covers the chain. The first stage is CVE-2026-90436 in the bundled Apache Axis 1.x library; the second stage, a local privilege escalation in N-central, has no CVE.
- **Affected:** N-central servers with the Legacy API enabled, including 2026.4 HF2 (2026.4.1.26). Apache Axis 1.x through 1.4. The same Axis flaw has also been exploited in Atlassian Confluence Data Center.
- **Fixed in:** N-central 2026.4 HF3 (build 2026.4.1.39) permanently removes Legacy API access. Apache Axis 1.x is end of life and will get no fixed release, only a source patch.
- **Status notes:** exploited to install cryptocurrency miners on 21 servers, 19 of them already on HF2. Disclosed with a PoC by Sean Bales. Rapid7 links a Metasploit module.
- **KEV:** CVE-2026-90436 added 2026-11-18, due 2026-11-21.
- **References:** [N-able remediation update](https://www.n-able.com/blog/n-able-vulnerability-remediation-update) · [HF3 release notes](https://status.n-able.com/2026/11/16/n-central-2026-4-hf3-release-notes/) · [Rapid7](https://www.rapid7.com/blog/post/etr-rapid7-detected-exploitation-of-cve-2026-90436-against-atlassian-confluence-data-center-n-able-n-central-also-exploited/) · [CISA KEV addition](https://www.cisa.gov/news-events/alerts/2026/11/18/cisa-adds-four-known-exploited-vulnerabilities-catalog)

### Able2Shell

- **CVEs:** CVE-2026-125883, CVE-2026-125881, CVE-2026-125878, CVE-2026-125879, CVE-2026-125882, CVE-2026-125880, CVE-2026-91000. The researcher, Sean Bales, reported 33 issues; these are the seven with CVEs.
- **Affected:** N-central, hosted and on-premises, all versions before 2026.4 HF2 (2026.4.1.26).
- **Fixed in:** N-central 2026.4 HF2 (build 2026.4.1.26, released 2026-11-10). Install HF3 (2026.4.1.39), which builds on HF2. N-able patches hosted servers itself.
- **Status notes:** public PoC; scanning observed. Sources disagree on exploitation: Safe Security reported no confirmed compromise as of 2026-11-12, while Hive Pro ties CVE-2026-125883 to the miner installs alongside CVE-2026-90436.
- **References:** [N-able remediation update](https://www.n-able.com/blog/n-able-vulnerability-remediation-update) · [Rapid7](https://www.rapid7.com/blog/post/etr-critical-vulnerabilities-in-n-able-n-central-prompt-hosted-shutdown/) · [Tenable FAQ](https://www.tenable.com/blog/able2shell-frequently-asked-questions-for-reported-n-able-n-central-zero-day-vulnerabilities)

### Node2Shell

- **CVE:** CVE-2026-111497 (GHSA-9v8h-qqgm-4m35).
- **Affected:** Google Brotli 1.0.3–1.2.0 and everything that bundles it, including Node.js 22.x, 24.x and 26.x, Python's Brotli and brotlicffi packages, Bun, .NET 8/9/10 (with Brotli decompression), Envoy and Istio (with Brotli decompression enabled), and Java brotli4j.
- **Fixed in:**
  - Brotli 1.0.10, 1.1.1, 1.2.1
  - Node.js 22.23.4, 24.22.1, 26.12.1
  - Bun 1.4.4 (affected: 1.0.21 to 1.4.3)
  - Python Brotli 1.2.1, brotlicffi 1.2.1.0
  - .NET 8.0.33, 9.0.22, 10.0.14
  - Istio 1.31.2, 1.30.6
  - PHP Windows builds 8.5.12-1, 8.4.27-1, 8.3.36-1, 8.2.35-1 (cURL extension)
- **Status notes:** CISA lists it as exploited, and a public RCE exploit by dimasma0305 is circulating. Sources disagree on exploitation: honeypot operators logged attempts, but Safe Security reported no confirmed successful exploitation.
- **KEV:** added 2026-10-27, due 2026-11-10.
- **References:** [Imperva](https://www.imperva.com/blog/node2shell-from-brotli-data-to-remote-code-execution/) · [Bun advisory](https://github.com/oven-sh/bun/security/advisories/GHSA-663w-cv8g-jj2p) · [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/node2shell-cve-2026-111497-nodejs-brotli-decoder/) · [SecurityWeek](https://www.securityweek.com/cisa-warns-of-node2shell-exploitation-as-honeypots-log-attack-attempts/)

### PHP2Shell

- **CVEs:** CVE-2026-109618, CVE-2026-109619.
- **Affected:** every PHP installation that serves web requests: Apache mod_php, PHP-FPM, php-cgi, FrankenPHP and LiteSpeed.
- **Fixed in:** PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 (released 2026-10-21). End-of-life 8.1, 8.0 and 7.4 received source backports only.
- **Recommended:** install the 2026-11-19 releases (8.5.13, 8.4.28, 8.3.37, 8.2.36). They also fix two related PHP bugs that this tracker doesn't cover, CVE-2026-115560 and CVE-2026-126714.
- **Status notes:** exploited, with attacks starting before the fix shipped. Public PoCs exist.
- **KEV:** both CVEs added 2026-10-26, due 2026-10-29.
- **References:** [CISA KEV bulletin](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/4309083) · [NCSC-NL php2shell](https://github.com/NCSC-NL/php2shell) · [Tenable FAQ](https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote)

### Plex2Shell

- **CVEs:** CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, CVE-2026-96656.
- **Affected:** Plex Media Server before 1.43.3.10861 on all platforms, including the QNAP app.
- **Fixed in:** Plex Media Server 1.43.3.10861. Most sources give the release date as 2026-08-04; one says early September. Plex Desktop should be on 1.115.0 or later.
- **Status notes:** exploited; Plex reported widespread exploitation, mostly to install miners and proxy software. The chain was published by code-zm.
- **KEV:** all four CVEs added 2026-10-20.
- **References:** [Plex release notes](https://forums.plex.tv/t/plex-media-server/30447/711) · [QNAP notice](https://www.qnap.com/en/security-news/2026/qnap-security-notice-plex-media-server-vulnerabilities-plex2shell-update-to-1-43-3-10861-or-later-immediately)

### Comment2Shell

- **CVE:** CVE-2026-93485. Reported by Rafie Muhammad.
- **Affected:** WordPress core 4.7 through 7.1.0.
- **Fixed in:** WordPress 7.1.1, 7.0.5 and 6.9.8, with branch releases back to 4.7.36 (released 2026-09-17).
- **Status notes:** reaching code execution needs a logged-in administrator to view the page with the comment. A public PoC was published by DeathShotXD. No exploitation reported.
- **References:** [WordPress 7.1.1 release](https://wordpress.org/news/2026/09/wordpress-7-1-1-maintenance-and-security-release/) · [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-93485) · [Researcher write-up](https://idnsec.com/research/comment2shell-zero-click-pre-auth-xss-to-rce-in-wordpress-core/)

### KindaRails2Shell

- **CVE:** CVE-2026-66066 (GHSA-xr9x-r78c-5hrm). Named by Ethiack.
- **Affected:** Active Storage before 7.2.3.2, 8.0.x before 8.0.5.1 and 8.1.x before 8.1.3.1, when using the Vips variant processor (the default since Rails 7.0) and accepting uploads from untrusted users.
- **Fixed in:** Rails 7.2.3.2, 8.0.5.1, 8.1.3.1 (released 2026-07-29). Also update libvips to 8.13 or later, and rotate secrets on any app that was exposed.
- **Status notes:** multiple public PoCs exist. Sources disagree on exploitation: one hosting provider reported mass attacks in early August, while other coverage found no public reports. It is not in KEV.
- **References:** [Rails advisory](https://github.com/rails/rails/security/advisories/GHSA-xr9x-r78c-5hrm) · [Rapid7 analysis](https://www.rapid7.com/blog/post/ra-kindarails2shell-technical-analysis-cve-2026-66066/)

### WP2Shell

- **CVEs:** CVE-2026-63030, CVE-2026-60137. Discovered by Adam Kues (Searchlight Cyber).
- **Affected:** the full chain affects WordPress 6.9.0–6.9.4 and 7.0.0–7.0.1. WordPress 6.8.0–6.8.5 has the SQL injection (CVE-2026-60137) only.
- **Fixed in:** WordPress 6.8.6, 6.9.5, 7.0.2 (released 2026-07-17), and 7.1 beta 2.
- **Status notes:** exploited; CrowdSec observed more than 62,000 attacking IP addresses.
- **KEV:** both CVEs added 2026-07-21.
- **References:** [Searchlight Cyber](https://www.slcyber.io/research/wp2shell-pre-authentication-rce-in-wordpress-core) · [Wordfence](https://www.wordfence.com/blog/2026/07/wp2shell-wordpress-exploit-technical-analysis-and-real-attack-data/) · [CrowdSec](https://www.crowdsec.net/vulntracking-report/cve-2026-63030-wordpress-wp2shell-active-exploitation)

---

## Detection script

[`something2shell_check.py`](something2shell_check.py) checks the host it runs on for every entry in the tracker. It looks for components in their usual install locations, in what running processes are executing, and inside running containers. It then reads their versions and compares them with the fixed versions listed above.

**Requirements:** Linux and Python 3.6 or later. It uses only the standard library, so there is nothing to install.

### Run it

Download the script, then run it on the host you want to check:

```bash
python3 something2shell_check.py             # as a regular user: your own files and processes only
sudo python3 something2shell_check.py        # full scan: every user's installs, all processes, containers
python3 something2shell_check.py --json      # machine-readable report instead of text
python3 something2shell_check.py --no-color  # plain output, for logs
python3 something2shell_check.py --version   # script version and tracker date
```

Color is also turned off automatically when output isn't a terminal, or when `NO_COLOR` is set.

### What it checks

It runs ten checks in order and prints a line for everything it finds.

| # | Check | Tracker entries | Where it looks |
|---|---|---|---|
| 1 | Ruby interpreters | Ruby2Shell | `ruby` on PATH, `/usr/bin/ruby*`, `/usr/local/bin/ruby*`, embedded Ruby under `/opt/*/embedded` (GitLab), rbenv and RVM installs |
| 2 | nginx / OpenResty | NGINX2Shell | `nginx` and `openresty` on PATH and in the usual `sbin` paths, plus the nginx configuration and the files it includes |
| 3 | Java runtimes | Java2Shell | `java` on PATH, `$JAVA_HOME`, `/usr/lib/jvm/*`, `/usr/java/*`, `/opt` JDKs, and JVMs loaded inside other programs (`libjvm.so`); reads `/proc/cpuinfo` for AVX-512 VBMI |
| 4 | N-central console | 4EverAble2Shell, Able2Shell | One GET request to `https://127.0.0.1/login` to read the console version |
| 5 | Brotli users | Node2Shell | The system Brotli library (`libbrotlidec`), Node.js (including nvm and Volta), Bun, .NET runtimes, and the Python `Brotli` and `brotlicffi` packages, including those in virtualenvs |
| 6 | PHP | PHP2Shell | `php`, `php-fpm`, `php-cgi` and `lsphp` binaries, including Remi, Plesk, cPanel and LiteSpeed builds, and PHP built into Apache (`libphp*.so`) |
| 7 | Plex Media Server | Plex2Shell | The `plexmediaserver` dpkg or rpm package, otherwise one GET request to `http://127.0.0.1:32400/identity` |
| 8 | WordPress | Comment2Shell, WP2Shell | `wp-includes/version.php`, up to 5 folders deep under `/var/www`, `/srv`, `/usr/share/nginx`, `/usr/share/wordpress`, `/opt`, `/home` and `/app` |
| 9 | Rails Active Storage | KindaRails2Shell | `Gemfile.lock` files in the same folders, plus `gem list activestorage` |
| 10 | Processes still running replaced files | All runtime entries | Running processes whose program or tracked library was replaced on disk after they started |

Three things apply across the checks:

- **Running processes.** Checks 1, 2, 3, 5 and 6 also pick up any matching program that a running process is executing, wherever it is installed. That catches runtimes bundled inside applications, such as the JDK that ships with Elasticsearch. Findings that are in use are marked `(running)`.
- **Running containers.** The script reads the filesystem of every running container and looks for the same components there. Files inside a container are never run: the version is read from the file itself. Containers that give identical findings are reported once, with the others listed under "also in".
- **Every user, when run as root.** Per-user installs (rbenv, RVM, nvm, Volta, Bun, `pip --user`, and virtualenvs kept by pipenv, Poetry, pyenv, pipx and conda) are searched in every home directory.

### Read the result

The script ends with a result block that opens with one of three lines:

- **NOT VULNERABLE:** no tracked vulnerability was found on this host.
- **VULNERABLE:** a numbered list of affected items. Each one shows the tracker entry and CVE, the component, its version and location, whether it is in use, and the fixed version to install.
- **No confirmed vulnerable item, but the result is incomplete:** nothing was confirmed, but some items need a manual check or a check failed.

Items the script found but can't judge are listed separately under **Needs a manual check**, with a reason. These include NGINX Plus, OpenResty, pre-release WordPress and .NET builds, WordPress branches 4.8 to 5.9, Rails 5.x and 6.x apps, .NET releases older than 6, processes that need a restart, and files in containers whose version couldn't be read.

Sample output, shortened:

```text
$ sudo python3 something2shell_check.py
something2shell detector 0.2.0  (tracker data 2026-11-20)
Scanning this host for 11 tracked *2Shell vulnerabilities...

[2/10] nginx / OpenResty  (NGINX2Shell)
    - nginx 1.30.7 at /usr/sbin/nginx -> not vulnerable  [NGINX2Shell]  (running)

[3/10] Java runtimes  (Java2Shell)
    CPU: AVX-512 VBMI present, so the vulnerable Java code path can be used.
    - Java 21.0.13.0.3 at /usr/bin/java -> VULNERABLE  [Java2Shell]
...
[6/10] PHP  (PHP2Shell)
    - PHP 8.3.6 at /usr/bin/php -> not vulnerable  [PHP2Shell]
      The upstream version is in the affected range, but the OS package
      php8.3-cli 8.3.6-0ubuntu0.24.04.13 names CVE-2026-109618,
      CVE-2026-109619 as fixed in its changelog (distro backport).
...
================================================================
 RESULT
================================================================
[!] VULNERABLE: 1 item(s) found on this host

  1. Java2Shell (CVE-2026-114938)
     Java 21.0.13.0.3 at /usr/bin/java
     Fixed in 21.0.13.1 (Oracle/OpenJDK numbering; other vendors use their
     own build numbers, so check your vendor's advisory). Interim mitigation:
     -XX:-UseBASE64Intrinsics. Installed from the OS package openjdk-21-jre-
     headless:amd64 21.0.13.0.3+1-1~24.04.1, whose changelog doesn't mention
     CVE-2026-114938, so it looks unpatched. Confirm against your distro's
     advisory.
```

### JSON output

`--json` prints one JSON document instead of the text report. The exit code is the same in both modes.

| Field | Contents |
|---|---|
| `result` | `vulnerable`, `incomplete` or `not_vulnerable` |
| `exit_code`, `counts` | The exit code, and the number of findings per verdict |
| `host` | Hostname, platform, whether the scan ran as root, and whether the CPU has AVX-512 VBMI |
| `containers` | The containers that were scanned |
| `failed_checks`, `notes`, `limits` | Checks that crashed, limits of this particular scan, and the general limits of the script |
| `findings` | One object per finding |

Each finding has `entry`, `cves`, `component`, `version`, `verdict` (`vulnerable`, `not_vulnerable` or `manual_check`), `location`, `path`, `container`, `also_in`, `running`, `pids` and `detail`. nginx findings also carry `config`: the files that were read, the features that are switched on, and the CVEs the configuration exposes.

For example, to list the vulnerable items with `jq`:

```bash
sudo python3 something2shell_check.py --json \
  | jq -r '.findings[] | select(.verdict == "vulnerable") | [.entry, .component, .version, .location] | @tsv'
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing vulnerable found. Manual-check items may still be listed. |
| `1` | At least one vulnerable item. |
| `2` | Nothing vulnerable found, but a check failed, so the result is incomplete. |
| `130` | Interrupted with Ctrl+C. |

The exit code makes it easy to schedule. For example, in cron or a CI job:

```bash
python3 something2shell_check.py --json > /var/log/something2shell.json
case $? in
  1) echo "something2shell: vulnerable item found" ;;
  2) echo "something2shell: scan incomplete, a check failed" ;;
esac
```

### What it does and doesn't do

- **It's read-only.** It runs version commands on the host and reads files. It sends no exploit payloads and changes nothing.
- **It doesn't run other users' files as root.** Under `sudo`, a program that isn't owned by root is run as its owner instead. Files inside containers are never run at all.
- **Its only network traffic is loopback.** It makes at most two GET requests, both to `127.0.0.1` (the N-central and Plex checks). It ignores proxy settings and doesn't follow a redirect that leaves the loopback address.
- **Distro backports are read from the package changelog.** Debian, Ubuntu and RHEL often patch a bug without changing the upstream version number. When a flagged file comes from a dpkg or rpm package, the script looks for the CVEs in that package's changelog. If all are named, the item is reported as not vulnerable; if only some are, it needs a manual check; if none are, it stays vulnerable. A fix that the changelog doesn't name can't be seen, and this check isn't done inside containers.
- **NGINX2Shell depends on configuration.** The script reads the nginx configuration and says which of the five CVEs it exposes. An affected version with none of the triggering features switched on (HTTP/2, HTTP/3 with an upstream, a resolver with a variable `proxy_pass` target, the mail proxy with `auth_http`) is reported as not vulnerable, with a note to update anyway. If any part of the configuration can't be read, every CVE is assumed reachable.
- **4EverAble2Shell depends on configuration.** The script can't tell whether the N-central Legacy API is turned on, so it flags any build before HF3 (2026.4.1.39). A patched server may also keep showing an old version number, so confirm against N-able's guidance.
- **Java2Shell depends on the CPU.** An affected Java version on a CPU without AVX-512 VBMI is reported as not vulnerable, with a note to update anyway.
- **Distro Node.js follows the system Brotli library.** Many distro Node.js packages, Debian's and Ubuntu's among them, load the system library instead of bundling their own copy. The script detects this for each Node.js binary and reports it by that library's status.
- **Updated on disk isn't the same as running.** After an update, a process keeps the old code in memory until it restarts. Check 10 lists those processes.
- **Some places are out of reach.** It doesn't inspect stopped containers or container images, self-contained .NET apps, or copies of Brotli compiled into other programs. A few versions inside containers can't be read without running the file, and those are listed for a manual check.

Run it only on systems you own or are authorized to assess.

---

## Contributing

Corrections and new entries are welcome through pull requests. Please:

- **Cite primary sources.** Use the vendor advisory for fixed versions, the CVE record for IDs, and the CISA KEV catalog for exploitation status.
- **Leave conflicts visible.** When sources disagree (on KEV status, CVE mapping or exploitation), note the disagreement instead of picking one.
- **Keep exploit material out.** Don't add exploit code, exploitation steps or links to exploit repositories. Naming who published a PoC is fine.
