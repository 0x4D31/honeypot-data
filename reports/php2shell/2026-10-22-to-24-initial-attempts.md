# PHP2Shell: initial exploitation attempts, 22–24 October 2026

**Historical window:** 22 October 22:45–24 October 01:28 UTC. This report preserves the original attempt-only analysis; confirmed RCE activity observed later on 24 October is documented separately in [PHP2Shell exploitation observed](2026-10-24-confirmed-rce.md).

---

Across six instrumented PHP-backed web personas, a 26-hour, 43-minute capture recorded **30 pre-script out-of-memory errors and 11 worker crashes**. The traffic included repeated leak-stage payloads, distributed fixed-length probes, serializer-oriented requests, and large chunked uploads. No remote code execution or usable memory disclosure was confirmed **in this initial window**.

The observation window runs from **22 October 22:45 to 24 October 01:28 UTC**. All times below are UTC; application names such as WordPress and Drupal refer to the presented web personas, not findings against those CMS products.

Jump to: [Campaign overview](#campaign-overview) · [Source outcomes](#source-level-outcomes) · [Crash timeline](#crash-timeline) · [IP and reverse-DNS appendix](#appendix-source-observables-and-reverse-dns) · [Request aggregates](#appendix-request-aggregates) · [Fingerprints](#appendix-tls-and-http-fingerprints) · [Request excerpts](#appendix-representative-requests)

## At a glance

| Observation | Result |
|---|---|
| Pre-script out-of-memory errors (OOMs) | 30, correlated to 13 external source IPs |
| Apache/PHP worker crashes | 11: ten `SIGSEGV`, one `SIGABRT` |
| PHP POST-size-limit warnings | 29 |
| Core/serializer probes | 38 requests from 11 source IPs |
| Remote code execution or usable memory disclosure | None confirmed in this window |

OOMs and crashes are separate outcomes, not additive counts of attacks. All 30 requests correlated with OOM errors returned **HTTP 200**, illustrating why status codes alone were not a reliable outcome signal.

## Campaign overview

The table groups activity by payloads, timing, and request sequences. These are activity clusters, not attributed threat actors: reuse of a public PoC does not establish common control.

| Cluster | Sources and timing | Distinguishing behavior | Observed outcome |
|---|---|---|---|
| **B1 leak-stage attempts** | `178.249.214.6`, `89.167.27.27`, `103.151.173.212`, `45.14.71.20`; October 23 into early October 24 | OOM requests followed by multipart bodies carrying `PHPSESSID=a`, progress value `k0`, and long `f0000ffff…` field names | Ten segmentation faults followed identical, complete B1 bodies. An incomplete B1-style transfer preceded the allocator abort. |
| **Distributed fixed-length probes** | 22 IPs in `14.102.84.0/24`, 17:02–18:22 on October 23; matching smaller bodies later from `91.107.150.150` | 33 POSTs from the `/24`, combining large multipart bodies with 93,685-byte and 192-byte probes using `attacksessionid0001` | Exact body reuse linked multiple sources. No usable leak was established. |
| **Core/serializer wave** | 11 IPs, 21:19:54–21:36:22 on October 23 | 38 multipart requests; markers included `----Php2Shell…`, `PHP2SHELL_CORE_…`, serialization wrappers, and `PHP2SHELL_CHAIN_OK` | No correlated OOM/crash or returned execution marker. Fifteen requests submitted `session.serialize_handler` fields, without evidence that the setting changed. |
| **Large-field multipart variant** | `188.253.121.168`, `188.253.121.92`, `188.253.121.97`; 15:28–15:30 and 17:23 on October 23 | Three incomplete chunked streams with long `g0000xxxx…` field names, plus one 18,767-byte fixed-session probe; roughly 60 MiB reconstructed from one stream | Data reached the capture point, but complete PHP parsing, a limit bypass, and exploitation were not established. |

### Identical leak-stage bodies, different outcomes

The ten segmentation faults each followed the same **33,128,677-byte HTTP body**. Its structure matches the B-stage multipart builder in [`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp/blob/main/pure/mk_leak_b.py); the project's [stage description](https://github.com/9bie/php2shell-bypass-aslr-exp) identifies B1 as the out-of-bounds-read stage and A2/B2 as the later execution stages.

Thirteen complete instances of that body were recovered, all using chunked transfer encoding. Ten preceded segmentation faults; three additional requests from `89.167.27.27` returned normal persona pages and session cookies without a correlated crash. Identical payload bytes therefore did not produce a uniform result.

`178.249.214.6` accounted for six crashes across Drupal, portal, and WordPress personas. `89.167.27.27` reached the same three personas in roughly 14 minutes and accounted for three crashes; `103.151.173.212` accounted for another. The remaining crash, from `45.14.71.20`, was an allocator abort with `zend_mm_heap corrupted`; its B1-style request was incomplete.

The requests, OOMs, and exits form a strong temporal sequence. They do not, without a core dump or debugger analysis, identify the exact defect responsible for each crash or demonstrate a successful leak.

### Payload reuse across addresses

The distributed fixed-length sequence matches markers in [`eness/poc_109618.py`](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC/blob/main/poc_109618.py). Complete 93,685-byte and 192-byte bodies were byte-identical across several `14.102.84.0/24` addresses and `91.107.150.150`, providing a stronger link than address proximity alone.

Large-body variants also repeated across `/24` sources, with declared lengths of 12,655,437, 15,657,436, and 16,777,296 bytes. This supports shared tooling, but not a conclusion about one controller, a botnet, or deliberate evasion; `91.107.150.150` also sent scanner-style controls, so one IP was not limited to one request family.

### Serializer probes and chunked uploads

The short serializer wave matched request-building markers in a pinned [`murrez/php2shell` revision](https://github.com/murrez/php2shell/blob/7de30d56887d20e4bfc1b3f90b47f067917742c7/poc.py). Sending a multipart field named `session.serialize_handler` does not demonstrate that the server applied it as configuration. The wave overlapped B1 traffic in time and targets, but no stronger link between the two was established.

The `188.253.121.0/24` streams also used chunked transfer, but began with numbered `g0000…` fields padded with long runs of `x`. Those repeated structures and close timing support a separate working cluster; its incomplete streams do not show how much PHP accepted or processed.

## Other probing activity

- **`p2s_v2` probes:** `27.100.38.10` produced three OOMs over TLS around 13:40 on October 23; `46.144.20.186` produced another on Drupal at 15:59. Markers included `recon0xdeadbeef` and `?c=echo%20p2s_v2_alive`; the command-shaped URL did not establish execution.
- **Nested-file probes:** `185.177.72.45` produced four OOMs across portal and WordPress, while `152.59.222.169` produced two on Drupal. A separate 300,067-byte nested `$_FILES` body from `190.47.59.9` also produced an OOM.
- **Scanner-style controls:** Four OOMs from `138.199.22.106`, `106.192.102.115`, and `91.107.150.150` followed Assetnote-style controls and nested-array probes. The [Assetnote scanner documentation](https://github.com/assetnote/php2shell-scanner) notes that some patched configurations can also produce OOM-based signatures, requiring version and vendor-backport checks.
- **Rapid and partial requests:** Declared 1 MiB form-urlencoded requests and rapid POST bursts appeared from `178.249.214.6` and `192.42.116.21`; the latter produced three Drupal OOMs without a correlated crash. Worker selection or pinning is a possible explanation, not demonstrated heap grooming. `172.86.85.171` also sent similarly declared requests and an incomplete B1-like stream around 19:53.
- **Canary and survey traffic:** Six `shellflow`-marked requests from `46.250.228.73` reached portal around 08:02 on October 23. Census-labelled upload-progress scans reached all six personas; the label was treated as self-identification, not verified ownership.
- **Other exploit probes:** PHP-CGI, traversal, webshell, and `androxgh0st` traffic was kept separate from the PHP2Shell clusters. Reviewed responses and runtime events did not establish execution.

## Source-level outcomes

OOMs were correlated with Apache request intervals and responses; TLS origins were joined through the proxy's upstream connection information and completion time. The table records observed request origins, not distinct operators.

| Source IP | OOMs | Worker crashes |
|---|---:|---:|
| `178.249.214.6` | 7 | 6 |
| `185.177.72.45` | 4 | 0 |
| `192.42.116.21` | 3 | 0 |
| `89.167.27.27` | 3 | 3 |
| `27.100.38.10` | 3 | 0 |
| `152.59.222.169` | 2 | 0 |
| `91.107.150.150` | 2 | 0 |
| `46.144.20.186` | 1 | 0 |
| `103.151.173.212` | 1 | 1 |
| `138.199.22.106` | 1 | 0 |
| `190.47.59.9` | 1 | 0 |
| `106.192.102.115` | 1 | 0 |
| `45.14.71.20` | 1 | 1 |
| **Total** | **30** | **11** |

The core/serializer wave came from a separate source set: `84.32.50.51`, `144.31.90.233`, `46.166.168.18`, `31.185.105.123`, `185.252.177.175`, `193.178.226.197`, `130.78.219.18`, `144.31.90.126`, `88.216.36.31`, `146.255.189.4`, and `80.47.18.86`. None was linked to an OOM or crash in this window.

## Crash timeline

Every exit below was recorded by Tetragon and matched an Apache `AH00051` worker-exit record. Times are rounded to milliseconds; the source associations use the surrounding request and packet sequence.

| UTC | Persona | Source IP | Signal |
|---|---|---|---|
| Oct 23 13:21:22.479 | WordPress | `45.14.71.20` | `SIGABRT`; allocator corruption message |
| Oct 23 17:47:25.935 | Drupal | `103.151.173.212` | `SIGSEGV` |
| Oct 23 19:43:19.223 | Drupal | `178.249.214.6` | `SIGSEGV` |
| Oct 23 19:43:32.882 | Drupal | `178.249.214.6` | `SIGSEGV` |
| Oct 23 20:39:55.973 | Portal | `178.249.214.6` | `SIGSEGV` |
| Oct 23 21:10:56.066 | Portal | `89.167.27.27` | `SIGSEGV` |
| Oct 23 21:11:44.685 | Portal | `178.249.214.6` | `SIGSEGV` |
| Oct 23 21:11:58.818 | Drupal | `89.167.27.27` | `SIGSEGV` |
| Oct 23 21:24:17.497 | WordPress | `89.167.27.27` | `SIGSEGV` |
| Oct 23 22:52:29.690 | Drupal | `178.249.214.6` | `SIGSEGV` |
| Oct 24 01:02:23.361 | WordPress | `178.249.214.6` | `SIGSEGV` |

## What the runtime and responses showed

- **Processes and network:** No Apache-spawned command was identified among the 717 `process_exec` records. No `tcp_connect` event was captured; the 4,336 `tcp_close` records should not be counted as outbound connection attempts.
- **Files:** 1,234 permission-hook events referenced 129 distinct `/tmp/php…` path strings. Those events are not counts of successful writes or installed webshells.
- **Responses and cookies:** Of 4,216 decoded target responses, 4,213 were complete. None contained the tested `PHP2SHELL_CHAIN_OK`, `PHP2SHELL_CHECK`, `p2s_v2_alive`, `shellflow_canary`, or `uid=` success markers. All 29 observed PHP session-cookie values were 32 hexadecimal characters long; that format alone neither proves nor rules out a memory leak.
- **TLS fingerprint:** The three TLS-associated OOMs from `27.100.38.10` carried JA4 `t13i311000_e8f1e7e78f70_d41ae481755e`. This is a client fingerprint, not an actor identifier.

### Source infrastructure

The following registration and reverse-DNS observations provide context for three crash-associated sources. They identify infrastructure, not the operators behind the requests.

| Source IP | Observed PTR | Registered network |
|---|---|---|
| `178.249.214.6` | `unn-178-249-214-6.datapacket.com` | `CDNEXT-TOR`, CA ([RIPE](https://rdap.db.ripe.net/ip/178.249.214.6)) |
| `89.167.27.27` | `rawi.network` | Hetzner `CLOUD-HEL1`, FI ([RIPE](https://rdap.db.ripe.net/ip/89.167.27.27)) |
| `45.14.71.20` | No PTR returned | `ProtonVPN-Osaka-1`, JP ([RIPE](https://rdap.db.ripe.net/ip/45.14.71.20)) |

Registration country codes are not operator locations. The `google.com` PTR returned for `91.107.150.150` was not treated as evidence of Google ownership.

## Payload observables

These SHA-256 values identify complete reconstructed HTTP bodies, not PCAP files. Exact hashes are useful for finding repeats; field names and request sequences can help identify modified variants.

| Body | Bytes | SHA-256 |
|---|---:|---|
| B1 body preceding all ten segmentation faults | 33,128,677 | `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2` |
| Shared fixed-length-family probe | 93,685 | `ecaf5a1898a7e0dd754c7633334a03f58059b262cfa870d366dc97af342f2397` |
| Shared fixed-session probe | 192 | `5b29950f7d421c5e7336441cf370d07e95a196b47c905bfbddef94e0d36c6937` |

## Scope and conclusion

The review covered 1,927 sealed collection segments overlapping the reporting window. All 6,118 selected evidence files, including adjacent-window context, matched their manifest sizes and SHA-256 values; 4,000 PCAP files were parsed and their TCP streams reassembled. Selection was by time window, not by pre-existing alert labels.

Some streams contained sequence gaps or incomplete uploads, although the ten crash-associated B1 bodies were complete in target-side captures. The absence of child-execution or connection events cannot exclude execution entirely within an existing process or activity outside the captured window.

The strongest finding is repeated use of the same leak-stage body followed by independently recorded worker crashes. For triage, the useful signal is the correlated **OOM → B1 request → worker exit** sequence, not a POST, HTTP status, or session cookie in isolation. These initial-window captures establish exploitation attempts and real worker failures, but not a completed leak-to-execution chain.

## Appendix: source observables and reverse DNS

This list covers the sources associated with the activity families discussed above, including survey-labelled requests. It is a hunting reference, not a blocklist; an IP or fingerprint match alone is not proof of malicious activity.

The `14.102.84.0/24` entries include all 27 source addresses seen in HTTP access records: 22 sent the 33 POSTs discussed above, while five sent only GET/HEAD requests. The latter are included as range context, not assigned the same exploitation behavior.

DNS was checked on 2026-10-24 (UTC). “No PTR” means the query completed without a PTR answer; lookup errors are shown separately. Forward confirmation means the returned hostname's A records included the original IP, not that the hostname's implied ownership was verified.

First/last times and request counts below come from Apache access records within the reporting window, including other requests from the listed source. They are not counts of exploit attempts. TLS origins were joined to completed proxy records using the upstream connection, method, and request-end time. Worker-ending or incomplete requests can appear only in packet captures, so the last access-log timestamp is not necessarily the last packet time.

| Source IP | Activity labels | First / last access-log time UTC | Access records (POST) | PTR | Forward A match |
|---|---|---|---:|---|---|
| `14.102.84.7` | Fixed-length | 10-23 18:22:52 / 10-23 18:22:52 | 1 (1) | No PTR | n/a |
| `14.102.84.16` | Fixed-length | 10-23 18:14:47 / 10-23 18:15:31 | 2 (2) | No PTR | n/a |
| `14.102.84.31` | Same /24; no POST | 10-23 15:45:49 / 10-23 15:45:49 | 1 (0) | No PTR | n/a |
| `14.102.84.33` | Fixed-length | 10-23 17:58:49 / 10-23 18:22:20 | 2 (2) | No PTR | n/a |
| `14.102.84.52` | Fixed-length | 10-23 17:59:05 / 10-23 17:59:05 | 1 (1) | No PTR | n/a |
| `14.102.84.54` | Fixed-length | 10-23 18:15:45 / 10-23 18:15:45 | 1 (1) | No PTR | n/a |
| `14.102.84.57` | Fixed-length | 10-23 18:15:11 / 10-23 18:22:51 | 2 (2) | No PTR | n/a |
| `14.102.84.71` | Same /24; no POST | 10-23 15:45:49 / 10-23 15:46:22 | 2 (0) | No PTR | n/a |
| `14.102.84.78` | Fixed-length | 10-23 17:02:27 / 10-23 17:02:27 | 1 (1) | No PTR | n/a |
| `14.102.84.80` | Fixed-length | 10-23 17:02:26 / 10-23 17:02:26 | 1 (1) | No PTR | n/a |
| `14.102.84.106` | Same /24; no POST | 10-23 17:58:48 / 10-23 17:58:48 | 1 (0) | No PTR | n/a |
| `14.102.84.119` | Fixed-length | 10-23 18:15:45 / 10-23 18:22:06 | 2 (2) | No PTR | n/a |
| `14.102.84.122` | Fixed-length | 10-23 18:15:19 / 10-23 18:21:40 | 2 (2) | No PTR | n/a |
| `14.102.84.129` | Fixed-length | 10-23 18:22:19 / 10-23 18:22:19 | 1 (1) | No PTR | n/a |
| `14.102.84.154` | Same /24; no POST | 10-23 17:02:26 / 10-23 17:02:26 | 1 (0) | No PTR | n/a |
| `14.102.84.166` | Fixed-length | 10-23 18:14:58 / 10-23 18:15:55 | 2 (2) | No PTR | n/a |
| `14.102.84.167` | Same /24; no POST | 10-23 18:14:47 / 10-23 18:14:47 | 1 (0) | No PTR | n/a |
| `14.102.84.168` | Fixed-length | 10-23 17:59:14 / 10-23 18:21:39 | 2 (1) | No PTR | n/a |
| `14.102.84.177` | Fixed-length | 10-23 17:59:06 / 10-23 18:15:37 | 2 (2) | No PTR | n/a |
| `14.102.84.193` | Fixed-length | 10-23 18:15:10 / 10-23 18:22:37 | 3 (3) | No PTR | n/a |
| `14.102.84.199` | Fixed-length | 10-23 18:22:36 / 10-23 18:22:36 | 1 (1) | No PTR | n/a |
| `14.102.84.211` | Fixed-length | 10-23 17:59:13 / 10-23 17:59:13 | 1 (1) | No PTR | n/a |
| `14.102.84.227` | Fixed-length | 10-23 15:46:22 / 10-23 18:15:55 | 2 (1) | No PTR | n/a |
| `14.102.84.229` | Fixed-length | 10-23 17:02:26 / 10-23 18:15:30 | 2 (1) | No PTR | n/a |
| `14.102.84.233` | Fixed-length | 10-23 18:21:53 / 10-23 18:21:53 | 1 (1) | No PTR | n/a |
| `14.102.84.238` | Fixed-length | 10-23 18:15:19 / 10-23 18:16:06 | 3 (3) | No PTR | n/a |
| `14.102.84.248` | Fixed-length | 10-23 17:58:57 / 10-23 17:58:57 | 1 (1) | No PTR | n/a |
| `27.100.38.10` | OOM, p2s_v2 | 10-23 13:40:40 / 10-23 13:40:49 | 15 (5) | Lookup failed | n/a |
| `31.185.105.123` | Serializer | 10-23 21:20:26 / 10-23 21:36:09 | 18 (6) | ip123.ip-31-185-105.infrawire.sh | No |
| `45.14.71.20` | B1 / crash, OOM | 10-23 13:04:48 / 10-23 13:21:23 | 7 (2) | No PTR | n/a |
| `45.156.128.41` | Survey-labelled | 10-23 02:43:33 / 10-23 13:30:21 | 5 (5) | sh-ams-nl-gd11-wk103a.internet-census.org | Yes |
| `45.156.128.43` | Survey-labelled | 10-23 05:10:57 / 10-23 16:42:00 | 2 (2) | sh-ams-nl-gd16-wk101a.internet-census.org | Yes |
| `45.156.128.45` | Survey-labelled | 10-22 22:49:02 / 10-23 13:33:58 | 4 (4) | sh-ams-nl-gd16-wk103a.internet-census.org | Yes |
| `45.156.128.47` | Survey-labelled | 10-23 00:47:42 / 10-24 01:25:03 | 8 (4) | sh-ams-nl-gd10-wk103a.internet-census.org | Yes |
| `45.156.129.52` | Survey-labelled | 10-23 19:20:32 / 10-24 00:39:22 | 6 (4) | sh-chi-us-gd10-wk101a.internet-census.org | Yes |
| `45.156.129.57` | Survey-labelled | 10-23 07:06:00 / 10-23 17:24:52 | 7 (4) | sh-chi-us-gd16-wk102a.internet-census.org | Yes |
| `46.144.20.186` | OOM, p2s_v2 | 10-23 15:56:21 / 10-23 15:59:18 | 22 (4) | 46-144-20-186.biz.kpn.net | Yes |
| `46.166.168.18` | Serializer | 10-23 21:20:02 / 10-23 22:30:42 | 51 (5) | ip-46-166-168-18.009.ptr.cherryservers.net | Yes |
| `46.250.228.73` | shellflow | 10-23 07:54:35 / 10-23 09:37:01 | 78 (9) | vmi3131471.contaboserver.net | No |
| `80.47.18.86` | Serializer | 10-23 21:35:16 / 10-23 22:28:50 | 4 (1) | No PTR | n/a |
| `84.32.50.51` | Serializer | 10-23 21:19:46 / 10-23 22:30:48 | 62 (14) | ip-84-32-50-51.008.ptr.cherryservers.net | Yes |
| `88.216.36.31` | Serializer | 10-23 21:21:00 / 10-23 21:35:12 | 26 (5) | No PTR | n/a |
| `89.167.27.27` | B1 / crash, OOM | 10-23 21:10:30 / 10-23 21:24:22 | 9 (6) | rawi.network | No |
| `91.107.150.150` | Fixed-length, OOM | 10-23 19:14:52 / 10-23 19:54:11 | 27 (21) | google.com | No |
| `103.151.173.212` | B1 / crash, OOM | 10-23 17:40:16 / 10-23 17:47:14 | 2 (1) | No PTR | n/a |
| `106.192.102.115` | OOM | 10-23 12:56:10 / 10-23 12:56:10 | 2 (2) | No PTR | n/a |
| `109.105.210.102` | Survey-labelled | 10-23 04:39:43 / 10-23 13:15:11 | 5 (3) | zl-dfwc-us-gd11-wk102a.internet-census.org | Yes |
| `130.78.219.18` | Serializer | 10-23 21:19:50 / 10-23 22:30:33 | 13 (2) | host-130-78-219-18.net.onlyservers.com | No |
| `138.199.22.106` | OOM | 10-23 10:15:04 / 10-23 10:15:05 | 2 (2) | unn-138-199-22-106.datapacket.com | No |
| `144.31.90.126` | Serializer | 10-23 21:27:02 / 10-23 21:31:31 | 7 (2) | s322193.love-is.nexus | No |
| `144.31.90.233` | Serializer | 10-23 21:19:48 / 10-23 21:37:38 | 68 (11) | s326990.love-is.nexus | No |
| `146.255.189.4` | Serializer | 10-23 20:05:49 / 10-23 22:30:45 | 20 (2) | No PTR | n/a |
| `152.59.222.169` | OOM | 10-23 16:43:20 / 10-23 19:09:36 | 54 (3) | Lookup failed | n/a |
| `172.86.85.171` | Partial B1 | 10-23 18:44:14 / 10-23 19:54:12 | 153 (151) | 171.85.86.172.static.cloudzy.com | No |
| `178.249.214.6` | B1 / crash, OOM | 10-23 19:25:19 / 10-24 01:02:13 | 330 (311) | unn-178-249-214-6.datapacket.com | No |
| `185.177.72.45` | OOM | 10-23 07:02:56 / 10-23 14:08:49 | 5 (4) | No PTR | n/a |
| `185.252.177.175` | Serializer | 10-23 21:19:52 / 10-23 21:36:53 | 28 (6) | vds19227.1cent.network | No |
| `188.253.121.92` | Large-field | 10-23 15:28:30 / 10-23 15:38:40 | 2 (1) | No PTR | n/a |
| `188.253.121.97` | Large-field | 10-23 15:38:40 / 10-23 15:38:40 | 1 (1) | No PTR | n/a |
| `188.253.121.168` | Large-field | 10-23 15:28:35 / 10-23 17:23:24 | 2 (2) | No PTR | n/a |
| `190.47.59.9` | OOM | 10-23 10:39:03 / 10-23 10:39:03 | 1 (1) | pc-9-59-47-190.cm.vtr.net | Yes |
| `192.42.116.21` | OOM | 10-23 19:04:08 / 10-23 19:11:27 | 454 (450) | hviv-bare.as1101.net | No |
| `193.178.226.197` | Serializer | 10-23 21:31:52 / 10-23 21:37:10 | 31 (5) | No PTR | n/a |

The PTR lookups for `27.100.38.10` and `152.59.222.169` timed out on repeated attempts; they are not classified as “No PTR.” All seven survey-labelled sources in the table had forward-confirmed `internet-census.org` names, which corroborates their request labels without establishing intent or authorization.


## Appendix: request aggregates

The access-log inventory contains 4,227 records: 3,285 on the direct HTTP path and 942 on the TLS-proxied path. This includes malformed requests and background scanning, not just the selected PHP2Shell families. The proxy's 949 starts, 942 completions, and seven aborts are lifecycle records and are not added to the Apache total.

TLS source correlation resolved 942 of 942 proxied access records. The decoded packet-response count elsewhere in the report is a separate capture-derived measure, not an additional request total.

| Persona | Access records | POST records | HTTP 200 | HTTP 400–499 | HTTP 500–599 |
|---|---:|---:|---:|---:|---:|
| API | 182 | 11 | 100 | 82 | 0 |
| Drupal | 1867 | 1002 | 1238 | 629 | 0 |
| Joomla | 1016 | 48 | 224 | 792 | 0 |
| Portal | 406 | 53 | 226 | 180 | 0 |
| Roundcube | 272 | 14 | 129 | 143 | 0 |
| WordPress | 484 | 52 | 208 | 276 | 0 |

| Method recorded by Apache | Records |
|---|---:|
| `GET` | 2764 |
| `POST` | 1180 |
| `-` | 124 |
| `HEAD` | 36 |
| `CONNECT` | 32 |
| `OPTIONS` | 20 |
| `PUT` | 16 |
| `PATCH` | 16 |
| `DELETE` | 16 |
| `PROPFIND` | 13 |
| `PRI` | 8 |
| `BMYM` | 1 |
| `FQOM` | 1 |

`-`, `PRI`, and nonstandard method strings are preserved as logged. They are not reclassified as valid application requests.

### Request shapes from selected sources

These rows include every distinct method/path/status combination recorded for sources in the observable table. Query strings are grouped under their path; counts include reconnaissance and other traffic from those sources, not only matched exploit probes.

<details>
<summary>Full request-shape table: 203 combinations</summary>

| Method / path / status | Access records |
|---|---:|
| `POST /index.php → 200` | 935 |
| `GET / → 200` | 202 |
| `POST / → 200` | 145 |
| `GET /index.php → 200` | 64 |
| `POST /bitsight/internet_census/probe → 404` | 8 |
| `HEAD / → 200` | 5 |
| `GET /info.php → 404` | 5 |
| `GET /favicon.ico → 404` | 4 |
| `GET /phpinfo.php → 404` | 4 |
| `GET /upload.php → 200` | 3 |
| `POST /wp-login.php → 200` | 3 |
| `GET /admin/upload.php → 404` | 2 |
| `GET /wp-admin/media-new.php → 404` | 2 |
| `POST /upload.php → 200` | 2 |
| `GET / → 400` | 1 |
| `GET /user/login → 200` | 1 |
| `POST /user/login → 200` | 1 |
| `GET /node → 200` | 1 |
| `- - → 408` | 1 |
| `GET /shell_059f4c5d.phtml → 404` | 1 |
| `GET /uploads/shell_059f4c5d.phtml → 404` | 1 |
| `GET /upload/shell_059f4c5d.phtml → 404` | 1 |
| `GET /files/shell_059f4c5d.phtml → 404` | 1 |
| `GET /wp-content/uploads/shell_059f4c5d.phtml → 404` | 1 |
| `GET /media/shell_059f4c5d.phtml → 404` | 1 |
| `GET /storage/shell_059f4c5d.phtml → 404` | 1 |
| `GET /upload/shell_059f4c5d.php5 → 404` | 1 |
| `GET /files/shell_059f4c5d.php5 → 404` | 1 |
| `GET /wp-content/uploads/shell_059f4c5d.php5 → 404` | 1 |
| `GET /media/shell_059f4c5d.php5 → 404` | 1 |
| `GET /content/uploads/shell_059f4c5d.php5 → 404` | 1 |
| `GET /shell_059f4c5d.php → 404` | 1 |
| `GET /uploads/shell_059f4c5d.php → 404` | 1 |
| `GET /upload/shell_059f4c5d.php → 404` | 1 |
| `GET /files/shell_059f4c5d.php → 404` | 1 |
| `GET /wp-content/uploads/shell_059f4c5d.php → 404` | 1 |
| `GET /media/shell_059f4c5d.php → 404` | 1 |
| `GET /images/shell_059f4c5d.php → 404` | 1 |
| `GET /data/uploads/shell_059f4c5d.php → 404` | 1 |
| `GET /public/uploads/shell_059f4c5d.php → 404` | 1 |
| `GET /content/uploads/shell_059f4c5d.php → 404` | 1 |
| `GET /shell_059f4c5d.phar → 404` | 1 |
| `GET /uploads/shell_059f4c5d.phar → 404` | 1 |
| `GET /upload/shell_059f4c5d.phar → 404` | 1 |
| `GET /wp-content/uploads/shell_059f4c5d.phar → 404` | 1 |
| `GET /media/shell_059f4c5d.phar → 404` | 1 |
| `GET /storage/shell_059f4c5d.phar → 404` | 1 |
| `GET /data/uploads/shell_059f4c5d.phar → 404` | 1 |
| `GET /public/uploads/shell_059f4c5d.phar → 404` | 1 |
| `GET /content/uploads/shell_059f4c5d.phar → 404` | 1 |
| `GET /admin/ → 404` | 1 |
| `GET /wp-login.php → 404` | 1 |
| `GET /fileupload.php → 404` | 1 |
| `GET /uploader.php → 404` | 1 |
| `GET /tools/upload.php → 404` | 1 |
| `GET /file-upload.php → 404` | 1 |
| `GET /admin/uploader.php → 404` | 1 |
| `GET /api/upload.php → 404` | 1 |
| `GET /ajax/upload.php → 404` | 1 |
| `GET /includes/upload.php → 404` | 1 |
| `GET /modules/upload.php → 404` | 1 |
| `GET /wp-admin/async-upload.php → 404` | 1 |
| `GET /wp-admin/admin-ajax.php → 404` | 1 |
| `GET /components/com_jprofi/upload.php → 404` | 1 |
| `GET /assets/upload.php → 404` | 1 |
| `GET /panel/upload.php → 404` | 1 |
| `GET /manager/upload.php → 404` | 1 |
| `GET /public/upload.php → 404` | 1 |
| `GET /cgi-bin/upload.php → 404` | 1 |
| `GET /dropzone/upload.php → 404` | 1 |
| `GET /plupload/upload.php → 404` | 1 |
| `GET /fckeditor/editor/filemanager/connectors/php/upload.php → 404` | 1 |
| `GET /ckeditor/upload.php → 404` | 1 |
| `GET /tinymce/upload.php → 404` | 1 |
| `GET /editor/upload.php → 404` | 1 |
| `GET /forum/upload.php → 404` | 1 |
| `GET /gallery/upload.php → 404` | 1 |
| `GET /photo/upload.php → 404` | 1 |
| `GET /avatar/upload.php → 404` | 1 |
| `GET /profile/upload.php → 404` | 1 |
| `GET /user/upload.php → 404` | 1 |
| `GET /member/upload.php → 404` | 1 |
| `GET /shop/upload.php → 404` | 1 |
| `GET /import/upload.php → 404` | 1 |
| `GET /backup/upload.php → 404` | 1 |
| `GET /handler.php → 404` | 1 |
| `GET /fileupload/index.php → 404` | 1 |
| `GET /shell_aba5012a.phtml → 404` | 1 |
| `GET /uploads/shell_aba5012a.phtml → 404` | 1 |
| `GET /upload/shell_aba5012a.phtml → 404` | 1 |
| `GET /files/shell_aba5012a.phtml → 404` | 1 |
| `GET /wp-content/uploads/shell_aba5012a.phtml → 404` | 1 |
| `GET /media/shell_aba5012a.phtml → 404` | 1 |
| `GET /images/shell_aba5012a.phtml → 404` | 1 |
| `GET /storage/shell_aba5012a.phtml → 404` | 1 |
| `GET /data/uploads/shell_aba5012a.phtml → 404` | 1 |
| `GET /public/uploads/shell_aba5012a.phtml → 404` | 1 |
| `GET /content/uploads/shell_aba5012a.phtml → 404` | 1 |
| `GET /shell_aba5012a.php5 → 404` | 1 |
| `GET /uploads/shell_aba5012a.php5 → 404` | 1 |
| `GET /upload/shell_aba5012a.php5 → 404` | 1 |
| `GET /files/shell_aba5012a.php5 → 404` | 1 |
| `GET /wp-content/uploads/shell_aba5012a.php5 → 404` | 1 |
| `GET /media/shell_aba5012a.php5 → 404` | 1 |
| `GET /images/shell_aba5012a.php5 → 404` | 1 |
| `GET /storage/shell_aba5012a.php5 → 404` | 1 |
| `GET /data/uploads/shell_aba5012a.php5 → 404` | 1 |
| `GET /public/uploads/shell_aba5012a.php5 → 404` | 1 |
| `GET /content/uploads/shell_aba5012a.php5 → 404` | 1 |
| `GET /shell_aba5012a.php → 404` | 1 |
| `GET /uploads/shell_aba5012a.php → 404` | 1 |
| `GET /files/shell_aba5012a.php → 404` | 1 |
| `GET /wp-content/uploads/shell_aba5012a.php → 404` | 1 |
| `GET /images/shell_aba5012a.php → 404` | 1 |
| `GET /public/uploads/shell_aba5012a.php → 404` | 1 |
| `GET /content/uploads/shell_aba5012a.php → 404` | 1 |
| `GET /shell_aba5012a.phar → 404` | 1 |
| `GET /uploads/shell_aba5012a.phar → 404` | 1 |
| `GET /upload/shell_aba5012a.phar → 404` | 1 |
| `GET /media/shell_aba5012a.phar → 404` | 1 |
| `GET /public/uploads/shell_aba5012a.phar → 404` | 1 |
| `GET /content/uploads/shell_aba5012a.phar → 404` | 1 |
| `GET /shell_4652a6d1.phtml → 404` | 1 |
| `GET /uploads/shell_4652a6d1.phtml → 404` | 1 |
| `GET /upload/shell_4652a6d1.phtml → 404` | 1 |
| `GET /files/shell_4652a6d1.phtml → 404` | 1 |
| `GET /wp-content/uploads/shell_4652a6d1.phtml → 404` | 1 |
| `GET /media/shell_4652a6d1.phtml → 404` | 1 |
| `GET /images/shell_4652a6d1.phtml → 404` | 1 |
| `GET /storage/shell_4652a6d1.phtml → 404` | 1 |
| `GET /data/uploads/shell_4652a6d1.phtml → 404` | 1 |
| `GET /public/uploads/shell_4652a6d1.phtml → 404` | 1 |
| `GET /content/uploads/shell_4652a6d1.phtml → 404` | 1 |
| `GET /shell_4652a6d1.php5 → 404` | 1 |
| `GET /uploads/shell_4652a6d1.php5 → 404` | 1 |
| `GET /upload/shell_4652a6d1.php5 → 404` | 1 |
| `GET /files/shell_4652a6d1.php5 → 404` | 1 |
| `GET /wp-content/uploads/shell_4652a6d1.php5 → 404` | 1 |
| `GET /media/shell_4652a6d1.php5 → 404` | 1 |
| `GET /images/shell_4652a6d1.php5 → 404` | 1 |
| `GET /storage/shell_4652a6d1.php5 → 404` | 1 |
| `GET /data/uploads/shell_4652a6d1.php5 → 404` | 1 |
| `GET /shell_4652a6d1.php → 404` | 1 |
| `GET /uploads/shell_4652a6d1.php → 404` | 1 |
| `GET /files/shell_4652a6d1.php → 404` | 1 |
| `GET /images/shell_4652a6d1.php → 404` | 1 |
| `GET /storage/shell_4652a6d1.php → 404` | 1 |
| `GET /public/uploads/shell_4652a6d1.php → 404` | 1 |
| `GET /content/uploads/shell_4652a6d1.php → 404` | 1 |
| `GET /uploads/shell_4652a6d1.phar → 404` | 1 |
| `GET /files/shell_4652a6d1.phar → 404` | 1 |
| `GET /media/shell_4652a6d1.phar → 404` | 1 |
| `GET /images/shell_4652a6d1.phar → 404` | 1 |
| `GET /storage/shell_4652a6d1.phar → 404` | 1 |
| `GET /data/uploads/shell_4652a6d1.phar → 404` | 1 |
| `GET /public/uploads/shell_4652a6d1.phar → 404` | 1 |
| `GET /content/uploads/shell_4652a6d1.phar → 404` | 1 |
| `GET /php_info.php → 404` | 1 |
| `GET /test.php → 404` | 1 |
| `GET /i.php → 404` | 1 |
| `GET /phpinfo/ → 404` | 1 |
| `GET /p.php → 404` | 1 |
| `GET /admin/phpinfo.php → 404` | 1 |
| `GET /shell_f74c8bbc.phtml → 404` | 1 |
| `GET /uploads/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /upload/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /files/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /wp-content/uploads/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /media/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /images/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /storage/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /data/uploads/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /public/uploads/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /content/uploads/shell_f74c8bbc.phtml → 404` | 1 |
| `GET /shell_f74c8bbc.php5 → 404` | 1 |
| `GET /uploads/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /upload/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /files/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /wp-content/uploads/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /media/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /images/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /storage/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /data/uploads/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /public/uploads/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /content/uploads/shell_f74c8bbc.php5 → 404` | 1 |
| `GET /shell_f74c8bbc.php → 404` | 1 |
| `GET /uploads/shell_f74c8bbc.php → 404` | 1 |
| `GET /upload/shell_f74c8bbc.php → 404` | 1 |
| `GET /files/shell_f74c8bbc.php → 404` | 1 |
| `GET /wp-content/uploads/shell_f74c8bbc.php → 404` | 1 |
| `GET /media/shell_f74c8bbc.php → 404` | 1 |
| `GET /images/shell_f74c8bbc.php → 404` | 1 |
| `GET /storage/shell_f74c8bbc.php → 404` | 1 |
| `GET /data/uploads/shell_f74c8bbc.php → 404` | 1 |
| `GET /public/uploads/shell_f74c8bbc.php → 404` | 1 |
| `GET /content/uploads/shell_f74c8bbc.php → 404` | 1 |
| `GET /upload/shell_f74c8bbc.phar → 404` | 1 |
| `GET /files/shell_f74c8bbc.phar → 404` | 1 |
| `GET /media/shell_f74c8bbc.phar → 404` | 1 |
| `GET /storage/shell_f74c8bbc.phar → 404` | 1 |
| `GET /data/uploads/shell_f74c8bbc.phar → 404` | 1 |
| `GET /public/uploads/shell_f74c8bbc.phar → 404` | 1 |
| `GET /content/uploads/shell_f74c8bbc.phar → 404` | 1 |

</details>

## Appendix: TLS and HTTP fingerprints

Fingerprints below were emitted by the TLS proxy and are reproduced as recorded, not independently recomputed. Counts refer to completed proxy requests from the listed sources, including reconnaissance; no JA4 was inferred for plaintext traffic. JA4H describes HTTP request structure and can vary by method and headers.

| Sources | Completed requests | JA4 | JA4H |
|---|---:|---|---|
| `45.156.128.47`, `45.156.129.52`, `45.156.129.57`, `109.105.210.102` | 4 | `t12i330500_5172cef6ed69_021165082e1c` | `ge11nn040000_88d30a62b7ad_000000000000_000000000000` |
| `27.100.38.10` | 3 | `t13i311000_e8f1e7e78f70_d41ae481755e` | `ge10nn020000_f24fcf356134_000000000000_000000000000` |
| `27.100.38.10` | 6 | `t13i311000_e8f1e7e78f70_d41ae481755e` | `ge11nn040000_f6984dcda499_000000000000_000000000000` |
| `27.100.38.10` | 1 | `t13i311000_e8f1e7e78f70_d41ae481755e` | `he11nn030000_86b6b04cb9cc_000000000000_000000000000` |
| `27.100.38.10` | 3 | `t13i311000_e8f1e7e78f70_d41ae481755e` | `po11nn040000_ace4a2dcc35f_000000000000_000000000000` |
| `27.100.38.10` | 2 | `t13i311000_e8f1e7e78f70_d41ae481755e` | `po11nn060000_4dd58824e810_000000000000_000000000000` |
| `45.156.128.41`, `45.156.128.43`, `45.156.128.45`, `45.156.128.47`, `45.156.129.52`, `45.156.129.57`, `109.105.210.102` | 13 | `t13i7511h1_479067518aa3_b26ce05bbdd6` | `po11cn070000_7a7c5172e3ad_fe81d65a9ab0_658f8aebdf77` |

For `27.100.38.10`, the three 1,060,211-byte POSTs correlated with OOMs used JA4H `po11nn040000_ace4a2dcc35f_000000000000_000000000000`. The other fingerprint rows include survey-labelled activity; they should not be treated as RCE indicators.

## Appendix: representative requests

The following excerpts retain observed request lines, selected headers, and decoded body sections. Destination hosts are represented by `example.invalid`; HTTP chunk framing is removed and line endings normalized. Long runs of identical filler characters are abbreviated, and omission markers identify shortened bodies. Body hashes cover the full reconstructed body, or the captured portion when explicitly marked incomplete. These are excerpts, not replay-ready raw requests.

### B1 leak-stage body

Source `103.151.173.212`; 10-23 17:47:16 UTC connection start; Drupal. Reconstructed body: 33,128,677 bytes, complete; SHA-256 `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2`.

```http
POST /index.php HTTP/1.1
Host: example.invalid
content-type: multipart/form-data; boundary=CCCCCCCCCC
transfer-encoding: chunked

--CCCCCCCCCC
Content-Disposition: form-data; name="PHPSESSID"

a
--CCCCCCCCCC
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

k0
--CCCCCCCCCC
Content-Disposition: form-data; name="f0000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[repeated filler abbreviated]
[body excerpt ends]
```

### Fixed-session initialization

Source `14.102.84.193`; 10-23 18:15:10 UTC connection start; Drupal. Reconstructed body: 192 bytes, complete; SHA-256 `5b29950f7d421c5e7336441cf370d07e95a196b47c905bfbddef94e0d36c6937`.

```http
POST / HTTP/1.1
Host: example.invalid
content-type: multipart/form-data; boundary=BNDRY12345
content-length: 192

--BNDRY12345
Content-Disposition: form-data; name="PHPSESSID"

attacksessionid0001
--BNDRY12345
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

pwn
--BNDRY12345--

```

### Core/serializer probe

Source `84.32.50.51`; 10-23 21:20:12 UTC connection start; Drupal. Reconstructed body: 8,755 bytes, complete; SHA-256 `24e48ed82efcde4c48d48ce1bdfc47c3c41fb33ff95d60e1f3f001947df9b4e7`.

```http
POST / HTTP/1.1
Host: example.invalid
user-agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
content-type: multipart/form-data; boundary=----Php2Shell22fe580e9
content-length: 8755
cookie: PHPSESSID=p2sca35689de5a64ce4

------Php2Shell22fe580e9
Content-Disposition: form-data; name="PHPSESSID"

p2sca35689de5a64ce4
------Php2Shell22fe580e9
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

upload_progress|a:2:{s:4:"name";s:25:"PHP2SHELL_CORE_ser_c75749";s:8:"handler";s:13:"php_serialize";}
------Php2Shell22fe580e9
Content-Disposition: form-data; name="session.serialize_handler"

php_serialize
------Php2Shell22fe580e9
Content-Disposition: form-data; name="f"; filename="PHP2SHELL_CORE_ser_c75749_php_serialize.txt"

ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
[repeated filler abbreviated]
[body excerpt ends]
```

### Large-field chunked upload

Source `188.253.121.168`; 10-23 17:23:24 UTC connection start; WordPress. Reconstructed body: 62,960,234 bytes, incomplete; SHA-256 `ede558480c3d4d2e7eafff5a6fae97ea92bf94e616325c85fbd02747ac357980`.

```http
POST /index.php HTTP/1.1
Host: example.invalid
content-type: multipart/form-data; boundary=SSSSSSSSSSSSSSSSS
transfer-encoding: chunked

--SSSSSSSSSSSSSSSSS
Content-Disposition: form-data; name="g0000xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

vvvvvvvv
--SSSSSSSSSSSSSSSSS
Content-Disposition: form-data; name="g0001xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

vvvvvvvv
--SSSSSSSSSSSSSSSSS
Content-Disposition: form-data; name="g0002xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

vvvvvvvv
--SSSSSSSSSSSSSSSSS
Content-Disposition: form-data; name="g0003xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

vvvvvvvv
--SSSSSSSSSSSSSSSSS
Content-Disposition: form-data; name="g0004xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
[body excerpt ends]
```

### Nested-file probe

Source `190.47.59.9`; 10-23 10:39:03 UTC connection start; WordPress. Reconstructed body: 300,067 bytes, complete; SHA-256 `f3c6533141734d3c5a7e781227542da4ceb5b06e0250b8c8ac3e36b79e946891`.

```http
POST / HTTP/1.1
Host: example.invalid
content-type: multipart/form-data; boundary=PROBE
content-length: 300067

--PROBE
Content-Disposition: form-data; name="a"

x
--PROBE
Content-Disposition: form-data; name="files[R00000][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a]"; filename=""
Content-Type: application/octet-stream


--PROBE
Content-Disposition: form-data; name="files[R00001][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a]"; filename=""
Content-Type: application/octet-stream


--PROBE
Content-Disposition: form-data; name="files[R00002][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a][a
[body excerpt ends]
```

### Survey-labelled upload-progress request

Source `109.105.210.102`; 10-23 07:08:20 UTC connection start; Drupal. Reconstructed body: 302 bytes, complete; SHA-256 `391d61b5f3ea47af476acde03bd0ef5d3ede5febc25940b96db9b0fda787c701`.

```http
POST / HTTP/1.1
Host: example.invalid
user-agent: python-requests/2.31.0
content-type: multipart/form-data; boundary=45397338d3cf2e2d2dd3acf27bde6b7f
content-length: 302
cookie: PHPSESSID=_

--45397338d3cf2e2d2dd3acf27bde6b7f
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

internet-census
--45397338d3cf2e2d2dd3acf27bde6b7f
Content-Disposition: form-data; name="f"; filename="internet-census.txt"
Content-Type: text/plain

1
--45397338d3cf2e2d2dd3acf27bde6b7f--

```

### TLS upload-progress reconnaissance

Source `27.100.38.10`; 10-23 13:40:43 UTC; WordPress. The proxy captured the complete 523-byte body, SHA-256 `7f2b8a256a0de71d6759dfe2d6dea9ea6f3981bfb99496c184cd80a673ebb219`. This smaller probe preceded the three larger OOM-associated POSTs.

```http
POST / HTTP/1.1
Host: example.invalid
User-Agent: Mozilla/5.0
Content-Type: multipart/form-data; boundary=----recon0xdeadbeef
Content-Length: 523

------recon0xdeadbeef
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

probe_recon
------recon0xdeadbeef
Content-Disposition: form-data; name="upload"; filename="probe.txt"
Content-Type: application/octet-stream

XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[repeated filler abbreviated]
------recon0xdeadbeef--

```
