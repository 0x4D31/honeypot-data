## Finch Reverse Proxy *Honeypot* (2025-07-31 → 2025-11-01)

### Overview
Three months of unsolicited inbound traffic captured by a Finch TLS reverse-proxy running on AWS EC2. Each record represents a single inbound request with full HTTP and TLS metadata, including JA3, JA3Raw, JA4, JA4H, Akamai HTTP/2 fingerprint, Suricata detections, and geolocation + ASN enrichment.

> ⚠️ Headers and bodies are preserved verbatim and may contain exploit payloads. Handle safely.

- **Collector:** [Finch](https://github.com/0x4D31/finch) reverse-proxy  
- **File format:** JSON Lines (`.jsonl.zst`)  
- **Schema:** [`schema/finch_event.v1.schema.json`](../../schema/finch_event.v1.schema.json)  
- **Size:** ~20 MB uncompressed (~22k requests)

### Pseudonymization

Source IPs are pseudonymized.  
- `srcIP` replaced with:  
  - `srcIP_hash` — HMAC-SHA256 (12 hex chars, stable per IP using a private salt)  
  - `srcIP_prefix` — `/24` (IPv4) or `/48` (IPv6) network  
  - `srcASN`, `srcASNOrg`, `srcCountry` — derived from MaxMind GeoLite2-ASN / City  
- Destination IPs belong to decommissioned honeypot infrastructure and are retained.

### License

Creative Commons Attribution 4.0 International (CC BY 4.0)
