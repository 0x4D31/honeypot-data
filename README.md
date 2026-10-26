# Honeypot Datasets & Reports

Public datasets and observation reports collected from Internet-facing honeypots.

## Available Datasets

- *2025-07-31 → 2025-11-01* — Finch Reverse Proxy: See the [dataset card](datasets/finch_20250731-20251101/DATASET_CARD.md) for details (source IPs are pseudonymized).
- *2026-10-24* — [PHP2Shell confirmed-RCE evidence](reports/php2shell/2026-10-24-rce-evidence/README.md): 35 case folders with HTTP packet captures and selected Apache, PHP, Tetragon, and signal records. Source IPs are retained; the evidence README documents the limited substitutions.

## Observation Reports

- *2026-10-22 → 2026-10-24* — PHP2Shell Exploitation ([initial exploitation attempts](reports/php2shell/2026-10-22-to-24-initial-attempts.md) and [confirmed RCE](reports/php2shell/2026-10-24-confirmed-rce.md)). Unlike the Finch dataset above, these reports intentionally retain unredacted source IPs as indicators.
