# ER Diagram Notes

## Entities & Relationships
- Users (1) → Accounts (1) — one user has one account
- Users (1) → Audit_Log (many) — every action is logged
- Users (1) → Alerts (many) — suspicious activity flagged
- Accounts (1) → Transactions (many) — all money movements tracked

## Cyber-Specific Columns
- `failed_attempts` → detects brute force login
- `ip_address` → detects location-based intrusion
- `alert_type` + `status` → threat alerting system

## Normalization
- 1NF — no repeating groups
- 2NF — no partial dependencies
- 3NF — no transitive dependencies
