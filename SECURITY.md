# Security Policy

## Educational Prototype Notice

This repository is an academic / educational prototype demonstrating database management principles, secure transaction processing, and defensive software controls.

> [!WARNING]
> This software is **NOT** intended for production financial infrastructure or real-money transactions. It is designed solely for demonstration, testing, and educational purposes.

---

## Demo Accounts

Demo users (`ayush@bank.com`, `rahul@bank.com`, `priya@bank.com`) are not created automatically at startup. They are seeded only by explicitly running [`scripts/seed_demo.py`](scripts/seed_demo.py), which reads passwords from environment variables (`DEMO_ADMIN_PASSWORD`, `DEMO_RAHUL_PASSWORD`, `DEMO_PRIYA_PASSWORD`) or prompts interactively via `getpass` and enforces `password_meets_policy()`.

- Never reuse real personal or banking passwords when testing this application.
- Never deploy this prototype with test or demo accounts enabled.

---

## Reporting Security Vulnerabilities

If you discover a security flaw, potential exploit, or vulnerability in this educational project:

1. **Do not** create a public GitHub issue detailing reproducible exploit steps.
2. Please report findings responsibly by opening a private security advisory on GitHub or by contacting the project maintainer via GitHub profile: [ayushkulhari47](https://github.com/ayushkulhari47).
3. Include in your report:
   - A clear description of the vulnerability and attack vector.
   - Proof of Concept (PoC) steps or automated test reproducing the behavior.
   - Suggested remediation or patch if available.
