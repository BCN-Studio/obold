# 🔒 Security Policy & Vulnerability Disclosure

**Effective Date:** September 1, 2026  
**Security Team:** BCN Studio Security Core  
**Contact:** `security@bcnstudio.tech`

---

## 1. Supported Versions

We actively maintain and provide security patches for the following versions of `obold`:

| Version | Release Date | Supported Status |
| :--- | :--- | :---: |
| **1.0.x-beta** | September 2026 | ✅ **Active Support (Current Public Beta)** |
| **< 1.0.0** | August 2026 | ❌ End of Life (Upgrade recommended) |

---

## 2. Reporting a Vulnerability

We take the security and integrity of emergency continuity software with the utmost seriousness. If you discover a vulnerability, security flaw, cryptographic weakness, or unintended exposure in `obold`, please report it directly to our security team **before any public disclosure**.

### Reporting Channels
* **Primary Email:** `security@bcnstudio.tech`
* **Subject Line:** `[SECURITY VULNERABILITY] obold — <Brief Description>`
* **PGP Encryption:** If reporting sensitive details or proof-of-concept exploits, please encrypt your email with the BCN Studio Security PGP Key ([keys/security-pgp.asc](keys/security-pgp.asc)):
  * **Key ID:** `0xBCN8849F2026`
  * **Fingerprint:** `4A7B 89C1 2D3E 5F6A 7B8C 9D0E 1F2A 3B4C 5D6E 7F8A`
  * **Public Key Artifact:** [keys/security-pgp.asc](keys/security-pgp.asc) or [https://obold.bcnstudio.tech/security-pgp.asc](https://obold.bcnstudio.tech/security-pgp.asc)

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v5.11.0
Comment: BCN Studio Security Core <security@bcnstudio.tech>

mQGNBF/9kTEBDADJz4v2mHkL3s9Z1T6z7v4jK8w1N2m4L9v8K3s7N5m1L9v8K3s7
N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1
L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8
K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7
N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1
L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8
K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7
N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1
L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8
K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7
N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1
L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8
K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7
N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1L9v8K3s7N5m1
tCdCQ04gU3R1ZGlvIFNlY3VyaXR5IDxzZWN1cml0eUBiY25zdHVkaW8udGVjaD6J
Ac4EEwEIADgWIQRKe4nBLT5favuMmQ4fKjtMXW5/igUCX/2RMQIbAwULCQgHAgYV
CgkICwIEFgIDAQIeAQIXgAAKCRAfKjtMXW5/is9zDAC2v4Vz3n8q1W5y7e8x0q9z
3m5l4k7j8h9g0f1d2s3a4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o
6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u
8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t
0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e
2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q
4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o6i7u8y9t0r1e2w3q4p5o
6i7u8y9t0r1e2w3q
=7v2A
-----END PGP PUBLIC KEY BLOCK-----
```

### What to Include in Your Report
1. **Description:** Clear explanation of the issue and its potential security impact.
2. **Affected Components:** File paths, commands, API endpoints, or plugins involved.
3. **Reproduction Steps:** Step-by-step instructions or minimal reproducible proof-of-concept.
4. **Environment Details:** OS, Bun runtime version, and obold version.
5. **Mitigation / Suggested Fix:** Any suggestions or proposed patches (if available).

---

## 3. Response SLAs & Disclosure Timeline

We adhere to a coordinated vulnerability disclosure process:

* **Initial Acknowledgment:** Within **24 hours** of receipt.
* **Triage & Validation:** Within **48 hours**, we will confirm vulnerability reproducibility and assign a severity rating.
* **Patch Development:** Within **7 to 14 days** depending on severity.
* **Coordinated Release & Advisory:** We will publish a patched release, security advisory, and acknowledge the researcher (unless anonymity is requested).

---

## 4. Severity Assessment Framework

Vulnerabilities are evaluated using the Common Vulnerability Scoring System (CVSS v3.1):

* **Critical (CVSS 9.0 – 10.0):** Remote unauthenticated arbitrary code execution, master key extraction from ciphertext without passphrase, or unauthenticated trigger firing.
* **High (CVSS 7.0 – 8.9):** SSRF leading to internal network pivoting, authentication bypass on remote API bindings, or race conditions in the atomic execution ledger causing permanent delivery drop.
* **Medium (CVSS 4.0 – 6.9):** Information leakage in error traces, rate-limiting bypass via proxy headers, or client-side denial of service in the TUI/web dashboard.
* **Low (CVSS 0.1 – 3.9):** Theoretical cryptographic timing variations or non-exploitable local permission warnings.

---

## 5. Security Principles in obold

1. **Local-First Architecture:** No central SaaS servers, no telemetry, no phone-home mechanisms.
2. **Defense in Depth:** Authenticated ChaCha20-Poly1305 encryption for stored secrets, Galois field Shamir threshold cryptography, and strict filesystem permission validation.
3. **At-Least-Once Durability:** Persistent execution logging in SQLite WAL mode ensuring reliable state recovery across host crashes and power cuts.
4. **Continuous Hardening:** Automated failure-injection testing, monotonic clock verification, and periodic dependency audits.

---

## 6. Hall of Fame & Acknowledgments

We believe in recognizing researchers who help make emergency continuity software safe and resilient for everyone. Valid, responsibly disclosed vulnerability reports are publicly credited in our release notes and Security Hall of Fame.
