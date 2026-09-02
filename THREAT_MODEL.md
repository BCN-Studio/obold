# 🛡️ obold Threat Model & Security Architecture

**Version:** 1.0.0-beta  
**Effective Date:** September 1, 2026  
**Security Standard:** BCN Studio Sovereign Security Framework (https://bcnstudio.tech)  
**Audience:** Security researchers, operators, cryptographic auditors, and users deploying obold for high-assurance emergency continuity.

---

## 1. Executive Summary & Security Objectives

`obold` is a local-first, sovereign emergency continuity daemon and dead man's switch. Its primary security objective is to **durably execute predefined actions (such as credential release, notification dispatch, or key destruction) if and only if the operator fails to perform periodic authenticated check-ins within a configured countdown window.**

Because dead man's switches operate under conditions of operator absence, physical duress, or catastrophic infrastructure disruption, this document explicitly defines our threat model, adversary assumptions, trust boundaries, cryptographic architecture, and known limitations.

---

## 2. Comprehensive Attacker Model ($A_1 – A_{20}$)

We evaluate `obold` against 20 distinct attacker classes, failure modes, and threat vectors:

### Network & Remote Vectors

* **$A_1$ — Remote Unauthenticated Attacker:** An attacker on the local network or public Internet attempting to trigger switches, disable countdowns, inspect secrets, or crash the daemon.
  * *Defense:* Default server binds strictly to loopback (`127.0.0.1`). Remote binding (`0.0.0.0`) strictly requires mandatory bearer token authentication. CORS rejects wildcards on remote bindings.
* **$A_2$ — Remote Authenticated Attacker:** An attacker possessing valid standard API credentials attempting privilege escalation, master key extraction, or unauthorized state mutation.
  * *Defense:* Principle of least privilege. Cryptographic keys and raw passphrases are never returned over HTTP API endpoints. Remote Shamir secret reconstruction is disabled by default (`allowRemoteCryptoApi: false`).
* **$A_3$ — Malicious or Untrusted Community Plugin:** A third-party plugin attempting arbitrary code execution, filesystem exfiltration, or credential theft.
  * *Defense:* Plugin risk tier classification (`TRUSTED_CORE`, `SENSITIVE_CORE`, `PRIVILEGED_HOST`, `COMMUNITY`). Privileged actions (like `core:shell`) require explicit configuration confirmation.
* **$A_4$ — Compromised Delivery Infrastructure (Telegram, Signal, Matrix Relay):** An upstream delivery provider intercepting, altering, or dropping notifications.
  * *Defense:* Multi-channel progressive escalation routes shares and notices across independent provider failure domains. Dynamic Shamir sharding ensures no single intercepted channel reveals the root secret.
* **$A_5$ — Compromised SMTP Relay & Plaintext Eavesdropping:** An intermediate mail transfer agent (MTA) inspecting plaintext email messages.
  * *Defense:* SMTP transport encryption (STARTTLS) protects messages in transit. Operators distributing secrets via email should utilize GPG encryption (`core:gpg`) or Shamir shares rather than plaintext credentials.
* **$A_6$ — Compromised Cloud Storage (S3 / R2):** A compromised cloud storage bucket where encrypted rescue payloads or wipe triggers are stored.
  * *Defense:* All payloads stored via `core:s3` are authenticated and encrypted locally using ChaCha20-Poly1305 or AES-256-GCM prior to transmission. The cloud provider only sees ciphertext.

### Local Host & Filesystem Vectors

* **$A_7$ — Local Unprivileged System User:** Another unprivileged user on the same multi-user host attempting to read obold configuration, database files, or process memory.
  * *Defense:* SQLite database files (`obold.db`) and master key files (`.obold.key`) are initialized with strict Unix file permissions (`0600`). Process memory is zeroed after sensitive operations.
* **$A_8$ — Local Root / Administrative Compromise:** An attacker with root/SYSTEM privileges on the host where obold is running.
  * *Defense:* **Out of scope.** A compromised root account can read process memory, inspect kernel memory, or alter daemon binaries. Operators requiring root-isolated survivability should run obold on dedicated hardware, an isolated virtual machine, or an air-gapped node.
* **$A_9$ — Stolen SQLite Database at Rest:** An attacker acquiring a copy of the `obold.db` file from physical theft, discarded disks, or unencrypted backups.
  * *Defense:* All execution ledger payloads, snapshot secrets, and sensitive switch configs are encrypted at rest using ChaCha20-Poly1305 with scrypt key derivation.
* **$A_{10}$ — Stolen Master Encryption Key:** An attacker acquiring the master passphrase or `.obold.key` file.
  * *Defense:* Without the database, the key is useless. If the key is suspected to be compromised, operators can execute `obold rekey` to rotate the master key and atomically re-encrypt all stored ledger records with zero downtime.
* **$A_{11}$ — Intercepted or Stolen Offline Rescue Bundle (`rescue.html`):** An unauthorized party acquiring an offline inheritance rescue vault.
  * *Defense:* The payload inside `rescue.html` is encrypted with AES-256-GCM and split across Galois field $\text{GF}(2^8)$ Shamir threshold shards. The file cannot be decrypted without possessing at least $k$-of-$n$ recovery shares.

### Physical, Environmental & Failure Vectors

* **$A_{12}$ — Physical Coercion & Coerced Check-In (Duress Protocol):** An operator forced under threat to check in and extend the timer to prevent an emergency alert.
  * *Defense:* **Duress PIN Protocol.** Entering the secret duress PIN returns a visually indistinguishable success response while silently firing covert distress beacons and logging a high-priority security event. *(See Section 4 for limitations).*
* **$A_{13}$ — Internet Outages & Network Disconnection:** The daemon loses Internet access while an emergency trigger is attempting delivery.
  * *Defense:* Persistent exponential backoff retry queue recorded in SQLite WAL. Failed actions are retried automatically upon network restoration.
* **$A_{14}$ — DNS Hijacking, Spoofing & Rebinding:** An attacker attempting SSRF via dynamic DNS rebinding or redirecting webhooks to private cloud metadata endpoints (`169.254.169.254`).
  * *Defense:* SSRF Network Guard with `redirect: 'manual'` inspection. Every redirect hop is re-resolved and validated against private and link-local IPv4/IPv6 subnets.
* **$A_{15}$ — Sudden Power Loss & Hardware Failure:** The host machine experiences unexpected power cutoff or kernel panic mid-transaction.
  * *Defense:* SQLite Write-Ahead Logging (WAL) guarantees transaction durability. Upon daemon restart, the boot-time crash replay engine reads unacknowledged executions from the ledger and resumes delivery.
* **$A_{16}$ — System Clock Manipulation, NTP Skew & VM Suspend:** The system clock jumps forward or backward due to NTP glitches, battery exhaustion, or VM hibernation.
  * *Defense:* High-resolution monotonic timers (`process.hrtime.bigint()`) track elapsed duration independently of wall-clock shifts to detect and log sudden time jumps.

### Operational & Supply-Chain Vectors

* **$A_{17}$ — Host Cold Reboot without Operator (Unattended Recovery):** The host restarts after a power failure while the operator is incapacitated or absent.
  * *Defense:* Background system service (`systemd` / `launchd`) automatically restarts the daemon and invokes `replayLedger()` to resume active timers and retry unacknowledged executions.
* **$A_{18}$ — Supply-Chain Dependency Tampering:** Malicious transitive dependencies attempting to intercept keys or manipulate execution.
  * *Defense:* Zero-dependency core cryptographic engine utilizing native Node/Bun crypto primitives. Strict lockfile freezing (`bun.lock`) and automated static analysis.
* **$A_{19}$ — Web Crawler & Email Link Prefetching:** Automated anti-virus email scanners or browser prefetchers opening check-in links and accidentally invalidating single-use tokens.
  * *Defense:* Single-use check-in links render an anti-crawler confirmation UI upon `GET`. Token consumption is strictly enforced on `POST /checkin/consume`.
* **$A_{20}$ — Denial of Service via Check-In & API Flooding:** Malicious actors flooding check-in endpoints to trigger lockouts or crash the server.
  * *Defense:* In-memory sliding-window rate limiting with trusted proxy support, per-IP rate limits, and timing-safe comparison (`crypto.timingSafeEqual`).

---

## 3. Trust Boundaries: What obold Protects vs What It Does Not

| Scenario | Protected by obold? | Architectural Mechanism |
| :--- | :---: | :--- |
| **Daemon or host crash mid-delivery** | **YES** | Boot-time WAL ledger crash replay & at-least-once retry queue. |
| **Physical disk theft / backup leak** | **YES** | ChaCha20-Poly1305 authenticated encryption of all stored secrets. |
| **Single trustee betrayal (Shamir)** | **YES** | Threshold cryptography ($k$-of-$n$) prevents individual trustees from reconstructing secrets. |
| **Single delivery channel outage** | **YES** | Multi-channel sharding and progressive stage escalation. |
| **Coerced check-in** | **YES (Signaling)** | Covert distress alert dispatched upon Duress PIN entry. |
| **Email scanner prefetch invalidation** | **YES** | Anti-crawler confirmation page with POST-only consumption. |
| **Host root compromise** | **NO** | Root user can inspect process memory and modify binaries. |
| **Physical host destruction without offsite backup** | **NO** | If the host hardware is obliterated, the local daemon cannot execute. Offsite redundancy or offline-capable rescue bundles must be distributed in advance. |
| **Plaintext email eavesdropping** | **NO** | SMTP provides hop-by-hop transport encryption, not end-to-end encryption. Use GPG or Shamir sharding for sensitive payloads. |

---

## 4. Coercion Threat Model: Duress PIN Protocol & Assumptions

The Duress PIN feature is designed for **emergency signaling**, not absolute physical shielding:

### How It Works
1. Under normal operation, the operator inputs their standard check-in command or token.
2. If coerced, the operator inputs their configured Duress PIN instead.
3. The daemon outputs a standard successful check-in message to deceive on-site observers.
4. Concurrently, the engine marks a high-priority duress event in the audit ledger and silently fires configured distress beacons (e.g. discreet Signal/Ntfy notices to trusted contacts).

### Operational Assumptions & Warnings
* **Adversary Network Monitoring:** If an adversary is actively sniffing local network packets or firewall egress traffic during the coerced check-in, they may observe outbound HTTPS/API traffic to emergency endpoints.
* **Device Seizure:** If the adversary seizes the unlocked device and inspects the daemon log or configuration file, the duress alert will be visible unless the configuration is stored in encrypted environment variables (`${OBOLD_DURESS_PIN}`).
* **Operator Guidance:** Never store duress alerts in predictable public channels (like a shared Discord channel). Route duress alerts to discreet, encrypted personal channels.

---

## 5. Deployment Hardening Checklist

To achieve optimal security posture with `obold`:

1. **Run as a Dedicated Non-Root User:** Execute the daemon under an isolated system account (`obold` or `daemon`) with restricted filesystem permissions.
2. **Protect Master Key Material:** Set file permissions `chmod 600 .obold.key` and restrict read access.
3. **Use Environment Variables for Credentials:** Reference tokens and passwords via recursive expansion (`${ENV_VAR}`) rather than embedding raw text in `obold.yaml`.
4. **Deploy Redundant Delivery Channels:** Combine at least two distinct communication protocols (e.g. Signal + SMTP + S3) across different providers to avoid single-vendor outages.
5. **Generate Offline Emergency Rescue Vaults:** Create self-contained `rescue.html` vaults for non-technical family members and distribute threshold shares to separate trustees in advance.
6. **Periodically Run `obold doctor`:** Verify database integrity, cipher roundtrips, and service connectivity on a regular operational schedule.
