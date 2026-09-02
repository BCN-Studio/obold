# 🪙 obold — Sovereign Emergency Continuity & Dead Man's Switch Daemon
### *A Source-Available Sovereign Standard by BCN Studio* · [https://obold.bcnstudio.tech](https://obold.bcnstudio.tech)

[![Version: Public Beta](https://img.shields.io/badge/Version-v1.0.0--beta-amber.svg)](https://github.com/BCN-Studio/obold)
[![License: BCN Sovereign](https://img.shields.io/badge/License-BCN%20Sovereign-emerald.svg)](LICENSE)
[![Runtime: Bun](https://img.shields.io/badge/Runtime-Bun-cyan.svg)](https://bun.sh)
[![Ledger: SQLite WAL](https://img.shields.io/badge/Storage-SQLite%20WAL-blue.svg)](https://sqlite.org)
[![Security: Audited](https://img.shields.io/badge/Security-Threat%20Model-purple.svg)](THREAT_MODEL.md)
[![Website: obold.bcnstudio.tech](https://img.shields.io/badge/Website-obold.bcnstudio.tech-purple.svg)](https://obold.bcnstudio.tech)

---

## 🧭 Project Identity & Purpose

* **Name:** `obold`
* **Etymology:** Derived from **Obol** (the coin historically given to pay the ferryman across the river Styx) paired with the standard Unix daemon suffix **-d**.
* **Purpose:** A local-first, self-hosted safety timer that durably delivers your critical files, credentials, or emergency messages if you ever stop checking in.

---

## ⚡ Core Capabilities

1. **Durable Atomic Execution Ledger:** Every action transitions through persistent states using SQLite Write-Ahead Logging (WAL). If a crash or power cut occurs mid-execution, `obold` recovers its queue state on restart with at-least-once intent delivery.
2. **Shamir's Secret Sharing ($k$-of-$n$):** Built-in Galois Field $\text{GF}(2^8)$ threshold cryptography to divide sensitive passphrases or seed phrases across trusted trustees.
3. **Offline-Capable Emergency Rescue Vaults:** Generates self-contained, offline HTML inheritance files with embedded WebCrypto decryptors that family members can open in any modern browser without installing tools.
4. **Dynamic Multi-Channel Sharding:** Splits secrets dynamically at trigger time and routes distinct shares through separate communication channels.
5. **Coercion & Duress Protocol:** If forced to check in under duress, entering a secret Duress PIN displays a normal success screen while silently dispatching covert distress beacons.
6. **Vacation & Maintenance Pause Mode:** Temporarily freeze countdowns during travel or server maintenance with automated resume timers.
7. **Emergency Cascade Abort:** Immediate manual operator abort to halt in-flight cascades and cancel unacknowledged execution retries.
8. **Master Key Rotation:** Zero-downtime re-encryption of all encrypted SQLite records using ChaCha20-Poly1305.
9. **Interactive Terminal TUI Monitor (`obold top`):** Headless terminal dashboard with live countdown gauges, status badges, and interactive keyboard shortcuts.
10. **24/7 Background Service Generators:** Automated generator for Linux `systemd` user/system units and macOS `launchd` plists.
11. **Single-Use Ephemeral Tokens:** 1-click check-in links using HMAC-SHA256 tokens with anti-crawler prefetch protection.

---

## 🚀 Quickstart

### 1. One-Line Install

```bash
curl -fsSL https://raw.githubusercontent.com/BCN-Studio/obold/main/install.sh | bash
```

Or clone and run locally:

```bash
git clone https://github.com/BCN-Studio/obold.git
cd obold
bun install
```

### 2. Initialize Configuration

```bash
bun run src/index.ts init --out ./obold.yaml
```

### 3. Start the Daemon & Web Dashboard

```bash
bun run src/index.ts run --config ./obold.yaml --port 8080
```

Open `http://localhost:8080` in your browser for the local real-time dashboard.

---

## 💻 CLI Commands

| Command | Description |
|---|---|
| `obold run` | Start the daemon watchdog, scheduler, and local web dashboard |
| `obold doctor` | Run comprehensive system environment, storage WAL, and cryptographic diagnostics |
| `obold update` | Check GitHub Releases, verify SHA256 checksum, and update obold |
| `obold top` / `obold monitor` | Launch the real-time interactive terminal TUI dashboard |
| `obold status` | Display live countdown timers, armed status, and switch states |
| `obold checkin <switch-id>` | Heartbeat check-in to extend countdown timer |
| `obold pause <switch-id> [flags]` | Suspend switch countdown (e.g. `--duration 14d --reason "Vacation"`) |
| `obold resume <switch-id>` | Resume active countdown for a paused switch |
| `obold abort <switch-id>` | Emergency abort to halt active cascade execution |
| `obold rekey` | Rotate master encryption key and re-encrypt SQLite records |
| `obold rescue generate` | Generate self-contained offline HTML recovery bundles for heirs |
| `obold rescue verify <file>` | Cryptographically inspect and verify offline rescue bundle integrity |
| `obold service install` | Install background service for Linux systemd or macOS launchd |
| `obold service uninstall` | Remove background service |
| `obold secret split` | Split sensitive text into $k$-of-$n$ Shamir shares |
| `obold secret combine <shares...>` | Reconstruct original secret from threshold Shamir shares |
| `obold token generate <switch-id>` | Generate signed single-use 1-click check-in URL |
| `obold trigger <switch-id> --dry-run` | Test trigger execution safely without side effects |
| `obold plugin list` | List all registered built-in and external plugins |
| `obold plugin new <name>` | Scaffold a new community plugin template |

---

## 🧩 Built-in Core Plugins

* **`core:signal`**: End-to-end encrypted private messages via signal-cli REST bridge.
* **`core:matrix`**: Cryptographically signed room notices with idempotency tokens.
* **`core:ntfy`**: High-priority real-time mobile and desktop push alerts.
* **`core:gotify`**: Self-hosted push notifications with priority ratings.
* **`core:shamir_distribute`**: Dynamic runtime secret splitting and multi-channel routing.
* **`core:email`**: Native RFC 5321/5322 SMTP client with STARTTLS/TLS and authentication.
* **`core:telegram`**: Telegram Bot API alerts with inline 1-tap check-in buttons.
* **`core:discord`**: Rich embedded channel notifications and emergency role mentions.
* **`core:webhook`**: Signed HTTP POST/GET dispatches with HMAC-SHA256 signatures and SSRF redirect defense.
* **`core:s3`**: Encrypted payload storage on AWS S3, Cloudflare R2, or MinIO via SigV4.
* **`core:gpg`**: Asymmetric file encryption and key management.
* **`core:nostr`**: Decentralized broadcast to public Nostr relays.
* **`core:shell`**: Host script execution, container management, and key erasure commands.

---

## 🛡️ Security & Threat Model

For full details on attacker vectors ($A_1 – A_{20}$), trust boundaries, duress signaling assumptions, and cryptographic guarantees, please read our [Threat Model (THREAT_MODEL.md)](THREAT_MODEL.md) and [Security Policy (SECURITY.md)](SECURITY.md).

---

## 📄 License

Licensed under the **BCN Studio Sovereign Non-Commercial Source-Available License (v1.0)**.
Free for private, local, and self-hosted personal usage, custom plugin development, and upstream contributions. Commercial hosting, SaaS reselling, and unauthorized public forks are prohibited. See [LICENSE](LICENSE) for terms.

Created with care by **BCN Studio** ([bcnstudio.tech](https://bcnstudio.tech)).
