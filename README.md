# SafeLocked

![CI](https://github.com/matheusc457/SafeLocked/actions/workflows/ci.yml/badge.svg)

SafeLocked is a secure and minimal TOTP (2FA) CLI manager for Linux, written in Rust.

The project follows a local-first security model. Authentication secrets are encrypted at rest and are only accessible during active agent sessions. SafeLocked works fully offline and avoids cloud dependency by design.

---

## Features

- AES-256-GCM encryption for vault protection
- Argon2id key derivation
- Background agent keeps the master key in memory only
- Agent session persists until explicit `lock` command
- Socket stored in RAM-backed directory (`/run/user/<uid>`, `/tmp`, or `$HOME`)
- No decrypted secrets written to disk
- Fully offline operation

---

## Installation

### Requirements

- Linux or Termux (Android)
- Rust and Cargo

### Build

```bash
git clone https://github.com/matheusc457/SafeLocked
cd SafeLocked
cargo build --release
```

### Install

```bash
sudo cp target/release/safelocked /usr/local/bin/
sudo chmod +x /usr/local/bin/safelocked
```

Verify installation:

```bash
safelocked --help
```

---

## Usage

Initialize vault:

```bash
safelocked init
```

Unlock vault (starts the background agent):

```bash
safelocked unlock
```

Check if vault is unlocked:

```bash
safelocked status
```

Add a service:

```bash
safelocked add Google
```

> The TOTP secret is entered interactively and never exposed in the shell history.

List active codes:

```bash
safelocked list
```

Filter by name:

```bash
safelocked list Google
```

Watch a code in real time:

```bash
safelocked watch Google
```

Rename a service:

```bash
safelocked rename Google Gmail
```

Remove a service:

```bash
safelocked remove Google
```

Lock vault:

```bash
safelocked lock
```

Delete vault and stop agent:

```bash
safelocked purge
```

---

## Security

SafeLocked follows RFC 6238 for TOTP generation.

Vault data remains encrypted at rest. When unlocked, the master key is held exclusively in the memory of a background agent process and is never written to disk. The agent communicates via a Unix socket with strict owner-only permissions (`600`). Locking the vault terminates the agent and the key is gone from memory immediately.

---

## License

This project is licensed under the MIT License.

