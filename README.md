# SafeLocked

![CI](https://github.com/matheusc457/SafeLocked/actions/workflows/ci.yml/badge.svg)

SafeLocked is a secure and minimal TOTP (2FA) CLI manager for Linux, written in Rust.

The project follows a local-first security model. Authentication secrets are encrypted at rest and are only accessible during temporary in-memory sessions. SafeLocked works fully offline and avoids cloud dependency by design.

---

## Features

- AES-256-GCM encryption for vault protection  
- Argon2id key derivation  
- Time-limited unlock sessions  
- Default unlock session: **60 seconds**  
- Session keys stored only in RAM (`/dev/shm`)  
- No decrypted secrets written to disk  
- Fully offline operation  

---

## Installation

### Requirements

- Linux
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

Unlock vault (default session: **60 seconds**):

```bash
safelocked unlock
```

Unlock with custom timeout:

```bash
safelocked unlock --timeout 300
```

Add a service:

```bash
safelocked add Google JBSWY3DPEHPK3PXP
```

List active codes:

```bash
safelocked list
```

Lock vault immediately:

```bash
safelocked lock
```

Remove a service:

```bash
safelocked remove Google
```

Delete vault and sessions:

```bash
safelocked purge
```

---

## Security

SafeLocked follows RFC 6238 for TOTP generation.

Vault data remains encrypted at rest and secrets are decrypted only during active sessions. Session keys exist exclusively in volatile memory and are automatically destroyed after expiration, system shutdown, or manual lock.

---

## License

This project is licensed under the MIT License.
