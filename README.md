# SafeLocked 🔐

A secure 2FA/TOTP CLI manager for Linux, built with Rust.

## Features
- **AES-256-GCM Encryption**: High-level encryption for your secrets.
- **Argon2id Key Derivation**: High resistance against brute-force attacks.
- **Linux Integration**: Stores data in `~/.safelocked.vault`.
- **Fast & Minimal**: Single binary, zero runtime dependencies.

## Installation
Requires Rust and Cargo.

git clone https://github.com
cd SafeLocked
cargo build --release

## Security
This tool follows RFC 6238 (TOTP) and uses the Argon2 password hashing algorithm to derive encryption keys from your master password.

