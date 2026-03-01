# SafeLocked 🔐

A secure, minimal, and user-friendly 2FA/TOTP CLI manager for Linux, built with Rust.

## Features
- **AES-256-GCM Encryption**: Industrial-grade protection for your seeds.
- **Argon2id Key Derivation**: High resistance against brute-force attacks.
- **Session Management**: Unlock your vault once and access codes for a custom duration (stored in RAM only).
- **Modern CLI**: Colored output, formatted tables, and intuitive commands.
- **Zero Disk Traces**: Session keys are stored in `/dev/shm` and auto-expire.

## Installation

### 1. Build from source
Requires [Rust](https://www.rust-lang.org) and Cargo.

git clone https://github.com/matheusc457/SafeLocked  
cd SafeLocked  
cargo build --release

### 2. Install to PATH
To run `safelocked` from anywhere in your terminal, move the binary to your local bin:

sudo cp target/release/safelocked /usr/local/bin/  
sudo chmod +x /usr/local/bin/safelocked

## Usage Guide

1. **Initialize**: Create your master vault.
   safelocked init

2. **Unlock**: Access your vault for a specific time (e.g., 5 minutes).
   safelocked unlock --timeout 300

3. **Add Service**: Save a new 2FA seed.  
   safelocked add Google JBSWY3DPEHPK3PXP

4. **List/Get**: View your active codes.  
   safelocked list            # Show all codes  
   safelocked list google     # Filter by name

5. **Management**:  
   safelocked remove Google # Delete a specific service  
   safelocked lock            # Immediate lock  
   safelocked purge           # Delete everything (vault + sessions)

## Security
This tool follows RFC 6238 (TOTP). It uses a session-based approach where the derived key is temporarily stored in a RAM-backed filesystem (`/dev/shm`), ensuring that even if your PC is powered off, the session key vanishes.
