# LockBox

![CI](https://github.com/matheusc457/LockBox/actions/workflows/ci.yml/badge.svg)

> Secure and minimal TOTP (2FA) CLI manager for Linux, written in Rust.

LockBox follows a local-first security model. Authentication secrets are encrypted at rest and only accessible during active agent sessions. Works fully offline with no cloud dependency.

> **Note:** This project is currently in maintenance mode. No new features are planned for now. Pull requests are welcome and appreciated — if you have an idea, feel free to open one!

---

## Features

- AES-256-GCM encryption for vault protection
- Argon2id key derivation with 32-byte salt
- Background agent keeps the master key in memory only
- Agent session persists until explicit `lock` command
- No decrypted secrets ever written to disk
- TOTP secrets never exposed in shell history
- Copy TOTP code directly to clipboard — clears automatically in 30 seconds
- Watch all codes updating in real time with `watch --all`
- Encrypted backup and restore via `export` and `import`
- Supports any TOTP secret format used in practice
- X11 and Wayland support
- Fully offline operation

---

## Installation

### Requirements

- Linux
- Rust and Cargo

### Build from source

```bash
git clone https://github.com/matheusc457/LockBox
cd LockBox
cargo build --release
sudo cp target/release/lockbox /usr/local/bin/
```

Verify:

```bash
lockbox --help
```

---

## Usage

```bash
lockbox init                    # Initialize a new vault
lockbox unlock                  # Unlock and start background agent
lockbox status                  # Check if vault is unlocked
lockbox add Google              # Add a new service (secret entered interactively)
lockbox list                    # List all TOTP codes
lockbox list Google             # Filter by name
lockbox watch Google            # Watch a code update in real time
lockbox watch --all             # Watch all codes update in real time
lockbox copy Google             # Copy code to clipboard (clears in 30s)
lockbox edit Google             # Edit the secret of an existing service
lockbox rename Google Gmail     # Rename a service
lockbox remove Google           # Remove a service
lockbox sort                    # Sort all services alphabetically
lockbox export ~/backup         # Export vault (encrypted or plain JSON)
lockbox import                  # Import from backup
lockbox lock                    # Lock vault and stop agent
lockbox purge                   # Delete vault permanently
```

> Run `lockbox <command> --help` for detailed information about any command.

---

## Security

LockBox uses multiple layers of protection:

**AES-256-GCM** encrypts the vault file on disk. Without the correct key the file is unreadable. The GCM tag also detects any tampering.

**Argon2id** derives the encryption key from your master password. Intentionally slow and memory-intensive, making brute force impractical even with powerful hardware.

**32-byte random salt** ensures two users with the same password produce completely different keys, eliminating precomputed dictionary attacks.

**Background agent** holds the master key exclusively in RAM. Never written to disk. Destroyed immediately when you run `lock`.

**Unix socket with 600 permissions** restricts agent access to your user only.

**Vault file with 600 permissions** ensures the encrypted file is only readable by your user.

**Interactive secret prompt** prevents TOTP secrets from appearing in shell history or system logs.

**Clipboard auto-clear** removes copied codes from the clipboard after 30 seconds.

### Threat model

LockBox is designed for personal use on a trusted device. All protections hold as long as your user session is not compromised. If an attacker gains active access to your user session, all secrets accessible in that session are at risk — this is true of any local password or 2FA manager.

---

## Contributing

This project is currently in maintenance mode and is not actively receiving new features. However, contributions are welcome and appreciated!

If you have a bug fix, improvement or new idea:

1. Fork the repository
2. Create a branch (`git checkout -b feat/my-feature`)
3. Run `cargo fmt` and `cargo clippy` before committing
4. Make sure all tests pass: `cargo test`
5. Open a Pull Request — it will be reviewed with care

---

## License

This project is licensed under the MIT License.

---

<p align="center">Made with ❤️ by <a href="https://github.com/matheusc457">Matheus</a></p>

