mod agent;
mod crypto;
mod storage;
mod totp;

use clap::{Parser, Subcommand};
use clipboard::{ClipboardContext, ClipboardProvider};
use colored::*;
use std::io::{self, Write};
use std::path::PathBuf;
use std::{thread, time::Duration};
use storage::{TwoFactorItem, Vault};

#[derive(Parser)]
#[command(name = "lockbox")]
#[command(author = "Matheus <://github.com>")]
#[command(version = "1.5")]
#[command(
    about = "Secure 2FA/TOTP manager for Linux terminal",
    long_about = "LockBox protects your seeds with AES-256-GCM. \nUse 'unlock' to access your codes."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new encrypted vault
    ///
    /// Creates a vault protected by a master password.
    /// Example: lockbox init
    Init,

    /// Unlock the vault and start the background agent
    ///
    /// The key stays in memory until you run 'lock'.
    /// Works across all terminal sessions.
    /// Example: lockbox unlock
    Unlock,

    /// Lock the vault and stop the background agent
    ///
    /// Terminates the agent and removes the key from memory immediately.
    /// Example: lockbox lock
    Lock,

    /// Show whether the vault is currently unlocked
    ///
    /// Example: lockbox status
    Status,

    /// Add a new TOTP service to the vault
    ///
    /// The secret is entered interactively and never exposed in the shell history.
    /// Example: lockbox add Google
    Add {
        /// Name of the service (e.g. Google, GitHub, AWS)
        name: String,
    },

    /// List all TOTP codes or filter by name
    ///
    /// Displays service name, current code and time remaining.
    /// Examples: lockbox list / lockbox list Google
    List {
        /// Optional filter to search by service name
        name: Option<String>,
    },

    /// Rename an existing service
    ///
    /// Example: lockbox rename Google Gmail
    Rename {
        /// Current name of the service
        name: String,
        /// New name for the service
        new_name: String,
    },

    /// Remove a service from the vault
    ///
    /// Example: lockbox remove Google
    Remove {
        /// Name of the service to remove
        name: String,
    },

    /// Watch a TOTP code update in real time
    ///
    /// Press Ctrl+C to exit.
    /// Example: lockbox watch Google
    Watch {
        /// Name of the service to watch
        name: String,
    },

    /// Export the vault to a backup file
    ///
    /// Choose between encrypted (.slbackup) or plain JSON.
    /// Encrypted backups use the same password as your vault.
    /// Example: lockbox export ~/backup
    Export {
        /// Destination path for the backup file (without extension)
        path: PathBuf,
    },

    /// Import services from a backup file
    ///
    /// Supports .slbackup and .json formats.
    /// You will be prompted for the directory and file name.
    /// Existing services with the same name are skipped automatically.
    /// Example: lockbox import
    Import,

    /// Copy a TOTP code to the clipboard
    ///
    /// The clipboard is automatically cleared after 30 seconds.
    /// Example: lockbox copy Google
    Copy {
        /// Name of the service to copy the code from
        name: String,
    },

    /// Delete the vault and stop the agent permanently
    ///
    /// This action is irreversible. Make sure you have a backup first.
    /// Example: lockbox purge
    Purge,
}

fn print_locked_msg() {
    println!("{} Vault is locked.", "Error:".red().bold());
    println!("   Run: {}", "lockbox unlock".cyan());
}

fn get_key_or_exit() -> Option<[u8; 32]> {
    match agent::get_master_key() {
        Some(k) => Some(k),
        None => {
            print_locked_msg();
            None
        }
    }
}

fn load_vault_or_exit(key: &[u8; 32]) -> Option<storage::Vault> {
    match agent::load_vault(key) {
        Some(v) => Some(v),
        None => {
            println!(
                "{}",
                "Error: Vault is corrupted or could not be read."
                    .red()
                    .bold()
            );
            None
        }
    }
}

fn format_code(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            if Vault::get_path().exists() {
                println!("{}", "Error: Vault already exists.".red().bold());
                return;
            }
            let password = rpassword::prompt_password("Create Master Password: ").unwrap();
            let confirm = rpassword::prompt_password("Confirm Master Password: ").unwrap();
            if password != confirm {
                println!("{}", "Error: Passwords do not match.".red().bold());
                return;
            }
            let mut salt = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            let vault = Vault::new(salt);
            let key = crypto::derive_key(&password, &salt);
            let encrypted = crypto::encrypt(&vault.serialize(), &key);
            let mut final_data = salt.to_vec();
            final_data.extend(encrypted);
            vault
                .save_to_disk(&final_data)
                .expect("Failed to write to disk");
            println!("\n{}", "Vault initialized!".green().bold());
        }

        Commands::Unlock => {
            if agent::is_agent_running() {
                println!("{}", "Vault is already unlocked.".yellow());
                return;
            }
            let data = match Vault::load_from_disk() {
                Ok(d) => d,
                Err(_) => {
                    println!(
                        "{}",
                        "Error: Vault not found. Run 'lockbox init' first."
                            .red()
                            .bold()
                    );
                    return;
                }
            };
            let password = rpassword::prompt_password("Master Password: ").unwrap();
            let salt: [u8; 32] = data[0..32].try_into().unwrap();
            let key = crypto::derive_key(&password, &salt);
            if crypto::decrypt(&data[32..], &key).is_some() {
                agent::start_agent(key);
                println!("{}", "Vault unlocked.".green().bold());
            } else {
                println!("{}", "Error: Invalid password.".red().bold());
            }
        }

        Commands::Lock => {
            if !agent::is_agent_running() {
                println!("{}", "Vault is already locked.".yellow());
                return;
            }
            agent::stop_agent();
            println!("{}", "Vault locked.".yellow().bold());
        }

        Commands::Status => {
            if agent::is_agent_running() {
                println!("{}", "Vault is unlocked.".green().bold());
            } else {
                println!("{}", "Vault is locked.".yellow().bold());
            }
        }

        Commands::Add { name } => {
            let key = match get_key_or_exit() {
                Some(k) => k,
                None => return,
            };
            let mut vault = match load_vault_or_exit(&key) {
                Some(v) => v,
                None => return,
            };
            if vault
                .items
                .iter()
                .any(|i| i.name.to_lowercase() == name.to_lowercase())
            {
                println!(
                    "{} Service '{}' already exists.",
                    "Error:".red().bold(),
                    name.cyan()
                );
                return;
            }
            let secret =
                rpassword::prompt_password(format!("Enter TOTP secret for '{}': ", name)).unwrap();
            if secret.trim().is_empty() {
                println!("{}", "Error: Secret cannot be empty.".red().bold());
                return;
            }
            vault.items.push(TwoFactorItem {
                name: name.clone(),
                secret: secret.trim().to_string(),
            });
            agent::save_vault(&vault, &key);
            println!(
                "{} Service '{}' added.",
                "Success:".green().bold(),
                name.cyan().bold()
            );
        }

        Commands::List { name } => {
            let key = match get_key_or_exit() {
                Some(k) => k,
                None => return,
            };
            let vault = match load_vault_or_exit(&key) {
                Some(v) => v,
                None => return,
            };
            let items_to_show: Vec<TwoFactorItem> = match name {
                Some(n) => vault
                    .items
                    .into_iter()
                    .filter(|i| i.name.to_lowercase().contains(&n.to_lowercase()))
                    .collect(),
                None => vault.items,
            };
            if items_to_show.is_empty() {
                println!("{}", "No services found.".yellow());
                return;
            }
            println!(
                "\n{:<20} {:<10} {:<10}",
                "SERVICE".bold(),
                "CODE".bold(),
                "EXPIRES".bold()
            );
            println!("{}", "-".repeat(45).blue());
            for item in items_to_show {
                let raw_code =
                    totp::generate_code(&item.secret).unwrap_or_else(|| "ERR".to_string());
                let code = format_code(&raw_code);
                let secs = totp::get_remaining_seconds();
                let time_color = if secs <= 7 {
                    secs.to_string().red()
                } else {
                    secs.to_string().green()
                };
                println!(
                    "{:<20} {:<10} {:<10}",
                    item.name.cyan(),
                    code.white().bold(),
                    format!("{}s", time_color)
                );
            }
        }

        Commands::Rename { name, new_name } => {
            let key = match get_key_or_exit() {
                Some(k) => k,
                None => return,
            };
            let mut vault = match load_vault_or_exit(&key) {
                Some(v) => v,
                None => return,
            };
            if vault
                .items
                .iter()
                .any(|i| i.name.to_lowercase() == new_name.to_lowercase())
            {
                println!(
                    "{} Service '{}' already exists.",
                    "Error:".red().bold(),
                    new_name.cyan()
                );
                return;
            }
            if let Some(item) = vault
                .items
                .iter_mut()
                .find(|i| i.name.to_lowercase() == name.to_lowercase())
            {
                item.name = new_name.clone();
                agent::save_vault(&vault, &key);
                println!(
                    "{} '{}' renamed to '{}'.",
                    "Success:".green().bold(),
                    name.cyan().bold(),
                    new_name.cyan().bold()
                );
            } else {
                println!(
                    "{} Service '{}' not found.",
                    "Error:".red().bold(),
                    name.cyan()
                );
            }
        }

        Commands::Remove { name } => {
            let key = match get_key_or_exit() {
                Some(k) => k,
                None => return,
            };
            let mut vault = match load_vault_or_exit(&key) {
                Some(v) => v,
                None => return,
            };
            let original_len = vault.items.len();
            vault
                .items
                .retain(|i| i.name.to_lowercase() != name.to_lowercase());
            if vault.items.len() < original_len {
                agent::save_vault(&vault, &key);
                println!(
                    "{} Service '{}' removed.",
                    "Success:".green().bold(),
                    name.cyan().bold()
                );
            } else {
                println!(
                    "{} Service '{}' not found.",
                    "Error:".red().bold(),
                    name.cyan()
                );
            }
        }

        Commands::Watch { name } => {
            let key = match get_key_or_exit() {
                Some(k) => k,
                None => return,
            };
            println!("Watching {} (Ctrl+C to exit)...", name.cyan().bold());
            loop {
                if !agent::is_agent_running() {
                    println!("\n{}", "Vault locked. Exiting watch.".red().bold());
                    break;
                }
                let vault = match agent::load_vault(&key) {
                    Some(v) => v,
                    None => break,
                };
                if let Some(item) = vault
                    .items
                    .iter()
                    .find(|i| i.name.to_lowercase() == name.to_lowercase())
                {
                    let raw_code = totp::generate_code(&item.secret).unwrap_or_default();
                    let code = format_code(&raw_code);
                    let secs = totp::get_remaining_seconds();
                    let time_color = if secs <= 7 {
                        secs.to_string().red()
                    } else {
                        secs.to_string().green()
                    };
                    print!(
                        "\rService: {:<15} Code: {:<10} Time: {:<5}s\x1B[K",
                        item.name.cyan(),
                        code.white().bold(),
                        time_color
                    );
                    io::stdout().flush().unwrap();
                } else {
                    println!(
                        "\n{} Service '{}' not found.",
                        "Error:".red().bold(),
                        name.cyan()
                    );
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            }
        }

        Commands::Export { path } => {
            let key = match get_key_or_exit() {
                Some(k) => k,
                None => return,
            };
            let vault = match load_vault_or_exit(&key) {
                Some(v) => v,
                None => return,
            };

            println!("Export format:");
            println!(
                "  [1] {} (recommended)",
                "Encrypted .slbackup".green().bold()
            );
            println!("  [2] {}", "Plain JSON".red().bold());
            print!("Choose: ");
            io::stdout().flush().unwrap();
            let mut choice = String::new();
            io::stdin().read_line(&mut choice).unwrap();

            match choice.trim() {
                "1" => {
                    let export_path = path.with_extension("slbackup");
                    let json = vault.serialize();
                    let encrypted = crypto::encrypt(&json, &key);
                    if let Err(e) = std::fs::write(&export_path, &encrypted) {
                        println!("{} Could not write file: {}", "Error:".red().bold(), e);
                        return;
                    }
                    println!(
                        "{} Backup saved to '{}'.",
                        "Success:".green().bold(),
                        export_path.display().to_string().cyan()
                    );
                }
                "2" => {
                    println!();
                    println!("{}", "WARNING".red().bold());
                    println!("{}", "=".repeat(50).red());
                    println!(
                        "{}",
                        "  This will export ALL your TOTP secrets as".red().bold()
                    );
                    println!(
                        "{}",
                        "  PLAIN TEXT. Anyone with this file will have".red().bold()
                    );
                    println!("{}", "  FULL ACCESS to all your 2FA accounts.".red().bold());
                    println!("{}", "=".repeat(50).red());
                    println!();
                    print!("Type {} to confirm: ", "I UNDERSTAND THE RISK".red().bold());
                    io::stdout().flush().unwrap();
                    let mut confirm = String::new();
                    io::stdin().read_line(&mut confirm).unwrap();
                    if confirm.trim() != "I UNDERSTAND THE RISK" {
                        println!("{}", "Aborted.".yellow());
                        return;
                    }
                    let export_path = path.with_extension("json");
                    if let Err(e) = std::fs::write(&export_path, vault.serialize()) {
                        println!("{} Could not write file: {}", "Error:".red().bold(), e);
                        return;
                    }
                    println!(
                        "{} Plain JSON saved to '{}'. Keep it safe!",
                        "Success:".green().bold(),
                        export_path.display().to_string().cyan()
                    );
                }
                _ => {
                    println!("{}", "Error: Invalid choice.".red().bold());
                }
            }
        }

        Commands::Import => {
            let key = match get_key_or_exit() {
                Some(k) => k,
                None => return,
            };
            let mut vault = match load_vault_or_exit(&key) {
                Some(v) => v,
                None => return,
            };

            print!("Enter directory path: ");
            io::stdout().flush().unwrap();
            let mut dir_input = String::new();
            io::stdin().read_line(&mut dir_input).unwrap();
            let dir = PathBuf::from(dir_input.trim());

            if !dir.exists() {
                println!(
                    "{} Directory '{}' not found.",
                    "Error:".red().bold(),
                    dir.display().to_string().cyan()
                );
                return;
            }
            if !dir.is_dir() {
                println!("{}", "Error: Path is not a directory.".red().bold());
                return;
            }

            print!("Enter file name (without extension): ");
            io::stdout().flush().unwrap();
            let mut name_input = String::new();
            io::stdin().read_line(&mut name_input).unwrap();
            let file_stem = name_input.trim();

            let slbackup_path = dir.join(format!("{}.slbackup", file_stem));
            let json_path = dir.join(format!("{}.json", file_stem));

            let (data, is_encrypted) = if slbackup_path.exists() {
                match std::fs::read(&slbackup_path) {
                    Ok(d) => (d, true),
                    Err(_) => {
                        println!("{}", "Error: Failed to read file.".red().bold());
                        return;
                    }
                }
            } else if json_path.exists() {
                match std::fs::read(&json_path) {
                    Ok(d) => (d, false),
                    Err(_) => {
                        println!("{}", "Error: Failed to read file.".red().bold());
                        return;
                    }
                }
            } else {
                println!(
                    "{} No file named '{}' found (.slbackup or .json).",
                    "Error:".red().bold(),
                    file_stem.cyan()
                );
                return;
            };

            let import_vault = if is_encrypted {
                let decrypted = match crypto::decrypt(&data, &key) {
                    Some(d) => d,
                    None => {
                        println!(
                            "{}",
                            "Error: Failed to decrypt backup. Wrong vault password?"
                                .red()
                                .bold()
                        );
                        return;
                    }
                };
                match Vault::deserialize(&decrypted) {
                    Some(v) => v,
                    None => {
                        println!("{}", "Error: Backup file is corrupted.".red().bold());
                        return;
                    }
                }
            } else {
                match Vault::deserialize(&data) {
                    Some(v) => v,
                    None => {
                        println!("{}", "Error: Invalid JSON backup file.".red().bold());
                        return;
                    }
                }
            };

            let mut added = 0;
            let mut skipped = 0;
            for item in import_vault.items {
                if vault
                    .items
                    .iter()
                    .any(|i| i.name.to_lowercase() == item.name.to_lowercase())
                {
                    println!(
                        "  {} Skipped '{}' (already exists).",
                        "~".yellow(),
                        item.name.cyan()
                    );
                    skipped += 1;
                } else {
                    println!("  {} Imported '{}'.", "+".green().bold(), item.name.cyan());
                    vault.items.push(item);
                    added += 1;
                }
            }

            agent::save_vault(&vault, &key);
            println!();
            println!(
                "{} Import complete: {} added, {} skipped.",
                "Success:".green().bold(),
                added.to_string().green(),
                skipped.to_string().yellow()
            );
        }

        Commands::Copy { name } => {
            let key = match get_key_or_exit() {
                Some(k) => k,
                None => return,
            };
            let vault = match load_vault_or_exit(&key) {
                Some(v) => v,
                None => return,
            };
            if let Some(item) = vault
                .items
                .iter()
                .find(|i| i.name.to_lowercase() == name.to_lowercase())
            {
                let raw_code = totp::generate_code(&item.secret).unwrap_or_default();
                let code = format_code(&raw_code);
                let plain_code = raw_code.clone();
                let mut ctx: ClipboardContext = match ClipboardProvider::new() {
                    Ok(c) => c,
                    Err(_) => {
                        println!("{} Could not access clipboard.", "Error:".red().bold());
                        return;
                    }
                };
                if ctx.set_contents(plain_code).is_err() {
                    println!("{} Failed to copy to clipboard.", "Error:".red().bold());
                    return;
                }
                println!(
                    "{} Code {} for '{}' copied to clipboard. Clears automatically in 30 seconds.",
                    "Success:".green().bold(),
                    code.white().bold(),
                    item.name.cyan()
                );
                thread::spawn(move || {
                    thread::sleep(Duration::from_secs(30));
                    if let Ok(mut ctx) = ClipboardContext::new() {
                        let _ = ctx.set_contents(String::new());
                    }
                });
            } else {
                println!(
                    "{} Service '{}' not found.",
                    "Error:".red().bold(),
                    name.cyan()
                );
            }
        }

        Commands::Purge => {
            print!("Purge everything? (y/N): ");
            io::stdout().flush().unwrap();
            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm).unwrap();
            if confirm.trim().to_lowercase() == "y" {
                agent::stop_agent();
                let _ = std::fs::remove_file(Vault::get_path());
                println!("{}", "Purged successfully.".green().bold());
            } else {
                println!("{}", "Aborted.".yellow());
            }
        }
    }
}
