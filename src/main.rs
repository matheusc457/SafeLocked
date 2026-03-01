mod crypto;
mod storage;
mod totp;

use chrono::Utc;
use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::{thread, time::Duration};
use storage::{TwoFactorItem, Vault};

#[derive(Parser)]
#[command(name = "safelocked")]
#[command(author = "Matheus <://github.com>")]
#[command(version = "1.5")]
#[command(
    about = "Secure 2FA/TOTP manager for Linux terminal",
    long_about = "SafeLocked protects your seeds with AES-256-GCM. \nUse 'unlock' to access your codes."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Unlock {
        #[arg(short, long, default_value_t = 60)]
        timeout: i64,
    },
    Lock,
    Add {
        name: String,
    },
    List {
        name: Option<String>,
    },
    Remove {
        name: String,
    },
    Watch {
        name: String,
    },
    Purge,
}

fn get_session_path() -> PathBuf {
    PathBuf::from("/dev/shm/.safelocked.session")
}

fn get_master_key() -> Option<[u8; 32]> {
    let path = get_session_path();
    let data = fs::read_to_string(path).ok()?;
    let parts: Vec<&str> = data.split('|').collect();
    if parts.len() != 2 {
        return None;
    }
    let expiry = parts[1].parse::<i64>().ok()?;
    if Utc::now().timestamp() > expiry {
        let _ = fs::remove_file(get_session_path());
        return None;
    }
    let key_vec = hex::decode(parts[0]).ok()?;
    key_vec.try_into().ok()
}

fn print_locked_msg() {
    println!("{} Vault is locked.", "Error:".red().bold());
    println!("   Run: 'safelocked unlock --timeout <seconds>'");
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            if Vault::get_path().exists() {
                println!("{}", "Error: Vault already exists.".yellow());
                return;
            }
            let password = rpassword::prompt_password("Create Master Password: ").unwrap();
            let confirm = rpassword::prompt_password("Confirm Master Password: ").unwrap();
            if password != confirm {
                println!("{}", "Error: Passwords do not match.".red().bold());
                return;
            }
            let mut salt = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            let vault = Vault::new(salt);
            let key = crypto::derive_key(&password, &salt);
            let encrypted = crypto::encrypt(&vault.serialize(), &key);
            let mut final_data = salt.to_vec();
            final_data.extend(encrypted);
            vault
                .save_to_disk(&final_data)
                .expect("Failed to write to disk");
            println!("\n{}", "Success: Vault initialized!".green().bold());
        }

        Commands::Unlock { timeout } => {
            let data = match Vault::load_from_disk() {
                Ok(d) => d,
                Err(_) => {
                    println!("Error: Vault file not found.");
                    return;
                }
            };
            let password = rpassword::prompt_password("Enter Master Password: ").unwrap();
            let salt: [u8; 16] = data[0..16].try_into().unwrap();
            let key = crypto::derive_key(&password, &salt);
            if crypto::decrypt(&data[16..], &key).is_some() {
                let expiry = Utc::now().timestamp() + timeout;
                let session_data = format!("{}|{}", hex::encode(key), expiry);
                fs::write(get_session_path(), session_data).expect("Failed to create session");
                println!("\n{} for {}s.", "Vault Unlocked".green().bold(), timeout);
            } else {
                println!("\n{}", "Error: Invalid password.".red().bold());
            }
        }

        Commands::Lock => {
            let _ = fs::remove_file(get_session_path());
            println!("{}", "Vault locked.".yellow());
        }

        Commands::Add { name } => {
            let key = match get_master_key() {
                Some(k) => k,
                None => {
                    print_locked_msg();
                    return;
                }
            };
            let secret = rpassword::prompt_password(format!("Enter TOTP secret for '{}': ", name))
                .unwrap();
            if secret.trim().is_empty() {
                println!("{}", "Error: Secret cannot be empty.".red().bold());
                return;
            }
            let data = Vault::load_from_disk().unwrap();
            let mut vault = Vault::deserialize(&crypto::decrypt(&data[16..], &key).unwrap());
            vault.items.push(TwoFactorItem {
                name: name.clone(),
                secret: secret.trim().to_string(),
            });
            let encrypted = crypto::encrypt(&vault.serialize(), &key);
            let mut final_data = vault.salt.to_vec();
            final_data.extend(encrypted);
            vault.save_to_disk(&final_data).unwrap();
            println!("Service '{}' added.", name.cyan().bold());
        }

        Commands::List { name } => {
            let key = match get_master_key() {
                Some(k) => k,
                None => {
                    print_locked_msg();
                    return;
                }
            };
            let data = Vault::load_from_disk().unwrap();
            let vault =
                Vault::deserialize(&crypto::decrypt(&data[16..], &key).expect("Decryption failed"));
            println!(
                "\n{:<20} {:<10} {:<10}",
                "SERVICE".bold(),
                "CODE".bold(),
                "EXPIRES".bold()
            );
            println!("{}", "-".repeat(45).blue());
            let items_to_show: Vec<TwoFactorItem> = match name {
                Some(n) => vault
                    .items
                    .into_iter()
                    .filter(|i| i.name.to_lowercase().contains(&n.to_lowercase()))
                    .collect(),
                None => vault.items,
            };
            for item in items_to_show {
                let code = totp::generate_code(&item.secret).unwrap_or_else(|| "ERR".to_string());
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

        Commands::Watch { name } => {
            let key = match get_master_key() {
                Some(k) => k,
                None => {
                    print_locked_msg();
                    return;
                }
            };
            println!(
                "Starting Live Watch for {} (Ctrl+C to exit)...",
                name.cyan().bold()
            );
            loop {
                if get_master_key().is_none() {
                    println!("\n{}", "Session expired. Vault locked.".red());
                    break;
                }
                let data = Vault::load_from_disk().unwrap();
                let vault = Vault::deserialize(&crypto::decrypt(&data[16..], &key).unwrap());

                if let Some(item) = vault
                    .items
                    .iter()
                    .find(|i| i.name.to_lowercase() == name.to_lowercase())
                {
                    let code = totp::generate_code(&item.secret).unwrap_or_default();
                    let secs = totp::get_remaining_seconds();
                    let time_color = if secs <= 7 {
                        secs.to_string().red()
                    } else {
                        secs.to_string().green()
                    };

                    // O segredo aqui é o \x1B[K para limpar o resto da linha
                    print!(
                        "\rService: {:<15} Code: {:<10} Time: {:<5}s\x1B[K",
                        item.name.cyan(),
                        code.white().bold(),
                        time_color
                    );
                    io::stdout().flush().unwrap();
                } else {
                    println!("\nService '{}' not found.", name.yellow());
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            }
        }

        Commands::Remove { name } => {
            let key = match get_master_key() {
                Some(k) => k,
                None => {
                    print_locked_msg();
                    return;
                }
            };
            let data = Vault::load_from_disk().unwrap();
            let mut vault = Vault::deserialize(&crypto::decrypt(&data[16..], &key).unwrap());
            let original_len = vault.items.len();
            vault
                .items
                .retain(|i| i.name.to_lowercase() != name.to_lowercase());
            if vault.items.len() < original_len {
                let encrypted = crypto::encrypt(&vault.serialize(), &key);
                let mut final_data = vault.salt.to_vec();
                final_data.extend(encrypted);
                vault.save_to_disk(&final_data).unwrap();
                println!("Service '{}' removed.", name.cyan().bold());
            }
        }

        Commands::Purge => {
            print!("Purge everything? (y/N): ");
            io::stdout().flush().unwrap();
            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm).unwrap();
            if confirm.trim().to_lowercase() == "y" {
                let _ = fs::remove_file(Vault::get_path());
                let _ = fs::remove_file(get_session_path());
                println!("Success: Purged.");
            }
        }
    }
}
