mod crypto;
mod storage;
mod totp;

use clap::{Parser, Subcommand};
use storage::{Vault, TwoFactorItem};
use chrono::Utc;
use rpassword::read_password;
use std::io::{self, Write};
use std::fs;
use std::path::PathBuf;
use colored::*;

#[derive(Parser)]
#[command(name = "safelocked")]
#[command(author = "Matheus <://github.com>")]
#[command(version = "1.0")]
#[command(about = "Secure 2FA/TOTP manager for Linux terminal", long_about = "SafeLocked protects your seeds with AES-256-GCM encryption. \nYou must unlock the vault to access codes for a chosen duration.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the secure vault (first time use)
    Init,
    /// Unlock the vault for a specific duration (default 60s)
    Unlock { 
        #[arg(short, long, default_value_t = 60, help = "Duration in seconds before auto-locking")]
        timeout: i64 
    },
    /// Lock the vault and clear the current session
    Lock,
    /// Add a new service (e.g., safelocked add Google SEED123)
    Add { name: String, secret: String },
    /// List all 2FA codes or filter by name (e.g., safelocked list google)
    List { name: Option<String> },
    /// Remove a specific service from the vault
    Remove { name: String },
    /// Delete the entire vault and all session data
    Purge,
}

fn get_session_path() -> PathBuf {
    PathBuf::from("/dev/shm/.safelocked.session")
}

fn get_master_key() -> Option<[u8; 32]> {
    let path = get_session_path();
    let data = fs::read_to_string(path).ok()?;
    let parts: Vec<&str> = data.split('|').collect();
    
    if parts.len() != 2 { return None; }
    
    let expiry = parts[1].parse::<i64>().ok()?;
    if Utc::now().timestamp() > expiry {
        let _ = fs::remove_file(get_session_path());
        return None;
    }

    let key_vec = hex::decode(parts[0]).ok()?;
    key_vec.try_into().ok()
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            if Vault::get_path().exists() {
                println!("{}", "Error: Vault already exists at ~/.safelocked.vault".yellow());
                return;
            }
            print!("Create Master Password: ");
            io::stdout().flush().unwrap();
            let password = read_password().unwrap();
            
            let mut salt = [0u8; 16];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
            let vault = Vault::new(salt);
            let key = crypto::derive_key(&password, &salt);
            let encrypted = crypto::encrypt(&vault.serialize(), &key);
            
            let mut final_data = salt.to_vec();
            final_data.extend(encrypted);
            vault.save_to_disk(&final_data).expect("Failed to write to disk");
            println!("\n{}", "Success: Vault initialized. Run 'safelocked unlock' to begin.".green().bold());
        }

        Commands::Unlock { timeout } => {
            let data = match Vault::load_from_disk() {
                Ok(d) => d,
                Err(_) => { 
                    println!("{} {}", "Error:".red().bold(), "Vault file not found. Run 'safelocked init'."); 
                    return; 
                }
            };

            print!("Enter Master Password: ");
            io::stdout().flush().unwrap();
            let password = read_password().unwrap();
            
            let salt: [u8; 16] = data[0..16].try_into().unwrap();
            let key = crypto::derive_key(&password, &salt);
            
            if crypto::decrypt(&data[16..], &key).is_some() {
                let expiry = Utc::now().timestamp() + timeout;
                let session_data = format!("{}|{}", hex::encode(key), expiry);
                fs::write(get_session_path(), session_data).expect("Failed to create session");
                println!("\n{} session will expire in {}s.", "Vault Unlocked".green().bold(), timeout);
            } else {
                println!("\n{}", "Error: Invalid password. Access denied.".red().bold());
            }
        }

        Commands::Lock => {
            let _ = fs::remove_file(get_session_path());
            println!("{}", "Vault locked and session cleared.".yellow());
        }

        Commands::Add { name, secret } => {
            let key = match get_master_key() {
                Some(k) => k,
                None => {
                    println!("{} {}", "Vault is locked.".red().bold(), "Please unlock first:");
                    println!("   safelocked unlock --timeout 60");
                    return;
                }
            };
            let data = Vault::load_from_disk().unwrap();
            let mut vault = Vault::deserialize(&crypto::decrypt(&data[16..], &key).unwrap());
            
            vault.items.push(TwoFactorItem { name: name.clone(), secret });
            let encrypted = crypto::encrypt(&vault.serialize(), &key);
            let mut final_data = vault.salt.to_vec();
            final_data.extend(encrypted);
            vault.save_to_disk(&final_data).unwrap();
            println!("Service '{}' added successfully.", name.cyan().bold());
        }

        Commands::List { name } => {
            let key = match get_master_key() {
                Some(k) => k,
                None => {
                    println!("{} {}", "Vault is locked.".red().bold(), "Unlock to view codes:");
                    println!("   safelocked unlock --timeout <seconds>");
                    return;
                }
            };

            let data = Vault::load_from_disk().unwrap();
            let vault = Vault::deserialize(&crypto::decrypt(&data[16..], &key).expect("Decryption failed"));
            
            println!("\n{:<20} {:<10} {:<10}", "SERVICE".bold(), "CODE".bold(), "EXPIRES".bold());
            println!("{}", "-".repeat(45).blue());

            let items_to_show: Vec<TwoFactorItem> = match name {
                Some(n) => vault.items.into_iter().filter(|i| i.name.to_lowercase().contains(&n.to_lowercase())).collect(),
                None => vault.items,
            };

            if items_to_show.is_empty() {
                println!("{}", "No services found.".yellow());
                return;
            }

            for item in items_to_show {
                let code = totp::generate_code(&item.secret).unwrap_or_else(|| "ERR".to_string());
                let secs = totp::get_remaining_seconds();
                let time_color = if secs <= 7 { secs.to_string().red() } else { secs.to_string().green() };
                println!("{:<20} {:<10} {:<10}", item.name.cyan(), code.white().bold(), format!("{}s", time_color));
            }
            println!("");
        }

        Commands::Remove { name } => {
            let key = match get_master_key() {
                Some(k) => k,
                None => {
                    println!("{} {}", "Vault is locked.".red().bold(), "Unlock to remove services.");
                    return;
                }
            };
            let data = Vault::load_from_disk().unwrap();
            let mut vault = Vault::deserialize(&crypto::decrypt(&data[16..], &key).unwrap());
            
            let original_len = vault.items.len();
            vault.items.retain(|i| i.name.to_lowercase() != name.to_lowercase());

            if vault.items.len() < original_len {
                let encrypted = crypto::encrypt(&vault.serialize(), &key);
                let mut final_data = vault.salt.to_vec();
                final_data.extend(encrypted);
                vault.save_to_disk(&final_data).unwrap();
                println!("Service '{}' removed.", name.cyan().bold());
            } else {
                println!("Service '{}' not found.", name.yellow());
            }
        }

        Commands::Purge => {
            print!("Are you sure you want to delete EVERYTHING? (y/N): ");
            io::stdout().flush().unwrap();
            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm).unwrap();
            
            if confirm.trim().to_lowercase() == "y" {
                let _ = fs::remove_file(Vault::get_path());
                let _ = fs::remove_file(get_session_path());
                println!("{}", "Success: Vault and sessions purged.".green().bold());
            } else {
                println!("Purge cancelled.");
            }
        }
    }
}

