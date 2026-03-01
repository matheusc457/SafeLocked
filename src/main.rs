mod agent;
mod crypto;
mod storage;
mod totp;

use clap::{Parser, Subcommand};
use colored::*;
use std::io::{self, Write};
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
    Unlock,
    Lock,
    Status,
    Add { name: String },
    List { name: Option<String> },
    Remove { name: String },
    Watch { name: String },
    Purge,
}

fn print_locked_msg() {
    println!("{} Vault is locked.", "Error:".red().bold());
    println!("   Run: safelocked unlock");
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
                        "Error: Vault not found. Run 'safelocked init' first.".red()
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
            println!("{}", "Vault locked.".yellow());
        }

        Commands::Status => {
            if agent::is_agent_running() {
                println!("{}", "Vault is unlocked.".green());
            } else {
                println!("{}", "Vault is locked.".yellow());
            }
        }

        Commands::Add { name } => {
            let key = match agent::get_master_key() {
                Some(k) => k,
                None => {
                    print_locked_msg();
                    return;
                }
            };
            let secret =
                rpassword::prompt_password(format!("Enter TOTP secret for '{}': ", name)).unwrap();
            if secret.trim().is_empty() {
                println!("{}", "Error: Secret cannot be empty.".red().bold());
                return;
            }
            let mut vault = match agent::load_vault(&key) {
                Some(v) => v,
                None => {
                    println!(
                        "{}",
                        "Error: Vault is corrupted or could not be read."
                            .red()
                            .bold()
                    );
                    return;
                }
            };
            vault.items.push(TwoFactorItem {
                name: name.clone(),
                secret: secret.trim().to_string(),
            });
            agent::save_vault(&vault, &key);
            println!("Service '{}' added.", name.cyan().bold());
        }

        Commands::List { name } => {
            let key = match agent::get_master_key() {
                Some(k) => k,
                None => {
                    print_locked_msg();
                    return;
                }
            };
            let vault = match agent::load_vault(&key) {
                Some(v) => v,
                None => {
                    println!(
                        "{}",
                        "Error: Vault is corrupted or could not be read."
                            .red()
                            .bold()
                    );
                    return;
                }
            };
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
            if items_to_show.is_empty() {
                println!("{}", "No services found.".yellow());
                return;
            }
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
            let key = match agent::get_master_key() {
                Some(k) => k,
                None => {
                    print_locked_msg();
                    return;
                }
            };
            println!("Watching {} (Ctrl+C to exit)...", name.cyan().bold());
            loop {
                if !agent::is_agent_running() {
                    println!("\n{}", "Vault locked. Exiting watch.".red());
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
                    let code = totp::generate_code(&item.secret).unwrap_or_default();
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
                    println!("\nService '{}' not found.", name.yellow());
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            }
        }

        Commands::Remove { name } => {
            let key = match agent::get_master_key() {
                Some(k) => k,
                None => {
                    print_locked_msg();
                    return;
                }
            };
            let mut vault = match agent::load_vault(&key) {
                Some(v) => v,
                None => {
                    println!(
                        "{}",
                        "Error: Vault is corrupted or could not be read."
                            .red()
                            .bold()
                    );
                    return;
                }
            };
            let original_len = vault.items.len();
            vault
                .items
                .retain(|i| i.name.to_lowercase() != name.to_lowercase());
            if vault.items.len() < original_len {
                agent::save_vault(&vault, &key);
                println!("Service '{}' removed.", name.cyan().bold());
            } else {
                println!("Service '{}' not found.", name.yellow());
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
                println!("{}", "Purged.".green());
            }
        }
    }
}
