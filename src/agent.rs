use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use crate::crypto;
use crate::storage::Vault;

pub fn get_socket_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };

    // 1. Prefer /run/user/<uid> (standard Linux with systemd)
    let xdg = PathBuf::from(format!("/run/user/{}", uid));
    if xdg.exists() {
        return xdg.join("safelocked.sock");
    }

    // 2. Fallback to /tmp (available on most Unix systems)
    let tmp = PathBuf::from("/tmp");
    if tmp.exists() {
        return tmp.join(format!("safelocked-{}.sock", uid));
    }

    // 3. Last resort: home directory (Termux and minimal environments)
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".safelocked.sock")
}

pub fn is_agent_running() -> bool {
    get_socket_path().exists()
}

/// Sends a command to the running agent and returns the response.
fn send_command(command: &str) -> Option<String> {
    let mut stream = UnixStream::connect(get_socket_path()).ok()?;
    writeln!(stream, "{}", command).ok()?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).ok()?;
    Some(response.trim().to_string())
}

/// Asks the agent for the master key.
pub fn get_master_key() -> Option<[u8; 32]> {
    let response = send_command("GET_KEY")?;
    if let Some(key_hex) = response.strip_prefix("OK ") {
        let key_vec = hex::decode(key_hex).ok()?;
        key_vec.try_into().ok()
    } else {
        None
    }
}

/// Tells the agent to shut down.
pub fn stop_agent() {
    let _ = send_command("LOCK");
}

/// Starts the agent in background, storing the master key in memory.
pub fn start_agent(key: [u8; 32]) {
    // Fork: the child becomes the agent, the parent returns immediately.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => {
            eprintln!("Error: Failed to fork agent process.");
        }
        0 => {
            // Child process — run the agent loop.
            run_agent(key);
            std::process::exit(0);
        }
        _ => {
            // Parent process — wait briefly to ensure socket is ready.
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

fn run_agent(key: [u8; 32]) {
    let socket_path = get_socket_path();

    // Clean up any leftover socket.
    let _ = fs::remove_file(&socket_path);

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Agent error: could not bind socket: {}", e);
            return;
        }
    };

    // Restrict socket permissions to owner only (600).
    let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if !handle_connection(stream, &key) {
                    break; // LOCK command received — shut down.
                }
            }
            Err(_) => break,
        }
    }

    let _ = fs::remove_file(&socket_path);
}

/// Returns false if the agent should stop.
fn handle_connection(stream: UnixStream, key: &[u8; 32]) -> bool {
    let mut reader = BufReader::new(&stream);
    let mut writer = &stream;
    let mut command = String::new();

    if reader.read_line(&mut command).is_err() {
        return true;
    }

    match command.trim() {
        "GET_KEY" => {
            let response = format!("OK {}\n", hex::encode(key));
            let _ = writer.write_all(response.as_bytes());
            true
        }
        "LOCK" => {
            let _ = writer.write_all(b"OK\n");
            false
        }
        _ => {
            let _ = writer.write_all(b"ERR unknown command\n");
            true
        }
    }
}

/// Decrypts the vault using the key from the agent.
pub fn load_vault(key: &[u8; 32]) -> Option<Vault> {
    let data = Vault::load_from_disk().ok()?;
    let decrypted = crypto::decrypt(&data[16..], key)?;
    Some(Vault::deserialize(&decrypted))
}

/// Encrypts and saves the vault using the key from the agent.
pub fn save_vault(vault: &Vault, key: &[u8; 32]) {
    let encrypted = crypto::encrypt(&vault.serialize(), key);
    let mut final_data = vault.salt.to_vec();
    final_data.extend(encrypted);
    vault.save_to_disk(&final_data).expect("Failed to save vault");
}

