use totp_rs::{Algorithm, Secret, TOTP};
use std::time::SystemTime;

pub fn generate_code(secret_str: &str) -> Option<String> {
    let secret = Secret::Encoded(secret_str.to_string());
    
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().ok()?,
    ).ok()?;

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();

    Some(totp.generate(time))
}

pub fn get_remaining_seconds() -> u64 {
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    30 - (time % 30)
}

