use std::time::SystemTime;
use totp_rs::{Algorithm, Secret, TOTP};

pub fn generate_code(secret_str: &str) -> Option<String> {
    let secret_bytes = Secret::Encoded(secret_str.to_string()).to_bytes().ok()?;

    if secret_bytes.len() < 16 {
        return None;
    }

    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes) {
        Ok(t) => t,
        Err(_) => return None,
    };

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
