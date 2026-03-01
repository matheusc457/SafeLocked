pub use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use rand::RngCore;

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let salt_string = SaltString::encode_b64(salt).expect("Salt error");
    let argon2 = Argon2::default();
    
    if let Ok(password_hash) = argon2.hash_password(password.as_bytes(), &salt_string) {
        if let Some(hash_bytes) = password_hash.hash {
            key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        }
    }
    key
}

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .expect("Encrypt error");

    let mut encrypted_data = nonce_bytes.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);
    encrypted_data
}

pub fn decrypt(encrypted_data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if encrypted_data.len() < 12 {
        return None;
    }

    let cipher = Aes256Gcm::new(key.into());
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).ok()
}

