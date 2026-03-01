use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TwoFactorItem {
    pub name: String,
    pub secret: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub salt: [u8; 16],
    pub items: Vec<TwoFactorItem>,
}

impl Vault {
    pub fn new(salt: [u8; 16]) -> Self {
        Self {
            salt,
            items: Vec::new(),
        }
    }

    pub fn get_path() -> PathBuf {
        let mut path = dirs::home_dir().expect("Could not find home directory");
        path.push(".safelocked.vault");
        path
    }

    pub fn save_to_disk(&self, encrypted_data: &[u8]) -> std::io::Result<()> {
        let path = Self::get_path();
        fs::write(path, encrypted_data)
    }

    pub fn load_from_disk() -> std::io::Result<Vec<u8>> {
        let path = Self::get_path();
        fs::read(path)
    }

    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize vault")
    }

    pub fn deserialize(data: &[u8]) -> Self {
        serde_json::from_slice(data).expect("Failed to deserialize vault")
    }
}

