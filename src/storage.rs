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
    pub salt: [u8; 32],
    pub items: Vec<TwoFactorItem>,
}

impl Vault {
    pub fn new(salt: [u8; 32]) -> Self {
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
        use std::os::unix::fs::PermissionsExt;
        let path = Self::get_path();
        fs::write(&path, encrypted_data)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    pub fn load_from_disk() -> std::io::Result<Vec<u8>> {
        let path = Self::get_path();
        fs::read(path)
    }

    pub fn serialize(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize vault")
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }
}
