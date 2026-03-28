use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::JanusError;

/// Group metadata stored in `.janus/groups/<name>/meta.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub members: Vec<String>,
    pub public_key: String,
    pub created_at: String,
}

/// Creates a new group with a shared key, encrypted for all members.
pub fn create(_name: &str, _members: &[String], _repo_root: &Path) -> Result<Group, JanusError> {
    todo!()
}

/// Imports (decrypts) a group's shared key using the user's SSH private key.
pub fn import(_name: &str, _identity_path: &Path, _repo_root: &Path) -> Result<(), JanusError> {
    todo!()
}

/// Loads group metadata from the repository.
pub fn load(_name: &str, _repo_root: &Path) -> Result<Group, JanusError> {
    todo!()
}

/// Rotates the group key with a new member list.
pub fn rotate(_name: &str, _members: &[String], _repo_root: &Path) -> Result<Group, JanusError> {
    todo!()
}

/// Encrypts plaintext using a group's public key.
pub fn encrypt_for_group(_group: &Group, _plaintext: &[u8]) -> Result<Vec<u8>, JanusError> {
    todo!()
}

/// Decrypts ciphertext using a group's locally stored private key.
pub fn decrypt_with_group(_group_name: &str, _ciphertext: &[u8]) -> Result<Vec<u8>, JanusError> {
    todo!()
}
