use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::error::JanusError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub members: Vec<String>,
    pub public_key: String,
    #[serde(default)]
    pub created_at: String,
}

fn groups_dir(repo_root: &Path, name: &str) -> std::path::PathBuf {
    repo_root.join(".janus").join("groups").join(name)
}

fn local_identity_dir() -> Result<std::path::PathBuf, JanusError> {
    let home = std::env::var("HOME").map_err(|_| JanusError::Config("HOME not set".into()))?;
    Ok(std::path::PathBuf::from(home)
        .join(".config")
        .join("janus")
        .join("identities"))
}

fn local_identity_path(name: &str) -> Result<std::path::PathBuf, JanusError> {
    Ok(local_identity_dir()?.join(format!("{name}.key")))
}

pub fn create(name: &str, members: &[String], repo_root: &Path) -> Result<Group, JanusError> {
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let secret_key = identity.to_string();
    let secret_key_str = secret_key.expose_secret();

    let recipients = crate::github::fetch_all_recipients(members)?;
    let bundle = crate::encrypt::encrypt(&recipients, secret_key_str.as_bytes())?;

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let group = Group {
        name: name.to_string(),
        members: members.to_vec(),
        public_key,
        created_at: epoch.to_string(),
    };

    let dir = groups_dir(repo_root, name);
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join("meta.toml"),
        toml::to_string_pretty(&group).map_err(|e| JanusError::Config(e.to_string()))?,
    )?;
    fs::write(dir.join("bundle.age"), &bundle)?;

    let id_dir = local_identity_dir()?;
    fs::create_dir_all(&id_dir)?;
    fs::write(local_identity_path(name)?, secret_key_str.as_bytes())?;

    Ok(group)
}

pub fn import(name: &str, identity_path: &Path, repo_root: &Path) -> Result<(), JanusError> {
    let bundle_path = groups_dir(repo_root, name).join("bundle.age");
    if !bundle_path.exists() {
        return Err(JanusError::GroupNotFound(name.to_string()));
    }

    let ciphertext = fs::read(&bundle_path)?;
    let secret_key_bytes = crate::decrypt::decrypt(identity_path, &ciphertext)?;

    let id_dir = local_identity_dir()?;
    fs::create_dir_all(&id_dir)?;
    fs::write(local_identity_path(name)?, &secret_key_bytes)?;

    Ok(())
}

pub fn load(name: &str, repo_root: &Path) -> Result<Group, JanusError> {
    let meta_path = groups_dir(repo_root, name).join("meta.toml");
    if !meta_path.exists() {
        return Err(JanusError::GroupNotFound(name.to_string()));
    }

    let content = fs::read_to_string(&meta_path)?;
    toml::from_str::<Group>(&content).map_err(|e| JanusError::Config(e.to_string()))
}

pub fn rotate(name: &str, members: &[String], repo_root: &Path) -> Result<Group, JanusError> {
    let dir = groups_dir(repo_root, name);
    if !dir.join("meta.toml").exists() {
        return Err(JanusError::GroupNotFound(name.to_string()));
    }

    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let secret_key = identity.to_string();
    let secret_key_str = secret_key.expose_secret();

    let recipients = crate::github::fetch_all_recipients(members)?;
    let bundle = crate::encrypt::encrypt(&recipients, secret_key_str.as_bytes())?;

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let group = Group {
        name: name.to_string(),
        members: members.to_vec(),
        public_key,
        created_at: epoch.to_string(),
    };

    fs::write(
        dir.join("meta.toml"),
        toml::to_string_pretty(&group).map_err(|e| JanusError::Config(e.to_string()))?,
    )?;
    fs::write(dir.join("bundle.age"), &bundle)?;

    let id_dir = local_identity_dir()?;
    fs::create_dir_all(&id_dir)?;
    fs::write(local_identity_path(name)?, secret_key_str.as_bytes())?;

    Ok(group)
}

pub fn encrypt_for_group(group: &Group, plaintext: &[u8]) -> Result<Vec<u8>, JanusError> {
    let recipient: age::x25519::Recipient = group
        .public_key
        .parse()
        .map_err(|e: &str| JanusError::Encrypt(e.to_string()))?;

    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| JanusError::Encrypt(e.to_string()))?;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;

    Ok(ciphertext)
}

pub fn decrypt_with_group(group_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JanusError> {
    let key_path = local_identity_path(group_name)?;
    if !key_path.exists() {
        return Err(JanusError::GroupKeyNotImported(group_name.to_string()));
    }

    let secret_key_str =
        fs::read_to_string(&key_path).map_err(|e| JanusError::Decrypt(e.to_string()))?;
    let identity: age::x25519::Identity = secret_key_str
        .trim()
        .parse()
        .map_err(|e: &str| JanusError::Decrypt(e.to_string()))?;

    let decryptor =
        age::Decryptor::new_buffered(ciphertext).map_err(|e| JanusError::Decrypt(e.to_string()))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| JanusError::Decrypt(e.to_string()))?;

    let mut plaintext = vec![];
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| JanusError::Decrypt(e.to_string()))?;

    Ok(plaintext)
}
