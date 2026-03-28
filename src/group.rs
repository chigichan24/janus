use std::fs;
use std::io::Write;
use std::path::Path;

use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::error::JanusError;

const JANUS_DIR: &str = ".janus";
const GROUPS_DIR: &str = "groups";
const META_FILE: &str = "meta.toml";
const BUNDLE_FILE: &str = "bundle.age";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub members: Vec<String>,
    pub public_key: String,
    #[serde(default)]
    pub created_at: Option<u64>,
}

fn validate_group_name(name: &str) -> Result<(), JanusError> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(JanusError::Config(format!(
            "invalid group name: '{name}' (only ASCII alphanumeric, '-', and '_' are allowed)"
        )));
    }
    Ok(())
}

fn dedup_members(members: &[String]) -> Vec<String> {
    members
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn groups_dir(repo_root: &Path, name: &str) -> std::path::PathBuf {
    repo_root.join(JANUS_DIR).join(GROUPS_DIR).join(name)
}

fn home_dir() -> Result<std::path::PathBuf, JanusError> {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .map_err(|_| JanusError::Config("HOME environment variable is not set".into()))
}

fn local_identity_dir() -> Result<std::path::PathBuf, JanusError> {
    Ok(home_dir()?.join(".config").join("janus").join("identities"))
}

fn local_identity_path(name: &str) -> Result<std::path::PathBuf, JanusError> {
    Ok(local_identity_dir()?.join(format!("{name}.key")))
}

#[cfg(unix)]
fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), JanusError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), JanusError> {
    fs::write(path, data)?;
    Ok(())
}

fn save_local_identity(name: &str, key_data: &[u8]) -> Result<(), JanusError> {
    let id_dir = local_identity_dir()?;
    fs::create_dir_all(&id_dir)?;
    write_secret_file(&local_identity_path(name)?, key_data)
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_group_atomically(
    name: &str,
    group: &Group,
    bundle: &[u8],
    repo_root: &Path,
) -> Result<(), JanusError> {
    let dir = groups_dir(repo_root, name);
    let tmp_dir = dir.with_extension("tmp");
    let backup_dir = dir.with_extension("bak");

    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir)?;
    }
    fs::create_dir_all(&tmp_dir)?;

    fs::write(
        tmp_dir.join(META_FILE),
        toml::to_string_pretty(group).map_err(|e| JanusError::Config(e.to_string()))?,
    )?;
    fs::write(tmp_dir.join(BUNDLE_FILE), bundle)?;

    if dir.exists() {
        fs::rename(&dir, &backup_dir)?;
    }
    if let Err(e) = fs::rename(&tmp_dir, &dir) {
        if backup_dir.exists() {
            if let Err(restore_err) = fs::rename(&backup_dir, &dir) {
                eprintln!("warning: failed to restore backup for group: {restore_err}");
            }
        }
        return Err(e.into());
    }
    if backup_dir.exists() {
        let _ = fs::remove_dir_all(&backup_dir);
    }

    Ok(())
}

fn generate_and_distribute_key(
    name: &str,
    members: Vec<String>,
    recipients: &[age::ssh::Recipient],
    repo_root: &Path,
) -> Result<Group, JanusError> {
    let identity = age::x25519::Identity::generate();
    let public_key = identity.to_public().to_string();
    let secret_key = identity.to_string();
    let secret_key_str = secret_key.expose_secret();

    let bundle = crate::encrypt::encrypt(recipients, secret_key_str.as_bytes())?;

    let group = Group {
        name: name.to_string(),
        members,
        public_key,
        created_at: Some(epoch_secs()),
    };

    write_group_atomically(name, &group, &bundle, repo_root)?;

    if let Err(e) = save_local_identity(name, secret_key_str.as_bytes()) {
        eprintln!(
            "warning: group created but local key save failed ({e}); \
             run `janus group import {name}` to recover"
        );
    }

    Ok(group)
}

/// Creates a new group with a shared key, encrypting it for all members' GitHub SSH keys.
pub fn create(name: &str, members: &[String], repo_root: &Path) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let members = dedup_members(members);
    let recipients = crate::github::fetch_all_recipients(&members)?;
    generate_and_distribute_key(name, members, &recipients, repo_root)
}

/// Creates a new group with pre-fetched SSH recipients, bypassing GitHub API calls.
pub fn create_with_recipients(
    name: &str,
    members: &[String],
    recipients: &[age::ssh::Recipient],
    repo_root: &Path,
) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let members = dedup_members(members);
    generate_and_distribute_key(name, members, recipients, repo_root)
}

/// Imports a group's shared key by decrypting the bundle with the user's SSH private key.
pub fn import(name: &str, identity_path: &Path, repo_root: &Path) -> Result<(), JanusError> {
    validate_group_name(name)?;
    let bundle_path = groups_dir(repo_root, name).join(BUNDLE_FILE);
    let ciphertext = fs::read(&bundle_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => JanusError::GroupNotFound(name.to_string()),
        _ => e.into(),
    })?;
    let secret_key_bytes = crate::decrypt::decrypt(identity_path, &ciphertext)?;
    save_local_identity(name, &secret_key_bytes)
}

/// Loads group metadata from the repository.
pub fn load(name: &str, repo_root: &Path) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let meta_path = groups_dir(repo_root, name).join(META_FILE);
    let content = fs::read_to_string(&meta_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => JanusError::GroupNotFound(name.to_string()),
        _ => e.into(),
    })?;

    let mut group =
        toml::from_str::<Group>(&content).map_err(|e| JanusError::Config(e.to_string()))?;

    if group.name != name {
        return Err(JanusError::Config(format!(
            "group directory name '{name}' does not match metadata name '{}'",
            group.name
        )));
    }

    group.members = dedup_members(&group.members);
    Ok(group)
}

/// Lists all groups in the repository.
pub fn list(repo_root: &Path) -> Result<Vec<Group>, JanusError> {
    let groups_path = repo_root.join(JANUS_DIR).join(GROUPS_DIR);
    let entries = match fs::read_dir(&groups_path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let mut groups = Vec::new();
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir() && entry.path().join(META_FILE).exists() {
            let name = entry.file_name().to_string_lossy().to_string();
            match load(&name, repo_root) {
                Ok(group) => groups.push(group),
                Err(e) => eprintln!("warning: failed to load group '{name}': {e}"),
            }
        }
    }
    Ok(groups)
}

/// Rotates the group key with a new member list, generating a fresh keypair.
pub fn rotate(name: &str, members: &[String], repo_root: &Path) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let meta_path = groups_dir(repo_root, name).join(META_FILE);
    if fs::metadata(&meta_path).is_err() {
        return Err(JanusError::GroupNotFound(name.to_string()));
    }
    let members = dedup_members(members);
    let recipients = crate::github::fetch_all_recipients(&members)?;
    generate_and_distribute_key(name, members, &recipients, repo_root)
}

/// Encrypts plaintext using a group's public key.
pub fn encrypt_for_group(group: &Group, plaintext: &[u8]) -> Result<Vec<u8>, JanusError> {
    let recipient: age::x25519::Recipient = group
        .public_key
        .parse()
        .map_err(|e: &str| JanusError::Encrypt(e.to_string()))?;
    crate::encrypt::encrypt_for_recipients(
        std::iter::once(&recipient as &dyn age::Recipient),
        plaintext,
    )
}

/// Decrypts ciphertext using a group's locally stored private key.
pub fn decrypt_with_group(group_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JanusError> {
    validate_group_name(group_name)?;
    let key_path = local_identity_path(group_name)?;
    let secret_key_str = fs::read_to_string(&key_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => JanusError::GroupKeyNotImported(group_name.to_string()),
        _ => JanusError::IdentityRead {
            path: key_path.clone(),
            source: e,
        },
    })?;
    let identity: age::x25519::Identity = secret_key_str
        .trim()
        .parse()
        .map_err(|e: &str| JanusError::Decrypt(e.to_string()))?;

    crate::decrypt::decrypt_with_identity(&identity, ciphertext)
}
