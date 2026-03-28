use std::fs;
use std::io::Write;
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
    pub created_at: Option<u64>,
}

fn validate_group_name(name: &str) -> Result<(), JanusError> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.contains('\0')
    {
        return Err(JanusError::Config(format!("invalid group name: {name}")));
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

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

    let dir = groups_dir(repo_root, name);
    let tmp_dir = dir.with_extension("tmp");
    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir)?;
    }
    fs::create_dir_all(&tmp_dir)?;

    fs::write(
        tmp_dir.join("meta.toml"),
        toml::to_string_pretty(&group).map_err(|e| JanusError::Config(e.to_string()))?,
    )?;
    fs::write(tmp_dir.join("bundle.age"), &bundle)?;

    let id_dir = local_identity_dir()?;
    fs::create_dir_all(&id_dir)?;
    write_secret_file(&local_identity_path(name)?, secret_key_str.as_bytes())?;

    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::rename(&tmp_dir, &dir)?;

    Ok(group)
}

pub fn create(name: &str, members: &[String], repo_root: &Path) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let members = dedup_members(members);
    let recipients = crate::github::fetch_all_recipients(&members)?;
    generate_and_distribute_key(name, members, &recipients, repo_root)
}

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

pub fn import(name: &str, identity_path: &Path, repo_root: &Path) -> Result<(), JanusError> {
    validate_group_name(name)?;
    let bundle_path = groups_dir(repo_root, name).join("bundle.age");
    if !bundle_path.exists() {
        return Err(JanusError::GroupNotFound(name.to_string()));
    }

    let ciphertext = fs::read(&bundle_path)?;
    let secret_key_bytes = crate::decrypt::decrypt(identity_path, &ciphertext)?;

    let id_dir = local_identity_dir()?;
    fs::create_dir_all(&id_dir)?;
    write_secret_file(&local_identity_path(name)?, &secret_key_bytes)?;

    Ok(())
}

pub fn load(name: &str, repo_root: &Path) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let meta_path = groups_dir(repo_root, name).join("meta.toml");
    if !meta_path.exists() {
        return Err(JanusError::GroupNotFound(name.to_string()));
    }

    let content = fs::read_to_string(&meta_path)?;
    toml::from_str::<Group>(&content).map_err(|e| JanusError::Config(e.to_string()))
}

pub fn list(repo_root: &Path) -> Result<Vec<Group>, JanusError> {
    let groups_path = repo_root.join(".janus").join("groups");
    if !groups_path.exists() {
        return Ok(vec![]);
    }
    let mut groups = Vec::new();
    for entry in fs::read_dir(&groups_path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() && entry.path().join("meta.toml").exists() {
            let name = entry.file_name().to_string_lossy().to_string();
            match load(&name, repo_root) {
                Ok(group) => groups.push(group),
                Err(e) => eprintln!("warning: failed to load group '{name}': {e}"),
            }
        }
    }
    Ok(groups)
}

pub fn rotate(name: &str, members: &[String], repo_root: &Path) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let dir = groups_dir(repo_root, name);
    if !dir.join("meta.toml").exists() {
        return Err(JanusError::GroupNotFound(name.to_string()));
    }
    let members = dedup_members(members);
    let recipients = crate::github::fetch_all_recipients(&members)?;
    generate_and_distribute_key(name, members, &recipients, repo_root)
}

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

pub fn decrypt_with_group(group_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JanusError> {
    validate_group_name(group_name)?;
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

    crate::decrypt::decrypt_with_identity(&identity, ciphertext)
}
