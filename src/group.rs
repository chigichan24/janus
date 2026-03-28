use std::fs;
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::error::JanusError;
use crate::keystore::KeyStore;

const JANUS_DIR: &str = ".janus";
const GROUPS_DIR: &str = "groups";
const META_FILE: &str = "meta.toml";
const BUNDLE_FILE: &str = "bundle.age";

/// Group metadata stored in `.janus/groups/<name>/meta.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub members: Vec<String>,
    pub public_key: String,
    #[serde(default)]
    pub created_at: Option<u64>,
}

/// Holds shared context for group operations: repository root, SSH identity
/// for bundle fallback, and the key storage backend.
pub struct GroupContext {
    pub repo_root: PathBuf,
    pub identity_path: PathBuf,
    pub keystore: Box<dyn KeyStore>,
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

fn groups_dir(repo_root: &Path, name: &str) -> PathBuf {
    repo_root.join(JANUS_DIR).join(GROUPS_DIR).join(name)
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

/// Resolves a group's secret key: tries the keystore first, falls back to
/// decrypting the bundle with the SSH identity, caching the result.
fn resolve_group_key(
    group_name: &str,
    ctx: &GroupContext,
) -> Result<age::x25519::Identity, JanusError> {
    // Try keystore cache first
    match ctx.keystore.load(group_name) {
        Ok(Some(key_data)) => return parse_group_identity(&key_data),
        Ok(None) => {} // Not cached, fall through to bundle
        Err(JanusError::Keychain { ref kind, .. })
            if *kind == crate::error::KeychainErrorKind::AuthenticationDenied =>
        {
            eprintln!("warning: keychain authentication denied, falling back to bundle");
        }
        Err(JanusError::Keychain { ref kind, .. })
            if *kind == crate::error::KeychainErrorKind::MissingEntitlement =>
        {
            eprintln!(
                "warning: code signing required for keychain access; \
                 see README for setup. Falling back to bundle"
            );
        }
        Err(e) => return Err(e),
    }

    // Fallback: decrypt from bundle
    let bundle_path = groups_dir(&ctx.repo_root, group_name).join(BUNDLE_FILE);
    let ciphertext = fs::read(&bundle_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => JanusError::GroupKeyNotImported(group_name.to_string()),
        _ => e.into(),
    })?;
    let key_data = crate::decrypt::decrypt(&ctx.identity_path, &ciphertext)?;

    // Cache for next time (no-op for NullStore)
    if let Err(e) = ctx.keystore.save(group_name, &key_data) {
        eprintln!("warning: failed to cache group key ({e})");
    }

    parse_group_identity(&key_data)
}

fn parse_group_identity(key_data: &[u8]) -> Result<age::x25519::Identity, JanusError> {
    let s = std::str::from_utf8(key_data).map_err(|e| JanusError::Decrypt(e.to_string()))?;
    s.trim()
        .parse()
        .map_err(|e: &str| JanusError::Decrypt(e.to_string()))
}

fn generate_and_distribute_key(
    name: &str,
    members: Vec<String>,
    recipients: &[age::ssh::Recipient],
    ctx: &GroupContext,
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

    write_group_atomically(name, &group, &bundle, &ctx.repo_root)?;

    if let Err(e) = ctx.keystore.save(name, secret_key_str.as_bytes()) {
        eprintln!(
            "warning: group created but key cache failed ({e}); \
             run `janus group import {name}` to recover"
        );
    }

    Ok(group)
}

/// Creates a new group with a shared key, encrypting it for all members' GitHub SSH keys.
pub fn create(name: &str, members: &[String], ctx: &GroupContext) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let members = dedup_members(members);
    let recipients = crate::github::fetch_all_recipients(&members)?;
    generate_and_distribute_key(name, members, &recipients, ctx)
}

/// Creates a new group with pre-fetched SSH recipients, bypassing GitHub API calls.
pub fn create_with_recipients(
    name: &str,
    members: &[String],
    recipients: &[age::ssh::Recipient],
    ctx: &GroupContext,
) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let members = dedup_members(members);
    generate_and_distribute_key(name, members, recipients, ctx)
}

/// Imports a group's shared key by decrypting the bundle and storing it in the keystore.
pub fn import(name: &str, ctx: &GroupContext) -> Result<(), JanusError> {
    validate_group_name(name)?;
    let bundle_path = groups_dir(&ctx.repo_root, name).join(BUNDLE_FILE);
    let ciphertext = fs::read(&bundle_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => JanusError::GroupNotFound(name.to_string()),
        _ => e.into(),
    })?;
    let secret_key_bytes = crate::decrypt::decrypt(&ctx.identity_path, &ciphertext)?;
    ctx.keystore.save(name, &secret_key_bytes)
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
pub fn rotate(name: &str, members: &[String], ctx: &GroupContext) -> Result<Group, JanusError> {
    validate_group_name(name)?;
    let meta_path = groups_dir(&ctx.repo_root, name).join(META_FILE);
    if fs::metadata(&meta_path).is_err() {
        return Err(JanusError::GroupNotFound(name.to_string()));
    }
    let members = dedup_members(members);
    let recipients = crate::github::fetch_all_recipients(&members)?;
    generate_and_distribute_key(name, members, &recipients, ctx)
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

/// Decrypts ciphertext using a group's secret key resolved via the keystore or bundle fallback.
pub fn decrypt_with_group(
    group_name: &str,
    ciphertext: &[u8],
    ctx: &GroupContext,
) -> Result<Vec<u8>, JanusError> {
    validate_group_name(group_name)?;
    let identity = resolve_group_key(group_name, ctx)?;
    crate::decrypt::decrypt_with_identity(&identity, ciphertext)
}
