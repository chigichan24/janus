use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum JanusError {
    #[error("failed to fetch SSH keys for GitHub user '{username}'")]
    KeyFetch {
        username: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("no SSH keys found for GitHub user '{0}'")]
    NoKeysFound(String),

    #[error("failed to parse SSH public key: {0}")]
    KeyParse(String),

    #[error("encryption failed: {0}")]
    Encrypt(String),

    #[error("decryption failed: {0}")]
    Decrypt(String),

    #[error("failed to read identity file '{path}'")]
    IdentityRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("group '{0}' not found")]
    GroupNotFound(String),

    #[error("group key for '{0}' not imported — run `janus group import {0}` first")]
    GroupKeyNotImported(String),

    #[error("keychain error: {message}")]
    Keychain {
        message: String,
        kind: KeychainErrorKind,
    },

    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),
}

/// Distinguishes keychain failure modes for fallback decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainErrorKind {
    /// Touch ID or password authentication was denied by the user.
    AuthenticationDenied,
    /// Keychain access is not allowed (headless / CI environment).
    AccessDenied,
    /// Binary is not code-signed with required entitlements.
    MissingEntitlement,
    /// Any other keychain operation failure.
    Other,
}
