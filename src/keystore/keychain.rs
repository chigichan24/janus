#![allow(dead_code, unused_imports)]

use crate::error::{JanusError, KeychainErrorKind};
use crate::keystore::KeyStore;

const SERVICE: &str = "com.janus.group-key";

/// macOS Keychain-backed key store with Touch ID protection.
pub struct KeychainStore;

impl KeyStore for KeychainStore {
    /// Stores a group key in macOS Keychain with Touch ID access control.
    fn save(&self, _group_name: &str, _key_data: &[u8]) -> Result<(), JanusError> {
        todo!("Keychain save — requires security-framework crate")
    }

    /// Retrieves a group key from macOS Keychain, triggering Touch ID if configured.
    fn load(&self, _group_name: &str) -> Result<Option<Vec<u8>>, JanusError> {
        todo!("Keychain load — requires security-framework crate")
    }

    /// Removes a group key from macOS Keychain.
    fn delete(&self, _group_name: &str) -> Result<(), JanusError> {
        todo!("Keychain delete — requires security-framework crate")
    }
}
