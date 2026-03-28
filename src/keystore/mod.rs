use crate::error::JanusError;

/// Abstraction for group secret key storage backends.
///
/// Implementations determine where and how group private keys are persisted.
/// Note: a successful `save` does NOT guarantee that a subsequent `load` will
/// return the saved data — `NullStore` intentionally discards data.
pub trait KeyStore {
    /// Stores a group's secret key data.
    fn save(&self, group_name: &str, key_data: &[u8]) -> Result<(), JanusError>;

    /// Retrieves a group's secret key data.
    /// Returns `Ok(Some(...))` if cached, `Ok(None)` if not found (triggers bundle fallback).
    fn load(&self, group_name: &str) -> Result<Option<Vec<u8>>, JanusError>;

    /// Removes a group's secret key data.
    fn delete(&self, group_name: &str) -> Result<(), JanusError>;
}

/// A no-op store that never persists keys. Used on non-macOS platforms,
/// causing every decryption to fall back to bundle decryption via SSH key.
pub struct NullStore;

impl KeyStore for NullStore {
    fn save(&self, _group_name: &str, _key_data: &[u8]) -> Result<(), JanusError> {
        Ok(())
    }

    fn load(&self, _group_name: &str) -> Result<Option<Vec<u8>>, JanusError> {
        Ok(None)
    }

    fn delete(&self, _group_name: &str) -> Result<(), JanusError> {
        Ok(())
    }
}

/// In-memory store for testing. Avoids filesystem side effects.
#[cfg(test)]
pub struct MemoryStore {
    store: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

#[cfg(test)]
impl MemoryStore {
    pub fn new() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(test)]
impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl KeyStore for MemoryStore {
    fn save(&self, group_name: &str, key_data: &[u8]) -> Result<(), JanusError> {
        self.store
            .lock()
            .unwrap()
            .insert(group_name.to_string(), key_data.to_vec());
        Ok(())
    }

    fn load(&self, group_name: &str) -> Result<Option<Vec<u8>>, JanusError> {
        Ok(self.store.lock().unwrap().get(group_name).cloned())
    }

    fn delete(&self, group_name: &str) -> Result<(), JanusError> {
        self.store.lock().unwrap().remove(group_name);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub mod keychain;

/// Returns the platform-appropriate default key store.
pub fn default_keystore() -> Box<dyn KeyStore> {
    #[cfg(target_os = "macos")]
    {
        Box::new(keychain::KeychainStore)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Box::new(NullStore)
    }
}
