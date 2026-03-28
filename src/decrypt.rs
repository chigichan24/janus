use std::path::Path;

use crate::error::JanusError;

/// Decrypts age-encrypted data using an SSH private key file.
pub fn decrypt(_identity_path: &Path, _ciphertext: &[u8]) -> Result<Vec<u8>, JanusError> {
    todo!()
}
