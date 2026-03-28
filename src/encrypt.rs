use crate::error::JanusError;

/// Encrypts plaintext to multiple SSH recipients in age binary format.
pub fn encrypt(
    _recipients: &[age::ssh::Recipient],
    _plaintext: &[u8],
) -> Result<Vec<u8>, JanusError> {
    todo!()
}

/// Encrypts plaintext to multiple SSH recipients in age ASCII-armored format.
pub fn encrypt_armor(
    _recipients: &[age::ssh::Recipient],
    _plaintext: &[u8],
) -> Result<String, JanusError> {
    todo!()
}
