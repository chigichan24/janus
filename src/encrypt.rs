use std::io::Write;

use age::Encryptor;
use age::armor::{ArmoredWriter, Format};

use crate::error::JanusError;

/// Encrypts plaintext to multiple SSH recipients in age binary format.
pub fn encrypt(
    recipients: &[age::ssh::Recipient],
    plaintext: &[u8],
) -> Result<Vec<u8>, JanusError> {
    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
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

/// Encrypts plaintext to multiple SSH recipients in age ASCII-armored format.
pub fn encrypt_armor(
    recipients: &[age::ssh::Recipient],
    plaintext: &[u8],
) -> Result<String, JanusError> {
    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let armored_writer = ArmoredWriter::wrap_output(&mut ciphertext, Format::AsciiArmor)
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;
    let mut writer = encryptor
        .wrap_output(armored_writer)
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| JanusError::Encrypt(e.to_string()))?
        .finish()
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;

    String::from_utf8(ciphertext).map_err(|e| JanusError::Encrypt(e.to_string()))
}
