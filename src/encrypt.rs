use std::io::Write;

use age::Encryptor;
use age::armor::{ArmoredWriter, Format};

use crate::error::JanusError;

fn make_encryptor<'a>(
    recipients: impl Iterator<Item = &'a dyn age::Recipient>,
) -> Result<Encryptor, JanusError> {
    Encryptor::with_recipients(recipients).map_err(|e| JanusError::Encrypt(e.to_string()))
}

fn encrypt_to_writer<W: Write>(
    encryptor: Encryptor,
    plaintext: &[u8],
    sink: W,
) -> Result<W, JanusError> {
    let mut writer = encryptor
        .wrap_output(sink)
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| JanusError::Encrypt(e.to_string()))
}

/// Encrypts plaintext for an arbitrary set of age recipients in binary format.
pub fn encrypt_for_recipients<'a>(
    recipients: impl Iterator<Item = &'a dyn age::Recipient>,
    plaintext: &[u8],
) -> Result<Vec<u8>, JanusError> {
    let encryptor = make_encryptor(recipients)?;
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    encrypt_to_writer(encryptor, plaintext, &mut ciphertext)?;
    Ok(ciphertext)
}

/// Encrypts plaintext to multiple SSH recipients in age binary format.
pub fn encrypt(
    recipients: &[age::ssh::Recipient],
    plaintext: &[u8],
) -> Result<Vec<u8>, JanusError> {
    encrypt_for_recipients(
        recipients.iter().map(|r| r as &dyn age::Recipient),
        plaintext,
    )
}

/// Encrypts plaintext to multiple SSH recipients in age ASCII-armored format.
pub fn encrypt_armor(
    recipients: &[age::ssh::Recipient],
    plaintext: &[u8],
) -> Result<String, JanusError> {
    let encryptor = make_encryptor(recipients.iter().map(|r| r as &dyn age::Recipient))?;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let armored = ArmoredWriter::wrap_output(&mut ciphertext, Format::AsciiArmor)
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;
    encrypt_to_writer(encryptor, plaintext, armored)?
        .finish()
        .map_err(|e| JanusError::Encrypt(e.to_string()))?;

    String::from_utf8(ciphertext).map_err(|e| JanusError::Encrypt(e.to_string()))
}
