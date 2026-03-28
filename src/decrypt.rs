use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::error::JanusError;

/// Decrypts age-encrypted data using an SSH private key file.
pub fn decrypt(identity_path: &Path, ciphertext: &[u8]) -> Result<Vec<u8>, JanusError> {
    let file = File::open(identity_path).map_err(|e| JanusError::IdentityRead {
        path: identity_path.to_path_buf(),
        source: e,
    })?;
    let reader = BufReader::new(file);

    let filename = identity_path.to_string_lossy().into_owned();
    let identity = age::ssh::Identity::from_buffer(reader, Some(filename))
        .map_err(|e| JanusError::KeyParse(e.to_string()))?;

    match &identity {
        age::ssh::Identity::Encrypted(_) => {
            return Err(JanusError::Decrypt(
                "encrypted SSH key is not supported; use an unencrypted key".to_string(),
            ));
        }
        age::ssh::Identity::Unsupported(k) => {
            return Err(JanusError::Decrypt(format!(
                "unsupported SSH key type: {k:?}"
            )));
        }
        age::ssh::Identity::Unencrypted(_) => {}
    }

    let armored_reader = age::armor::ArmoredReader::new(ciphertext);
    let decryptor = age::Decryptor::new_buffered(armored_reader)
        .map_err(|e| JanusError::Decrypt(e.to_string()))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| JanusError::Decrypt(e.to_string()))?;

    let mut plaintext = vec![];
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| JanusError::Decrypt(e.to_string()))?;

    Ok(plaintext)
}
