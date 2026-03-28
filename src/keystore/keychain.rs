use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password, generic_password,
    set_generic_password, set_generic_password_options,
};

use crate::error::{JanusError, KeychainErrorKind};
use crate::keystore::KeyStore;

const SERVICE: &str = "com.janus.group-key";
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// macOS Keychain-backed key store.
/// Attempts Touch ID protection first; falls back to basic Keychain if unsigned.
pub struct KeychainStore;

fn map_keychain_error(err: security_framework::base::Error) -> JanusError {
    let code = err.code();
    // errSecAuthFailed = -25293
    if code == -25293 {
        return JanusError::Keychain {
            message: "authentication denied".into(),
            kind: KeychainErrorKind::AuthenticationDenied,
        };
    }
    // errSecInteractionNotAllowed = -25308
    if code == -25308 {
        return JanusError::Keychain {
            message: "keychain access not allowed (headless environment?)".into(),
            kind: KeychainErrorKind::AccessDenied,
        };
    }
    if code == ERR_SEC_MISSING_ENTITLEMENT {
        return JanusError::Keychain {
            message: "missing code signing entitlement".into(),
            kind: KeychainErrorKind::MissingEntitlement,
        };
    }
    JanusError::Keychain {
        message: format!("keychain error (code {code}): {err}"),
        kind: KeychainErrorKind::Other,
    }
}

impl KeyStore for KeychainStore {
    /// Stores a group key in macOS Keychain.
    /// Tries Touch ID protection first, falls back to basic Keychain.
    fn save(&self, group_name: &str, key_data: &[u8]) -> Result<(), JanusError> {
        let _ = delete_generic_password(SERVICE, group_name);

        // Try with Touch ID first
        let mut options = PasswordOptions::new_generic_password(SERVICE, group_name);
        options.set_access_control_options(AccessControlOptions::USER_PRESENCE);
        match set_generic_password_options(key_data, options) {
            Ok(()) => return Ok(()),
            Err(err) if err.code() == ERR_SEC_MISSING_ENTITLEMENT => {
                // No code signing — fall back to basic Keychain (no Touch ID)
            }
            Err(err) => return Err(map_keychain_error(err)),
        }

        set_generic_password(SERVICE, group_name, key_data).map_err(map_keychain_error)
    }

    /// Retrieves a group key from macOS Keychain.
    fn load(&self, group_name: &str) -> Result<Option<Vec<u8>>, JanusError> {
        // Try with Touch ID access control first
        let mut options = PasswordOptions::new_generic_password(SERVICE, group_name);
        options.set_access_control_options(AccessControlOptions::USER_PRESENCE);
        match generic_password(options) {
            Ok(data) => return Ok(Some(data)),
            Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => {}
            Err(err) if err.code() == ERR_SEC_MISSING_ENTITLEMENT => {}
            Err(err) => return Err(map_keychain_error(err)),
        }

        // Fall back to basic Keychain (item may have been saved without Touch ID)
        match security_framework::passwords::get_generic_password(SERVICE, group_name) {
            Ok(data) => Ok(Some(data)),
            Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(err) => Err(map_keychain_error(err)),
        }
    }

    /// Removes a group key from macOS Keychain.
    fn delete(&self, group_name: &str) -> Result<(), JanusError> {
        match delete_generic_password(SERVICE, group_name) {
            Ok(()) => Ok(()),
            Err(err) if err.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(err) => Err(map_keychain_error(err)),
        }
    }
}
