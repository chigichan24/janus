use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password, generic_password,
    set_generic_password_options,
};
// errSecItemNotFound = -25300
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

use crate::error::{JanusError, KeychainErrorKind};
use crate::keystore::KeyStore;

const SERVICE: &str = "com.janus.group-key";

/// macOS Keychain-backed key store with Touch ID / passcode protection.
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
    // errSecMissingEntitlement = -34018
    if code == -34018 {
        return JanusError::Keychain {
            message: "missing code signing entitlement; see README for setup".into(),
            kind: KeychainErrorKind::MissingEntitlement,
        };
    }
    JanusError::Keychain {
        message: format!("keychain error (code {code}): {err}"),
        kind: KeychainErrorKind::Other,
    }
}

impl KeyStore for KeychainStore {
    /// Stores a group key in macOS Keychain with biometric/passcode access control.
    fn save(&self, group_name: &str, key_data: &[u8]) -> Result<(), JanusError> {
        // Delete any existing entry first (set_generic_password_options handles
        // duplicates, but we want to ensure access control is applied fresh)
        let _ = delete_generic_password(SERVICE, group_name);

        let mut options = PasswordOptions::new_generic_password(SERVICE, group_name);
        options.set_access_control_options(AccessControlOptions::USER_PRESENCE);
        set_generic_password_options(key_data, options).map_err(map_keychain_error)
    }

    /// Retrieves a group key from macOS Keychain. Triggers Touch ID / passcode prompt.
    fn load(&self, group_name: &str) -> Result<Option<Vec<u8>>, JanusError> {
        let mut options = PasswordOptions::new_generic_password(SERVICE, group_name);
        options.set_access_control_options(AccessControlOptions::USER_PRESENCE);
        match generic_password(options) {
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
