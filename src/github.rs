use crate::error::JanusError;

/// Fetches SSH public keys for a GitHub user as `age::ssh::Recipient` values.
pub fn fetch_recipients(_username: &str) -> Result<Vec<age::ssh::Recipient>, JanusError> {
    todo!()
}

/// Fetches SSH keys for multiple GitHub users, merging all recipients.
pub fn fetch_all_recipients(_usernames: &[String]) -> Result<Vec<age::ssh::Recipient>, JanusError> {
    todo!()
}
