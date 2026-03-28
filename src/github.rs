use crate::error::JanusError;

/// Fetches SSH public keys for a GitHub user as `age::ssh::Recipient` values.
pub fn fetch_recipients(username: &str) -> Result<Vec<age::ssh::Recipient>, JanusError> {
    let url = format!("https://github.com/{username}.keys");
    let response = reqwest::blocking::get(&url).map_err(|e| JanusError::KeyFetch {
        username: username.to_string(),
        source: e,
    })?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(JanusError::NoKeysFound(username.to_string()));
    }

    let body = response.text().map_err(|e| JanusError::KeyFetch {
        username: username.to_string(),
        source: e,
    })?;

    let recipients: Vec<age::ssh::Recipient> = body
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.parse::<age::ssh::Recipient>().ok())
        .collect();

    if recipients.is_empty() {
        return Err(JanusError::NoKeysFound(username.to_string()));
    }

    Ok(recipients)
}

/// Fetches SSH keys for multiple GitHub users, merging all recipients.
pub fn fetch_all_recipients(usernames: &[String]) -> Result<Vec<age::ssh::Recipient>, JanusError> {
    let mut all_recipients = Vec::new();
    for username in usernames {
        let recipients = fetch_recipients(username)?;
        all_recipients.extend(recipients);
    }
    Ok(all_recipients)
}
