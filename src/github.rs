use crate::error::JanusError;

/// Fetches SSH public keys for a GitHub user as `age::ssh::Recipient` values.
pub fn fetch_recipients(username: &str) -> Result<Vec<age::ssh::Recipient>, JanusError> {
    let url = format!("https://github.com/{username}.keys");
    let response = reqwest::blocking::get(&url).map_err(|e| JanusError::KeyFetch {
        username: username.to_string(),
        source: e,
    })?;

    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(JanusError::NoKeysFound(username.to_string()));
    }
    if !status.is_success() {
        return Err(JanusError::KeyFetch {
            username: username.to_string(),
            source: response.error_for_status().unwrap_err(),
        });
    }

    let body = response.text().map_err(|e| JanusError::KeyFetch {
        username: username.to_string(),
        source: e,
    })?;

    let mut skipped = 0usize;
    let recipients: Vec<age::ssh::Recipient> = body
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| match line.parse::<age::ssh::Recipient>() {
            Ok(r) => Some(r),
            Err(_) => {
                let prefix: String = line.split_whitespace().take(1).collect();
                eprintln!("warning: skipping unsupported key type for '{username}': {prefix}");
                skipped += 1;
                None
            }
        })
        .collect();

    if recipients.is_empty() {
        if skipped > 0 {
            return Err(JanusError::KeyParse(format!(
                "found {skipped} key(s) for '{username}' but none are age-compatible SSH keys"
            )));
        }
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
