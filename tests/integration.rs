use tempfile::TempDir;

fn generate_ssh_keypair(dir: &std::path::Path) -> (std::path::PathBuf, age::ssh::Recipient) {
    let key_path = dir.join("id_ed25519");
    let status = std::process::Command::new("ssh-keygen")
        .args([
            "-t",
            "ed25519",
            "-f",
            key_path.to_str().unwrap(),
            "-N",
            "",
            "-q",
        ])
        .status()
        .expect("ssh-keygen");
    assert!(status.success());

    let pub_key = std::fs::read_to_string(dir.join("id_ed25519.pub")).unwrap();
    let recipient: age::ssh::Recipient = pub_key.trim().parse().expect("parse ssh public key");
    (key_path, recipient)
}

#[test]
fn encrypt_decrypt_round_trip_with_ssh_key() {
    let dir = TempDir::new().expect("tempdir");
    let (key_path, recipient) = generate_ssh_keypair(dir.path());

    let plaintext = b"hello, janus!";
    let ciphertext = janus::encrypt(&[recipient], plaintext).expect("encrypt");
    let decrypted = janus::decrypt(&key_path, &ciphertext).expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_armor_produces_ascii_output() {
    let dir = TempDir::new().expect("tempdir");
    let (_key_path, recipient) = generate_ssh_keypair(dir.path());

    let output = janus::encrypt_armor(&[recipient], b"test message").expect("encrypt_armor");
    assert!(output.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(output.contains("-----END AGE ENCRYPTED FILE-----"));
}

#[test]
fn encrypt_armor_decrypt_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let (key_path, recipient) = generate_ssh_keypair(dir.path());

    let plaintext = b"armored round trip";
    let armored = janus::encrypt_armor(&[recipient], plaintext).expect("encrypt_armor");
    let decrypted = janus::decrypt(&key_path, armored.as_bytes()).expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn group_create_and_encrypt_decrypt_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let repo_root = dir.path();
    let ssh_dir = dir.path().join("ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let (key_path, recipient) = generate_ssh_keypair(&ssh_dir);

    // Manually create a group (bypassing GitHub fetch)
    let group_identity = age::x25519::Identity::generate();
    let group_public = group_identity.to_public();
    let group_secret = group_identity.to_string();
    let secret_str = age::secrecy::ExposeSecret::expose_secret(&group_secret);

    let bundle = janus::encrypt(&[recipient], secret_str.as_bytes()).expect("encrypt bundle");

    let groups_dir = repo_root.join(".janus").join("groups").join("test-team");
    std::fs::create_dir_all(&groups_dir).unwrap();
    std::fs::write(
        groups_dir.join("meta.toml"),
        format!(
            "name = \"test-team\"\nmembers = [\"testuser\"]\npublic_key = \"{}\"\ncreated_at = \"0\"",
            group_public
        ),
    )
    .unwrap();
    std::fs::write(groups_dir.join("bundle.age"), &bundle).unwrap();

    janus::group::import("test-team", &key_path, repo_root).expect("import");

    let group = janus::group::load("test-team", repo_root).expect("load");
    let ciphertext =
        janus::encrypt_for_group(&group, b"secret group message").expect("encrypt for group");
    let plaintext =
        janus::decrypt_with_group("test-team", &ciphertext).expect("decrypt with group");

    assert_eq!(plaintext, b"secret group message");
}

#[test]
fn group_load_not_found() {
    let dir = TempDir::new().expect("tempdir");
    let result = janus::group::load("nonexistent", dir.path());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[test]
fn decrypt_with_group_not_imported() {
    let result = janus::decrypt_with_group("nonexistent-group-xyz", b"dummy");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not imported"));
}

#[test]
fn decrypt_with_invalid_identity() {
    let dir = TempDir::new().expect("tempdir");
    let bad_key = dir.path().join("bad_key");
    std::fs::write(&bad_key, "not a real key").unwrap();

    let result = janus::decrypt(&bad_key, b"dummy ciphertext");
    assert!(result.is_err());
}
