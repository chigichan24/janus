use assert_cmd::Command;
use tempfile::TempDir;

fn generate_ssh_keypair(dir: &std::path::Path) -> (std::path::PathBuf, age::ssh::Recipient) {
    std::fs::create_dir_all(dir).unwrap();
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

fn make_test_context(
    dir: &std::path::Path,
    identity_path: std::path::PathBuf,
) -> janus::GroupContext {
    janus::GroupContext {
        repo_root: dir.to_path_buf(),
        identity_path,
        keystore: Box::new(janus::keystore::MemoryStore::new()),
    }
}

#[test]
fn encrypt_decrypt_round_trip_with_ssh_key() {
    let dir = TempDir::new().expect("tempdir");
    let (key_path, recipient) = generate_ssh_keypair(&dir.path().join("ssh"));

    let plaintext = b"hello, janus!";
    let ciphertext = janus::encrypt(&[recipient], plaintext).expect("encrypt");
    let decrypted = janus::decrypt(&key_path, &ciphertext).expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_armor_produces_ascii_output() {
    let dir = TempDir::new().expect("tempdir");
    let (_key_path, recipient) = generate_ssh_keypair(&dir.path().join("ssh"));

    let output = janus::encrypt_armor(&[recipient], b"test message").expect("encrypt_armor");
    assert!(output.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(output.contains("-----END AGE ENCRYPTED FILE-----"));
}

#[test]
fn encrypt_armor_decrypt_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let (key_path, recipient) = generate_ssh_keypair(&dir.path().join("ssh"));

    let plaintext = b"armored round trip";
    let armored = janus::encrypt_armor(&[recipient], plaintext).expect("encrypt_armor");
    let decrypted = janus::decrypt(&key_path, armored.as_bytes()).expect("decrypt");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn group_create_and_encrypt_decrypt_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let (key_path, recipient) = generate_ssh_keypair(&dir.path().join("ssh"));
    let ctx = make_test_context(dir.path(), key_path);

    let group =
        janus::group::create_with_recipients("test-team", &["testuser".into()], &[recipient], &ctx)
            .expect("create");

    janus::group::import("test-team", &ctx).expect("import");

    let ciphertext =
        janus::encrypt_for_group(&group, b"secret group message").expect("encrypt for group");
    let plaintext =
        janus::decrypt_with_group("test-team", &ciphertext, &ctx).expect("decrypt with group");

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
fn decrypt_with_group_not_imported_uses_bundle_fallback() {
    let dir = TempDir::new().expect("tempdir");
    let (key_path, recipient) = generate_ssh_keypair(&dir.path().join("ssh"));
    let ctx = make_test_context(dir.path(), key_path);

    let group = janus::group::create_with_recipients(
        "fallback-test",
        &["testuser".into()],
        &[recipient],
        &ctx,
    )
    .expect("create");

    // Use a fresh MemoryStore (empty cache) to force bundle fallback
    let fresh_ctx = make_test_context(dir.path(), ctx.identity_path.clone());

    let ciphertext = janus::encrypt_for_group(&group, b"fallback msg").expect("encrypt");
    let plaintext =
        janus::decrypt_with_group("fallback-test", &ciphertext, &fresh_ctx).expect("decrypt");

    assert_eq!(plaintext, b"fallback msg");
}

#[test]
fn decrypt_with_invalid_identity() {
    let dir = TempDir::new().expect("tempdir");
    let bad_key = dir.path().join("bad_key");
    std::fs::write(&bad_key, "not a real key").unwrap();

    let result = janus::decrypt(&bad_key, b"dummy ciphertext");
    assert!(result.is_err());
}

#[test]
fn invalid_group_name_rejected() {
    let dir = TempDir::new().expect("tempdir");
    let result = janus::group::load("../escape", dir.path());
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("invalid group name")
    );
}

#[test]
fn group_list_empty() {
    let dir = TempDir::new().expect("tempdir");
    let groups = janus::group::list(dir.path()).expect("list");
    assert!(groups.is_empty());
}

#[test]
fn group_members_deduplication() {
    let dir = TempDir::new().expect("tempdir");
    let (key_path, recipient) = generate_ssh_keypair(&dir.path().join("ssh"));
    let ctx = make_test_context(dir.path(), key_path);

    let group = janus::group::create_with_recipients(
        "dedup-test",
        &["alice".into(), "alice".into(), "bob".into()],
        &[recipient],
        &ctx,
    )
    .expect("create");

    assert_eq!(group.members.len(), 2);
    assert!(group.members.contains(&"alice".to_string()));
    assert!(group.members.contains(&"bob".to_string()));
}

#[test]
fn completions_bash_produces_output() {
    Command::cargo_bin("janus")
        .unwrap()
        .args(["completions", "bash"])
        .assert()
        .success()
        .stdout(predicates::str::contains("complete"))
        .stdout(predicates::str::contains("janus"));
}

#[test]
fn completions_invalid_shell_fails() {
    Command::cargo_bin("janus")
        .unwrap()
        .args(["completions", "invalid"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("invalid"));
}
