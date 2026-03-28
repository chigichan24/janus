use std::io::Write;

use tempfile::TempDir;

#[test]
fn encrypt_decrypt_round_trip_with_age_key() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    let plaintext = b"hello, janus!";

    // Encrypt using the x25519 recipient (simulates the group key path)
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .expect("encryptor creation");
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(&mut ciphertext).expect("wrap_output");
    writer.write_all(plaintext).expect("write");
    writer.finish().expect("finish");

    // Decrypt
    let decryptor = age::Decryptor::new_buffered(&ciphertext[..]).expect("decryptor");
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .expect("decrypt");
    let mut result = vec![];
    std::io::Read::read_to_end(&mut reader, &mut result).expect("read");

    assert_eq!(result, plaintext);
}

#[test]
fn encrypt_armor_produces_ascii_output() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    // Use SSH-like flow through janus library (but with x25519 for testing)
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .expect("encryptor");

    let mut ciphertext = vec![];
    let armored =
        age::armor::ArmoredWriter::wrap_output(&mut ciphertext, age::armor::Format::AsciiArmor)
            .expect("armored writer");
    let mut writer = encryptor.wrap_output(armored).expect("wrap_output");
    writer.write_all(b"test message").expect("write");
    writer
        .finish()
        .expect("finish stream")
        .finish()
        .expect("finish armor");

    let output = String::from_utf8(ciphertext).expect("valid utf8");
    assert!(output.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));
    assert!(output.contains("-----END AGE ENCRYPTED FILE-----"));
}

#[test]
fn group_create_and_encrypt_decrypt_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let repo_root = dir.path();

    // Generate a "member" SSH key pair using ssh-keygen
    let ssh_dir = dir.path().join("ssh");
    std::fs::create_dir_all(&ssh_dir).unwrap();
    let key_path = ssh_dir.join("id_ed25519");
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

    // Read the public key and write it to a known location
    let pub_key = std::fs::read_to_string(ssh_dir.join("id_ed25519.pub")).unwrap();
    let pub_key = pub_key.trim();

    // Parse as age SSH recipient to verify it works
    let recipient: age::ssh::Recipient = pub_key.parse().expect("parse ssh public key");

    // Manually create a group (bypassing GitHub fetch)
    let group_identity = age::x25519::Identity::generate();
    let group_public = group_identity.to_public();
    let group_secret = group_identity.to_string();
    let secret_str = age::secrecy::ExposeSecret::expose_secret(&group_secret);

    // Encrypt the group key for the SSH recipient
    let bundle = janus::encrypt(&[recipient], secret_str.as_bytes()).expect("encrypt bundle");

    // Set up group files in repo
    let groups_dir = repo_root.join(".janus").join("groups").join("test-team");
    std::fs::create_dir_all(&groups_dir).unwrap();
    std::fs::write(
        groups_dir.join("meta.toml"),
        format!(
            "name = \"test-team\"\nmembers = [\"testuser\"]\npublic_key = \"{}\"\ncreated_at = \"0\"",
            group_public
        ),
    ).unwrap();
    std::fs::write(groups_dir.join("bundle.age"), &bundle).unwrap();

    // Import the group key
    janus::group::import("test-team", &key_path, repo_root).expect("import");

    // Encrypt a message for the group
    let group = janus::group::load("test-team", repo_root).expect("load");
    let ciphertext =
        janus::encrypt_for_group(&group, b"secret group message").expect("encrypt for group");

    // Decrypt the message using the group key
    let plaintext =
        janus::decrypt_with_group("test-team", &ciphertext).expect("decrypt with group");

    assert_eq!(plaintext, b"secret group message");
}

#[test]
fn group_load_not_found() {
    let dir = TempDir::new().expect("tempdir");
    let result = janus::group::load("nonexistent", dir.path());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[test]
fn decrypt_with_group_not_imported() {
    let result = janus::decrypt_with_group("nonexistent-group-xyz", b"dummy");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("not imported"));
}
