# janus

GitHub SSH key-based multi-recipient encryption CLI with LINE-style group key management.

Powered by [age](https://github.com/FiloSottile/age) encryption ([rage](https://github.com/str4d/rage) Rust implementation).

## Features

- Encrypt messages for GitHub users using their SSH public keys
- Multi-recipient encryption (any recipient can decrypt)
- LINE-style shared group key management via Git repository
- ASCII armor support for text-safe output
- Compatible with `rage`/`age` CLI tools
- Usable as both a CLI tool and a Rust library

## Install

```bash
cargo install --path .
```

## Usage

### Direct encryption (by GitHub username)

```bash
# Encrypt for multiple GitHub users
janus encrypt --to alice --to bob "secret message"

# Encrypt with ASCII armor (text-safe output)
echo "secret" | janus encrypt --to alice --to bob --armor

# Encrypt from stdin to a file
echo "secret" | janus encrypt --to alice -o encrypted.age

# Decrypt with your SSH private key (defaults to ~/.ssh/id_ed25519)
janus decrypt < encrypted.age

# Decrypt with a specific key
janus decrypt -i ~/.ssh/id_rsa < encrypted.age
```

### Group encryption (LINE-style shared key)

```bash
# Create a group (generates shared key, encrypts for members)
janus group create team-a --members alice bob charlie

# Commit the group to your repo
git add .janus/groups/team-a/
git commit -m "add group team-a"
git push

# Members pull and import the group key
git pull
janus group import team-a

# Import with a specific SSH key
janus group import team-a -i ~/.ssh/id_rsa

# Encrypt for the group (O(1), regardless of member count)
janus encrypt --group team-a "secret message"

# Decrypt with the group key
janus decrypt --group team-a < encrypted.age

# Rotate key when members change
janus group rotate team-a --members alice bob dave
```

Note: `--armor` is only available for direct encryption (`--to`), not for group encryption (`--group`).

### Group management

```bash
janus group list           # List all groups
janus group show team-a    # Show group details
```

### Group name constraints

Group names must consist of ASCII alphanumeric characters, hyphens (`-`), and underscores (`_`) only.
Duplicate members are automatically deduplicated.

## Architecture

### Group key management

Inspired by [LINE's Letter Sealing protocol](https://www.lycorp.co.jp/ja/privacy-security/line-encryption-whitepaper-ver2.2.pdf):

1. **Group creation**: Generates an age X25519 keypair. The private key is encrypted for each member using their GitHub SSH public keys.
2. **Key distribution**: Encrypted key bundle (`.janus/groups/<name>/bundle.age`) is shared via Git.
3. **Key import**: Members decrypt the bundle with their SSH key, storing the group private key locally.
4. **Encryption**: Messages are encrypted to the group's public key (single recipient, O(1)).
5. **Key rotation**: New keypair generated on membership change. All members must re-import.

### File layout

```
# In repository (safe to share)
.janus/groups/<name>/
  meta.toml      # Group metadata (name, members, public key)
  bundle.age     # Group private key encrypted for all members

# Local (never share)
~/.config/janus/identities/
  <name>.key     # Decrypted group private key
```

## Library usage

```rust
use std::path::Path;

// Fetch GitHub SSH keys and encrypt
let recipients = janus::github::fetch_all_recipients(&["alice".into(), "bob".into()])?;
let ciphertext = janus::encrypt(&recipients, b"secret message")?;

// Encrypt with ASCII armor
let armored = janus::encrypt_armor(&recipients, b"secret message")?;

// Decrypt with SSH key
let plaintext = janus::decrypt(Path::new("/home/user/.ssh/id_ed25519"), &ciphertext)?;

// Decrypt with any age identity (SSH or X25519)
let plaintext = janus::decrypt_with_identity(&identity, &ciphertext)?;

// Group operations
let group = janus::group::create("team-a", &members, Path::new("."))?;
let group = janus::group::load("team-a", Path::new("."))?;
let ciphertext = janus::encrypt_for_group(&group, b"secret")?;
let plaintext = janus::decrypt_with_group("team-a", &ciphertext)?;

// List all groups
let groups = janus::group::list(Path::new("."))?;

// Create group with pre-fetched recipients (useful for testing)
let group = janus::group::create_with_recipients("team-a", &members, &recipients, Path::new("."))?;
```

Note: The library API does not expand `~` in paths. Use absolute paths when calling library functions directly.

## License

MIT OR Apache-2.0
