# janus

GitHub SSH key-based multi-recipient encryption CLI with LINE-style group key management.

Powered by [age](https://github.com/FiloSottile/age) encryption ([rage](https://github.com/str4d/rage) Rust implementation).

## Features

- Encrypt messages for GitHub users using their SSH public keys
- Multi-recipient encryption (any recipient can decrypt)
- LINE-style shared group key management via Git repository
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

# Encrypt with ASCII armor (text-safe)
echo "secret" | janus encrypt --to alice --to bob --armor

# Decrypt with your SSH private key
janus decrypt -i ~/.ssh/id_ed25519 < encrypted.age
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

# Encrypt for the group (O(1), regardless of member count)
janus encrypt --group team-a "secret message"

# Decrypt with the group key
janus decrypt --group team-a < encrypted.age

# Rotate key when members change
janus group rotate team-a --members alice bob dave
```

### Group management

```bash
janus group list           # List all groups
janus group show team-a    # Show group details
```

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
// Fetch GitHub SSH keys and encrypt
let recipients = janus::github::fetch_all_recipients(&["alice".into(), "bob".into()])?;
let ciphertext = janus::encrypt(&recipients, b"secret message")?;

// Decrypt with SSH key
let plaintext = janus::decrypt(Path::new("~/.ssh/id_ed25519"), &ciphertext)?;

// Group encryption
let group = janus::group::load("team-a", Path::new("."))?;
let ciphertext = janus::encrypt_for_group(&group, b"secret")?;
let plaintext = janus::decrypt_with_group("team-a", &ciphertext)?;
```

## License

MIT OR Apache-2.0
