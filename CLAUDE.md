# janus

GitHub SSH key-based multi-recipient encryption CLI with shared group key management. Wraps the `age` crate.

## Commands

```bash
cargo build              # Build
cargo test               # Run all tests (10 integration tests)
cargo fmt -- --check     # Check formatting
cargo clippy -- -D warnings  # Lint with warnings as errors
cargo fmt && cargo clippy -- -D warnings && cargo test  # Full check (run before every commit)
```

## Architecture

```
src/
  lib.rs          — Public API re-exports
  cli.rs          — clap argument definitions
  main.rs         — CLI entry point, GroupContext assembly
  error.rs        — JanusError enum + KeychainErrorKind
  github.rs       — Fetch SSH public keys from GitHub
  encrypt.rs      — Multi-recipient encryption (age format)
  decrypt.rs      — Decryption with SSH key or any age identity
  group.rs        — Group key management: create/import/load/list/rotate/encrypt/decrypt
  keystore/
    mod.rs        — KeyStore trait, NullStore, MemoryStore
    keychain.rs   — macOS Keychain implementation (security-framework)
```

### Key types

- **`GroupContext`** — Bundles `repo_root`, `identity_path` (SSH key for bundle fallback), and `keystore` (Box<dyn KeyStore>). Passed to all group operations to avoid parameter sprawl.
- **`KeyStore` trait** — Pluggable group key storage. Implementations: `KeychainStore` (macOS), `NullStore` (no persistence), `MemoryStore` (testing).
- **`resolve_group_key`** — Tries keystore cache first, falls back to bundle.age decryption via SSH key.

### Group key flow

- `.janus/groups/<name>/meta.toml` + `bundle.age` — In repo, safe to share (public key + encrypted secret key)
- Keychain (macOS) — Caches decrypted group secret key locally with login protection
- Non-macOS — No local persistence; decrypts from bundle every time

## Code conventions

- All `pub fn` must have `///` doc comments. Do not remove them.
- Code comments and doc comments must be written in English.
- Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` before every commit. All must pass.
- Group names: ASCII alphanumeric, `-`, `_` only (whitelist validation).
- No plaintext secret key files on disk. Use Keychain (macOS) or no persistence.

## Git workflow

- `main` branch is protected: changes must go through pull requests.
- When integrating work from worktrees, use cherry-pick (not merge).
- Keep commits small and independent.
- Commit messages: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `ci:`

## Testing

- Integration tests use `MemoryStore` to avoid filesystem side effects.
- SSH keypairs generated via `ssh-keygen` in temp directories.
- No network-dependent tests in CI (GitHub API calls would need `#[ignore]`).
- macOS Keychain tests would need `#[cfg(target_os = "macos")]` + `#[ignore]`.

## Dependencies

- `age` 0.11.2 — Core encryption (ssh + armor features)
- `clap` 4 — CLI argument parsing (derive feature)
- `reqwest` 0.12 — GitHub key fetching (blocking feature, no async runtime)
- `security-framework` 3 — macOS Keychain (target_os = "macos" only)
- `serde` + `toml` — Group metadata serialization
- `thiserror` 2 — Error type derivation
