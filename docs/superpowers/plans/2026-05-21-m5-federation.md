# M5 — Federation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Important:** Refresh this plan after M3 + M4 ship. The TLS-pinning outbound client assumes M3 produced an `axum_server::tls_rustls` setup with `tls.crt` + `tls.key` in the config dir; the ACL hook (`AppState::acl.filter_sessions`) assumes M4 exposed a per-session capability check. If those shapes drifted, update the touch points listed in Task 7 (federated `GET /api/sessions`) and Task 6 (peer-token middleware).

**Goal:** Two or more terminal-hub instances can be peered so that the primary user on instance A sees, attaches to, and manages sessions running on instances B, C, … from a single sidebar. Peering is added through an admin UI that pins **both** the peer's ed25519 pubkey fingerprint and TLS cert fingerprint out-of-band; no TOFU. After this milestone the three-server / nine-session scenario from the original brief works end-to-end.

**Architecture:** A new `federation` module in the server crate owns: (a) the ed25519 peer identity loaded from `peer_id` / `peer_id.pub`, (b) the inbound peer-auth handler (`/peer/challenge` + `/peer/auth`) gated on `authorized_peers`, (c) the lazy outbound `PeerClient` (reqwest with a custom rustls verifier that pins SHA-256 of the cert), and (d) the proxy bridge for `GET /api/sessions` and `/ws/attach/<peer>/<id>` that talks to peers using a short-lived `PeerToken`. The CLI gains `peer-info`. The sidebar grows collapsible groups per peer with status dots.

**Tech Stack:** Same as M3/M4 + `ed25519-dalek = "2"`, `rand_core = "0.6"`, `base64 = "0.22"`, `sha2 = "0.10"` (probably already pulled in by M3), `reqwest = { version = "0.12", default-features = false, features = ["rustls-tls-manual-roots", "json", "stream"] }`, `rustls = "0.23"`, `toml = "0.8"`, `tokio-tungstenite = { version = "0.23", features = ["rustls-tls-webpki-roots"] }`. The `cli` crate adds `clap = { version = "4", features = ["derive"] }` if M3 didn't already pull it.

**Spec reference:** `docs/superpowers/specs/2026-05-21-terminal-hub-design.md` §5 (architecture), §9 (federation), §10 (TLS pinning), §11 (persistence layout), §12 (sidebar UX). Threat model context: §13 ("accepted: A trusts B as much as B trusts A").

---

## Task 1: Peer identity on first boot — ed25519 keypair + fingerprint helper

The peer identity is the cornerstone every other federation task depends on. We must generate it deterministically on first boot, persist it with mode 0600, refuse to start if the file is world-readable, and expose both the public bytes and the 12-char fingerprint as a library helper. The same `fingerprint12` function will also be used for TLS cert pinning, so it lives in the shared module.

**Files:**
- Create: `crates/server/src/federation/mod.rs`
- Create: `crates/server/src/federation/identity.rs`
- Create: `crates/server/src/federation/fingerprint.rs`
- Modify: `crates/server/Cargo.toml`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Add federation crate dependencies**

Add to `crates/server/Cargo.toml` `[dependencies]`:

```toml
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand_core = { version = "0.6", features = ["std"] }
base64 = "0.22"
sha2 = "0.10"
toml = "0.8"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls-manual-roots", "json", "stream"] }
rustls = "0.23"
tokio-tungstenite = { version = "0.23", features = ["rustls-tls-webpki-roots"] }
futures-util = "0.3"
hex = "0.4"
```

- [ ] **Step 2: Fingerprint helper (shared by peer pubkey + TLS cert pinning)**

Create `crates/server/src/federation/fingerprint.rs`:

```rust
//! SHA-256 → 12-hex-char fingerprints formatted `xxxx:xxxx:xxxx`.
//!
//! Used for both the peer's ed25519 public key and the peer's TLS cert.
//! The shortened form is what the user reads off `peer-info` and types into
//! the "Add server" form on the other instance.

use sha2::{Digest, Sha256};

/// SHA-256 of `bytes`, truncated to 12 hex chars, formatted `xxxx:xxxx:xxxx`.
pub fn fingerprint12(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex = hex::encode(&digest[..6]); // 6 bytes = 12 hex chars
    format!("{}:{}:{}", &hex[0..4], &hex[4..8], &hex[8..12])
}

/// Loose validator used by the admin UI to reject obviously-malformed input
/// before we waste a TLS handshake. Format: three groups of four lowercase
/// hex chars separated by colons.
pub fn looks_like_fingerprint(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 3
        && parts.iter().all(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_for_known_input() {
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(fingerprint12(b"hello"), "2cf2:4dba:5fb0");
    }

    #[test]
    fn validator_accepts_canonical_form() {
        assert!(looks_like_fingerprint("a3f9:c12e:7b04"));
        assert!(!looks_like_fingerprint("a3f9:c12e"));
        assert!(!looks_like_fingerprint("A3F9:C12E:7B04")); // upper rejected
        assert!(!looks_like_fingerprint("zzzz:c12e:7b04"));
    }
}
```

- [ ] **Step 3: PeerIdentity — load-or-generate ed25519 keypair**

Create `crates/server/src/federation/identity.rs`:

```rust
//! Per-instance ed25519 peer identity.
//!
//! On first boot, generate a fresh keypair and write `peer_id` (mode 0600)
//! and `peer_id.pub` into the config dir. On subsequent boots, load them.
//! Refuse to start if `peer_id` is group/world-readable.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::OsRng;

use super::fingerprint::fingerprint12;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid base64: {0}")]
    B64(#[from] base64::DecodeError),
    #[error("malformed peer_id file (expected 32 bytes, got {0})")]
    KeyLen(usize),
    #[error("malformed peer_id.pub (expected 32 bytes, got {0})")]
    PubLen(usize),
    #[error("ed25519: {0}")]
    Ed(#[from] ed25519_dalek::SignatureError),
    #[error("refusing to start: {0} has insecure permissions (mode {1:o}); chmod 600 it")]
    Perms(PathBuf, u32),
}

#[derive(Clone)]
pub struct PeerIdentity {
    signing: SigningKey,
    verifying: VerifyingKey,
    pub_b64: String,
    fingerprint: String,
}

impl PeerIdentity {
    /// Load `peer_id` + `peer_id.pub` from `config_dir`, or generate + write
    /// them on first boot.
    pub fn load_or_create(config_dir: &Path) -> Result<Self, Error> {
        let priv_path = config_dir.join("peer_id");
        let pub_path = config_dir.join("peer_id.pub");

        let signing = match fs::read_to_string(&priv_path) {
            Ok(text) => {
                check_secure_perms(&priv_path)?;
                let bytes = B64.decode(text.trim())?;
                if bytes.len() != 32 {
                    return Err(Error::KeyLen(bytes.len()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                SigningKey::from_bytes(&arr)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let sk = SigningKey::generate(&mut OsRng);
                let encoded = B64.encode(sk.to_bytes());
                fs::create_dir_all(config_dir)?;
                fs::write(&priv_path, encoded)?;
                set_owner_only(&priv_path)?;
                sk
            }
            Err(e) => return Err(Error::Io(e)),
        };

        let verifying = signing.verifying_key();
        let pub_bytes = verifying.to_bytes();
        let pub_b64 = B64.encode(pub_bytes);

        // (Re)write the pubkey file unconditionally — it's derivable from the
        // private key and harmless if it goes missing.
        fs::write(&pub_path, &pub_b64)?;

        let fingerprint = fingerprint12(&pub_bytes);

        Ok(Self { signing, verifying, pub_b64, fingerprint })
    }

    pub fn pub_b64(&self) -> &str { &self.pub_b64 }
    pub fn fingerprint(&self) -> &str { &self.fingerprint }
    pub fn verifying(&self) -> &VerifyingKey { &self.verifying }

    pub fn sign(&self, msg: &[u8]) -> Signature { self.signing.sign(msg) }

    pub fn verify(pub_bytes: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        if pub_bytes.len() != 32 { return Err(Error::PubLen(pub_bytes.len())); }
        let mut k = [0u8; 32];
        k.copy_from_slice(pub_bytes);
        let vk = VerifyingKey::from_bytes(&k)?;
        let s = Signature::from_slice(sig)?;
        vk.verify(msg, &s)?;
        Ok(())
    }
}

#[cfg(unix)]
fn check_secure_perms(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Perms(path.to_path_buf(), mode));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_secure_perms(_: &Path) -> Result<(), Error> { Ok(()) }

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_: &Path) -> Result<(), Error> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_and_reloads_same_key() {
        let dir = tempdir().unwrap();
        let a = PeerIdentity::load_or_create(dir.path()).unwrap();
        let b = PeerIdentity::load_or_create(dir.path()).unwrap();
        assert_eq!(a.pub_b64(), b.pub_b64());
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn sign_round_trip() {
        let dir = tempdir().unwrap();
        let id = PeerIdentity::load_or_create(dir.path()).unwrap();
        let msg = b"hello federation";
        let sig = id.sign(msg);
        assert!(PeerIdentity::verify(id.verifying().as_bytes(), msg, &sig.to_bytes()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_world_readable_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        PeerIdentity::load_or_create(dir.path()).unwrap();
        std::fs::set_permissions(dir.path().join("peer_id"),
            std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = PeerIdentity::load_or_create(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Perms(_, 0o644)));
    }
}
```

- [ ] **Step 4: Module wiring**

Create `crates/server/src/federation/mod.rs`:

```rust
//! Federation: peer identity, peer auth handshake, outbound TLS-pinned client.

pub mod fingerprint;
pub mod identity;
```

Add to `crates/server/src/lib.rs` (in the existing `pub mod` block):

```rust
pub mod federation;
```

Add to `crates/server/Cargo.toml` `[dev-dependencies]`:

```toml
tempfile = "3"
```

- [ ] **Step 5: Run + commit**

Run: `cargo test -p terminal-hub-server federation::`
Expected: 5 tests pass (2 fingerprint, 3 identity).

```bash
git add crates/server/Cargo.toml crates/server/src/lib.rs crates/server/src/federation/
git commit -m "feat(federation): ed25519 peer identity + SHA-256 fingerprint helper"
```

---

## Task 2: `authorized_peers` and `peers.toml` parsers

Both files are hand-editable; the UI just provides a convenience layer (Task 8). `authorized_peers` is loaded once at boot — we explicitly do **not** watch the file. If the user edits it, they restart the service. This is documented inline so future Claude doesn't add fs-watching "to help."

**Files:**
- Create: `crates/server/src/federation/authorized.rs`
- Create: `crates/server/src/federation/peers_toml.rs`
- Modify: `crates/server/src/federation/mod.rs`

- [ ] **Step 1: `authorized_peers` parser**

Create `crates/server/src/federation/authorized.rs`:

```rust
//! `authorized_peers` — line-oriented list of peers this instance accepts
//! inbound federation auth from.
//!
//! Format (one per line, `#` for comments, blank lines ignored):
//!
//!     <pubkey-b64> <friendly_name> <tls_cert_fp>
//!
//! Loaded once at boot. Edits require a restart — we deliberately do not
//! fs-watch this file (small, rarely-changed, restart is fine for MVP).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPeer {
    pub pubkey_b64: String,
    pub pubkey_bytes: [u8; 32],
    pub friendly_name: String,
    pub tls_cert_fp: String,
}

#[derive(Debug, Default, Clone)]
pub struct AuthorizedPeers {
    by_pubkey: HashMap<String, AuthorizedPeer>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("line {0}: expected `<pubkey-b64> <friendly_name> <tls_cert_fp>`")]
    BadLine(usize),
    #[error("line {line}: bad base64 pubkey: {err}")]
    BadKey { line: usize, err: base64::DecodeError },
    #[error("line {0}: pubkey must be 32 bytes")]
    BadKeyLen(usize),
}

impl AuthorizedPeers {
    /// Load from `config_dir/authorized_peers`. Missing file = empty list
    /// (federation inbound is opt-in).
    pub fn load(config_dir: &Path) -> Result<Self, Error> {
        let path = config_dir.join("authorized_peers");
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(Error::Io(e)),
        };
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut by_pubkey = HashMap::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 3 { return Err(Error::BadLine(idx + 1)); }
            let pubkey_b64 = parts[0].to_string();
            let bytes = B64.decode(&pubkey_b64)
                .map_err(|err| Error::BadKey { line: idx + 1, err })?;
            if bytes.len() != 32 { return Err(Error::BadKeyLen(idx + 1)); }
            let mut pubkey_bytes = [0u8; 32];
            pubkey_bytes.copy_from_slice(&bytes);
            by_pubkey.insert(pubkey_b64.clone(), AuthorizedPeer {
                pubkey_b64,
                pubkey_bytes,
                friendly_name: parts[1].to_string(),
                tls_cert_fp: parts[2].to_string(),
            });
        }
        Ok(Self { by_pubkey })
    }

    pub fn get(&self, pubkey_b64: &str) -> Option<&AuthorizedPeer> {
        self.by_pubkey.get(pubkey_b64)
    }

    pub fn len(&self) -> usize { self.by_pubkey.len() }
    pub fn is_empty(&self) -> bool { self.by_pubkey.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    #[test]
    fn parses_canonical_lines() {
        let key = B64.encode([7u8; 32]);
        let text = format!("# comment\n\n{key} prod-box a3f9:c12e:7b04\n");
        let ap = AuthorizedPeers::parse(&text).unwrap();
        let peer = ap.get(&key).unwrap();
        assert_eq!(peer.friendly_name, "prod-box");
        assert_eq!(peer.tls_cert_fp, "a3f9:c12e:7b04");
    }

    #[test]
    fn rejects_short_pubkey() {
        let key = B64.encode([1u8; 8]); // wrong size
        let text = format!("{key} bad fp");
        assert!(matches!(AuthorizedPeers::parse(&text), Err(Error::BadKeyLen(1))));
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ap = AuthorizedPeers::load(dir.path()).unwrap();
        assert!(ap.is_empty());
    }
}
```

- [ ] **Step 2: `peers.toml` (peers we connect TO)**

Create `crates/server/src/federation/peers_toml.rs`:

```rust
//! `peers.toml` — peers this instance connects out to.
//!
//! ```toml
//! [[peer]]
//! url = "https://prod-box.local:5999"
//! friendly_name = "prod-box"
//! peer_pubkey = "Bf3...="      # base64
//! tls_cert_fp = "a3f9:c12e:7b04"
//! ```

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEntry {
    pub url: String,
    pub friendly_name: String,
    pub peer_pubkey: String,   // base64
    pub tls_cert_fp: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PeersFile {
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")] Io(#[from] std::io::Error),
    #[error("toml parse: {0}")] Parse(#[from] toml::de::Error),
    #[error("toml serialize: {0}")] Ser(#[from] toml::ser::Error),
    #[error("duplicate friendly_name `{0}`")] Duplicate(String),
}

impl PeersFile {
    pub fn load(config_dir: &Path) -> Result<Self, Error> {
        let path = config_dir.join("peers.toml");
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(Error::Io(e)),
        };
        let parsed: Self = toml::from_str(&text)?;
        parsed.check_unique_names()?;
        Ok(parsed)
    }

    pub fn save(&self, config_dir: &Path) -> Result<(), Error> {
        self.check_unique_names()?;
        let text = toml::to_string_pretty(self)?;
        fs::create_dir_all(config_dir)?;
        fs::write(config_dir.join("peers.toml"), text)?;
        Ok(())
    }

    pub fn add(&mut self, entry: PeerEntry) -> Result<(), Error> {
        if self.peers.iter().any(|p| p.friendly_name == entry.friendly_name) {
            return Err(Error::Duplicate(entry.friendly_name));
        }
        self.peers.push(entry);
        Ok(())
    }

    pub fn remove(&mut self, friendly_name: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.friendly_name != friendly_name);
        self.peers.len() != before
    }

    pub fn get(&self, friendly_name: &str) -> Option<&PeerEntry> {
        self.peers.iter().find(|p| p.friendly_name == friendly_name)
    }

    fn check_unique_names(&self) -> Result<(), Error> {
        let mut seen = std::collections::HashSet::new();
        for p in &self.peers {
            if !seen.insert(&p.friendly_name) {
                return Err(Error::Duplicate(p.friendly_name.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = PeersFile::default();
        f.add(PeerEntry {
            url: "https://b.local:5999".into(),
            friendly_name: "b".into(),
            peer_pubkey: "AAAA".into(),
            tls_cert_fp: "a3f9:c12e:7b04".into(),
        }).unwrap();
        f.save(dir.path()).unwrap();
        let loaded = PeersFile::load(dir.path()).unwrap();
        assert_eq!(loaded.peers, f.peers);
    }

    #[test]
    fn duplicate_names_rejected() {
        let mut f = PeersFile::default();
        let e = PeerEntry { url: "x".into(), friendly_name: "dup".into(),
                            peer_pubkey: "AA".into(), tls_cert_fp: "a:b:c".into() };
        f.add(e.clone()).unwrap();
        assert!(matches!(f.add(e), Err(Error::Duplicate(_))));
    }
}
```

- [ ] **Step 3: Module wiring**

Update `crates/server/src/federation/mod.rs`:

```rust
//! Federation: peer identity, peer auth handshake, outbound TLS-pinned client.

pub mod authorized;
pub mod fingerprint;
pub mod identity;
pub mod peers_toml;
```

- [ ] **Step 4: Run + commit**

Run: `cargo test -p terminal-hub-server federation::`
Expected: original 5 + 3 authorized + 2 peers_toml = 10 pass.

```bash
git add crates/server/src/federation/authorized.rs crates/server/src/federation/peers_toml.rs crates/server/src/federation/mod.rs
git commit -m "feat(federation): parse authorized_peers + peers.toml"
```

---

## Task 3: `terminal-hub-cli peer-info` subcommand

The user runs this on instance B to read off the fingerprints they will type into instance A's "Add server" form. It must work without the server process running — it just reads the config dir and the TLS cert from disk.

**Files:**
- Modify: `crates/cli/Cargo.toml`
- Modify: `crates/cli/src/main.rs`
- Create: `crates/cli/tests/peer_info.rs`

- [ ] **Step 1: Add clap + access to the federation library code**

Update `crates/cli/Cargo.toml`:

```toml
[package]
name = "terminal-hub-cli"
version = "0.1.0"
edition.workspace = true

[[bin]]
name = "terminal-hub-cli"
path = "src/main.rs"

[dependencies]
anyhow = { workspace = true }
clap = { version = "4", features = ["derive"] }
directories-next = "2"
terminal-hub-server = { path = "../server" }

[dev-dependencies]
tempfile = "3"
assert_cmd = "2"
predicates = "3"
```

- [ ] **Step 2: Implement the subcommand**

Replace `crates/cli/src/main.rs`:

```rust
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use terminal_hub_server::federation::fingerprint::fingerprint12;
use terminal_hub_server::federation::identity::PeerIdentity;

#[derive(Parser)]
#[command(name = "terminal-hub-cli", version, about = "terminal-hub admin CLI")]
struct Cli {
    /// Override the config dir (defaults to the platform-standard location).
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print this instance's peer pubkey + fingerprint + TLS cert fingerprint,
    /// suitable for pasting into another instance's "Add server" form.
    PeerInfo {
        /// Public URL clients should use to reach this instance.
        #[arg(long, default_value = "https://localhost:5999")]
        url: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = cli.config_dir.unwrap_or_else(default_config_dir);
    match cli.cmd {
        Cmd::PeerInfo { url } => peer_info(&dir, &url),
    }
}

fn default_config_dir() -> PathBuf {
    directories_next::ProjectDirs::from("dev", "", "terminal-hub")
        .map(|p| p.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("./terminal-hub-config"))
}

fn peer_info(config_dir: &std::path::Path, url: &str) -> Result<()> {
    let id = PeerIdentity::load_or_create(config_dir)
        .with_context(|| format!("loading peer identity from {}", config_dir.display()))?;

    let tls_cert_path = config_dir.join("tls.crt");
    let tls_fp = match std::fs::read(&tls_cert_path) {
        Ok(bytes) => {
            // tls.crt is PEM. Strip the PEM envelope and base64-decode to get
            // the DER bytes that we fingerprint.
            let der = pem_to_der(&bytes)
                .with_context(|| format!("parsing PEM cert at {}", tls_cert_path.display()))?;
            fingerprint12(&der)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            "(tls.crt missing — start the server once to generate it)".to_string()
        }
        Err(e) => return Err(e.into()),
    };

    println!("terminal-hub peer info");
    println!("  url:                {url}");
    println!("  peer pubkey (b64):  {}", id.pub_b64());
    println!("  peer fingerprint:   {}", id.fingerprint());
    println!("  tls cert fp:        {tls_fp}");
    println!();
    println!("To peer this instance from another:");
    println!("  1. On the other instance, open the admin UI -> Add server.");
    println!("  2. Paste url, friendly_name of your choosing, BOTH fingerprints above.");
    println!("  3. Add this line to THIS instance's authorized_peers:");
    println!("       {} <friendly_name_they_used> <their_tls_cert_fp>", id.pub_b64());
    println!("     then restart this instance.");
    Ok(())
}

fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let text = std::str::from_utf8(pem).context("cert is not UTF-8")?;
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    Ok(B64.decode(body.trim())?)
}
```

- [ ] **Step 3: CLI integration test**

Create `crates/cli/tests/peer_info.rs`:

```rust
use assert_cmd::Command;
use predicates::str::contains;

#[test]
fn peer_info_emits_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("terminal-hub-cli").unwrap()
        .arg("--config-dir").arg(dir.path())
        .arg("peer-info")
        .arg("--url").arg("https://test.local:5999")
        .assert()
        .success()
        .stdout(contains("peer pubkey (b64):"))
        .stdout(contains("peer fingerprint:"))
        .stdout(contains("https://test.local:5999"));

    // Running again must produce the same fingerprint (identity persists).
    let first = Command::cargo_bin("terminal-hub-cli").unwrap()
        .arg("--config-dir").arg(dir.path())
        .arg("peer-info").output().unwrap();
    let second = Command::cargo_bin("terminal-hub-cli").unwrap()
        .arg("--config-dir").arg(dir.path())
        .arg("peer-info").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&first.stdout), String::from_utf8_lossy(&second.stdout));
}
```

- [ ] **Step 4: Run + commit**

Run: `cargo test -p terminal-hub-cli`
Expected: 1 test pass.

```bash
git add crates/cli/
git commit -m "feat(cli): peer-info subcommand prints peer + TLS fingerprints"
```

---

## Task 4: Inbound peer-auth handshake — `/peer/challenge` + `/peer/auth`

Two endpoints, no cookie auth, gated by `authorized_peers`. The challenge endpoint hands out a fresh 32-byte nonce keyed by the requesting pubkey; `/peer/auth` verifies the ed25519 signature over that nonce and returns a short-lived (5-minute) `PeerToken` (random 32 bytes hex). Tokens live in an in-memory `PeerTokenStore`.

The challenge has a 60-second TTL. Replay protection: each nonce is consumed on a successful `/peer/auth` (deleted from the store).

**Files:**
- Create: `crates/server/src/federation/auth.rs`
- Modify: `crates/server/src/federation/mod.rs`
- Modify: `crates/server/src/lib.rs`
- Create: `crates/server/tests/peer_auth.rs`

- [ ] **Step 1: Inbound auth handler + token store**

Create `crates/server/src/federation/auth.rs`:

```rust
//! Inbound peer-auth handshake.
//!
//! 1. Client `POST /peer/challenge { pubkey_b64 }` -> `{ challenge_b64 }`.
//!    Server stores `(pubkey, challenge)` with a 60s TTL.
//! 2. Client `POST /peer/auth { pubkey_b64, signed_challenge_b64 }` ->
//!    `{ token, expires_in }`. Server verifies signature, consumes the
//!    challenge, mints a random 32-byte hex token with 5-minute TTL.
//! 3. Subsequent peer requests carry `Authorization: PeerToken <token>`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::authorized::AuthorizedPeers;
use super::identity::PeerIdentity;

pub const CHALLENGE_TTL: Duration = Duration::from_secs(60);
pub const TOKEN_TTL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub struct PeerSession {
    pub pubkey_b64: String,
    pub friendly_name: String,
    pub expires_at: Instant,
}

#[derive(Default)]
pub struct PeerAuthState {
    challenges: Mutex<HashMap<String, (Vec<u8>, Instant)>>, // pubkey -> (nonce, expires)
    tokens: Mutex<HashMap<String, PeerSession>>,            // token -> session
}

impl PeerAuthState {
    pub fn new() -> Arc<Self> { Arc::new(Self::default()) }

    pub async fn lookup_token(&self, token: &str) -> Option<PeerSession> {
        let mut g = self.tokens.lock().await;
        let now = Instant::now();
        g.retain(|_, s| s.expires_at > now);
        g.get(token).cloned()
    }
}

#[derive(Deserialize)]
pub struct ChallengeReq { pub pubkey_b64: String }

#[derive(Serialize)]
pub struct ChallengeResp { pub challenge_b64: String, pub ttl_secs: u64 }

#[derive(Deserialize)]
pub struct AuthReq { pub pubkey_b64: String, pub signed_challenge_b64: String }

#[derive(Serialize)]
pub struct AuthResp { pub token: String, pub expires_in: u64 }

#[derive(Clone)]
pub struct InboundAuthCtx {
    pub state: Arc<PeerAuthState>,
    pub authorized: Arc<AuthorizedPeers>,
    pub _identity: Arc<PeerIdentity>, // here for symmetry; unused on the inbound side
}

pub async fn post_challenge(
    State(ctx): State<InboundAuthCtx>,
    Json(req): Json<ChallengeReq>,
) -> Result<Json<ChallengeResp>, (StatusCode, String)> {
    if ctx.authorized.get(&req.pubkey_b64).is_none() {
        return Err((StatusCode::FORBIDDEN, "pubkey not in authorized_peers".into()));
    }
    let mut nonce = vec![0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let expires = Instant::now() + CHALLENGE_TTL;
    ctx.state.challenges.lock().await
        .insert(req.pubkey_b64.clone(), (nonce.clone(), expires));
    Ok(Json(ChallengeResp {
        challenge_b64: B64.encode(&nonce),
        ttl_secs: CHALLENGE_TTL.as_secs(),
    }))
}

pub async fn post_auth(
    State(ctx): State<InboundAuthCtx>,
    Json(req): Json<AuthReq>,
) -> Result<Json<AuthResp>, (StatusCode, String)> {
    let peer = ctx.authorized.get(&req.pubkey_b64)
        .ok_or((StatusCode::FORBIDDEN, "pubkey not in authorized_peers".into()))?
        .clone();

    let (nonce, expires) = {
        let mut g = ctx.state.challenges.lock().await;
        g.remove(&req.pubkey_b64)
            .ok_or((StatusCode::BAD_REQUEST, "no outstanding challenge".into()))?
    };
    if Instant::now() > expires {
        return Err((StatusCode::BAD_REQUEST, "challenge expired".into()));
    }

    let sig = B64.decode(&req.signed_challenge_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad signature b64: {e}")))?;

    PeerIdentity::verify(&peer.pubkey_bytes, &nonce, &sig)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("signature verify failed: {e}")))?;

    let mut tok_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut tok_bytes);
    let token = hex::encode(tok_bytes);
    let expires_at = Instant::now() + TOKEN_TTL;
    ctx.state.tokens.lock().await.insert(token.clone(), PeerSession {
        pubkey_b64: peer.pubkey_b64.clone(),
        friendly_name: peer.friendly_name.clone(),
        expires_at,
    });
    Ok(Json(AuthResp { token, expires_in: TOKEN_TTL.as_secs() }))
}

/// Extract & validate a `PeerToken` from the `Authorization` header.
/// Used as a guard for all peer-only routes added in later tasks.
pub async fn require_peer_token(
    state: &Arc<PeerAuthState>,
    header: Option<&str>,
) -> Result<PeerSession, (StatusCode, String)> {
    let header = header.ok_or((StatusCode::UNAUTHORIZED, "missing Authorization".into()))?;
    let token = header.strip_prefix("PeerToken ")
        .ok_or((StatusCode::UNAUTHORIZED, "expected `Authorization: PeerToken <token>`".into()))?;
    state.lookup_token(token).await
        .ok_or((StatusCode::UNAUTHORIZED, "expired or unknown peer token".into()))
}
```

- [ ] **Step 2: Wire endpoints into router**

Update `crates/server/src/federation/mod.rs`:

```rust
//! Federation: peer identity, peer auth handshake, outbound TLS-pinned client.

pub mod auth;
pub mod authorized;
pub mod fingerprint;
pub mod identity;
pub mod peers_toml;
```

Modify `crates/server/src/lib.rs` — extend `AppState` and `router_with` to mount the new routes. Locate the existing `AppState` struct from M2/M3/M4 and add:

```rust
// inside AppState:
pub peer_auth: std::sync::Arc<crate::federation::auth::PeerAuthState>,
pub authorized_peers: std::sync::Arc<crate::federation::authorized::AuthorizedPeers>,
pub peer_identity: std::sync::Arc<crate::federation::identity::PeerIdentity>,
```

In `router_with`, before building the `Router`:

```rust
let peer_identity = std::sync::Arc::new(
    crate::federation::identity::PeerIdentity::load_or_create(&cfg.config_dir)?
);
let authorized_peers = std::sync::Arc::new(
    crate::federation::authorized::AuthorizedPeers::load(&cfg.config_dir)?
);
let peer_auth = crate::federation::auth::PeerAuthState::new();

let peer_ctx = crate::federation::auth::InboundAuthCtx {
    state: peer_auth.clone(),
    authorized: authorized_peers.clone(),
    _identity: peer_identity.clone(),
};
```

Add the routes (use a nested sub-router with its own state, then `.merge()` into the main router so the two `State` types don't collide):

```rust
let peer_router = Router::new()
    .route("/peer/challenge", axum::routing::post(crate::federation::auth::post_challenge))
    .route("/peer/auth", axum::routing::post(crate::federation::auth::post_auth))
    .with_state(peer_ctx);

// then on the main router:
.merge(peer_router)
```

Add a `config_dir: PathBuf` field to `Config` (default: `directories_next` resolution; mirror what M3 already did — if M3 added it, skip).

- [ ] **Step 3: Integration test for the round-trip**

Create `crates/server/tests/peer_auth.rs`:

```rust
use std::net::SocketAddr;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use tokio::net::TcpListener;

use terminal_hub_server::federation::identity::PeerIdentity;

async fn spawn(config_dir: &std::path::Path) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = terminal_hub_server::Config {
        config_dir: config_dir.to_path_buf(),
        ..terminal_hub_server::Config::default()
    };
    let app = terminal_hub_server::router_with(cfg).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    addr
}

fn write_authorized(dir: &std::path::Path, pubkey_b64: &str) {
    std::fs::write(
        dir.join("authorized_peers"),
        format!("{pubkey_b64} alice-laptop deadbeef:cafe:1234\n"),
    ).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_then_auth_yields_token() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let client_id = PeerIdentity::load_or_create(client_dir.path()).unwrap();
    write_authorized(server_dir.path(), client_id.pub_b64());

    let addr = spawn(server_dir.path()).await;
    let http = reqwest::Client::new();

    let chal: serde_json::Value = http.post(format!("http://{addr}/peer/challenge"))
        .json(&serde_json::json!({ "pubkey_b64": client_id.pub_b64() }))
        .send().await.unwrap().json().await.unwrap();
    let challenge = B64.decode(chal["challenge_b64"].as_str().unwrap()).unwrap();
    let sig = client_id.sign(&challenge).to_bytes();

    let auth: serde_json::Value = http.post(format!("http://{addr}/peer/auth"))
        .json(&serde_json::json!({
            "pubkey_b64": client_id.pub_b64(),
            "signed_challenge_b64": B64.encode(sig),
        }))
        .send().await.unwrap().json().await.unwrap();
    assert!(auth["token"].as_str().unwrap().len() == 64);
    assert_eq!(auth["expires_in"].as_u64().unwrap(), 300);
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthorized_pubkey_rejected() {
    let server_dir = tempfile::tempdir().unwrap();
    // No authorized_peers file written -> empty allow-list.
    let addr = spawn(server_dir.path()).await;
    let http = reqwest::Client::new();

    let stranger = PeerIdentity::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
    let resp = http.post(format!("http://{addr}/peer/challenge"))
        .json(&serde_json::json!({ "pubkey_b64": stranger.pub_b64() }))
        .send().await.unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_signature_rejected() {
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let client_id = PeerIdentity::load_or_create(client_dir.path()).unwrap();
    write_authorized(server_dir.path(), client_id.pub_b64());

    let addr = spawn(server_dir.path()).await;
    let http = reqwest::Client::new();
    let _: serde_json::Value = http.post(format!("http://{addr}/peer/challenge"))
        .json(&serde_json::json!({ "pubkey_b64": client_id.pub_b64() }))
        .send().await.unwrap().json().await.unwrap();

    let resp = http.post(format!("http://{addr}/peer/auth"))
        .json(&serde_json::json!({
            "pubkey_b64": client_id.pub_b64(),
            "signed_challenge_b64": B64.encode(vec![0u8; 64]),
        }))
        .send().await.unwrap();
    assert_eq!(resp.status(), 401);
}
```

- [ ] **Step 4: Run + commit**

Run: `cargo test -p terminal-hub-server --test peer_auth -- --nocapture`
Expected: 3 tests pass.

```bash
git add crates/server/src/federation/auth.rs crates/server/src/federation/mod.rs crates/server/src/lib.rs crates/server/tests/peer_auth.rs
git commit -m "feat(federation): /peer/challenge + /peer/auth handshake gated by authorized_peers"
```

---

## Task 5: TLS-cert-pinning outbound `PeerClient`

The outbound federation client is a `reqwest::Client` built from a custom `rustls::ClientConfig` whose `ServerCertVerifier` accepts ONLY certs whose SHA-256 matches the pinned value. No CA validation, no hostname validation — the pin **is** the trust anchor. This is intentional: peers use self-signed certs and we don't want to drag a CA bundle around.

The verifier is constructed per peer (a stateless impl that closes over the expected fingerprint). The `PeerClient` caches the resulting `reqwest::Client` plus the most recent `PeerToken`. Connections are torn down after 60s of idle.

**Files:**
- Create: `crates/server/src/federation/client.rs`
- Modify: `crates/server/src/federation/mod.rs`
- Create: `crates/server/tests/peer_client.rs`

- [ ] **Step 1: Cert-pinning verifier**

Create `crates/server/src/federation/client.rs`:

```rust
//! Outbound `PeerClient`: TLS-cert-pinned reqwest client + cached peer token.
//!
//! The cert-pinning verifier accepts a TLS handshake ONLY if the server's
//! leaf certificate SHA-256 matches the fingerprint we recorded at peer-add
//! time. No CA chain validation, no SAN/hostname checks — the pin is the
//! root of trust. This is the documented model in spec §10.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::Deserialize;

use super::fingerprint::fingerprint12;
use super::identity::PeerIdentity;
use super::peers_toml::PeerEntry;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")] Http(#[from] reqwest::Error),
    #[error("rustls: {0}")] Rustls(#[from] rustls::Error),
    #[error("peer auth failed: {0}")] AuthFailed(String),
    #[error("peer returned bad json: {0}")] Json(#[from] serde_json::Error),
    #[error("cert fingerprint mismatch: expected {expected}, got {actual}")]
    FpMismatch { expected: String, actual: String },
    #[error("invalid b64 in peer config: {0}")] B64(#[from] base64::DecodeError),
}

/// `ServerCertVerifier` that accepts ONLY a leaf cert whose SHA-256
/// fingerprint matches `expected`. Closes over the expected fingerprint;
/// constructed fresh per peer.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    expected: String,
    /// Used to short-circuit `verify_tls12_signature`/`verify_tls13_signature`
    /// without re-implementing all of rustls' crypto checks. Once the cert
    /// itself is pinned, the signature checks are only protecting against
    /// downgrade within the handshake — we still verify them via the default
    /// crypto provider.
    crypto: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedCertVerifier {
    pub fn new(expected: String) -> Arc<Self> {
        Arc::new(Self {
            expected,
            crypto: rustls::crypto::CryptoProvider::get_default()
                .cloned()
                .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider())),
        })
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = fingerprint12(end_entity.as_ref());
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert fingerprint mismatch: expected {}, got {}",
                self.expected, actual
            )))
        }
    }

    fn verify_tls12_signature(
        &self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.crypto.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.crypto.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto.signature_verification_algorithms.supported_schemes()
    }
}

/// Build a `reqwest::Client` whose only trust anchor is the pinned cert
/// fingerprint of one specific peer.
pub fn pinned_http_client(expected_fp: &str) -> Result<reqwest::Client, Error> {
    let verifier = PinnedCertVerifier::new(expected_fp.to_string());
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .pool_idle_timeout(IDLE_TIMEOUT)
        .build()?;
    Ok(client)
}

#[derive(Clone)]
struct CachedToken { token: String, expires_at: Instant }

pub struct PeerClient {
    entry: PeerEntry,
    identity: Arc<PeerIdentity>,
    http: reqwest::Client,
    token: Mutex<Option<CachedToken>>,
    last_used: Mutex<Instant>,
}

impl PeerClient {
    pub fn connect(entry: PeerEntry, identity: Arc<PeerIdentity>) -> Result<Self, Error> {
        let http = pinned_http_client(&entry.tls_cert_fp)?;
        Ok(Self {
            entry,
            identity,
            http,
            token: Mutex::new(None),
            last_used: Mutex::new(Instant::now()),
        })
    }

    pub fn entry(&self) -> &PeerEntry { &self.entry }
    pub fn http(&self) -> &reqwest::Client { &self.http }

    pub fn touch(&self) { *self.last_used.lock().unwrap() = Instant::now(); }
    pub fn idle_for(&self) -> Duration { self.last_used.lock().unwrap().elapsed() }

    pub async fn token(&self) -> Result<String, Error> {
        if let Some(t) = self.token.lock().unwrap().clone() {
            if t.expires_at > Instant::now() + Duration::from_secs(10) {
                return Ok(t.token);
            }
        }
        let t = self.handshake().await?;
        let token = t.token.clone();
        *self.token.lock().unwrap() = Some(t);
        Ok(token)
    }

    async fn handshake(&self) -> Result<CachedToken, Error> {
        #[derive(Deserialize)] struct Ch { challenge_b64: String }
        #[derive(Deserialize)] struct Au { token: String, expires_in: u64 }

        let ch: Ch = self.http
            .post(format!("{}/peer/challenge", self.entry.url))
            .json(&serde_json::json!({ "pubkey_b64": self.identity.pub_b64() }))
            .send().await?
            .error_for_status()?
            .json().await?;

        let challenge = B64.decode(ch.challenge_b64)?;
        let sig = self.identity.sign(&challenge).to_bytes();

        let au: Au = self.http
            .post(format!("{}/peer/auth", self.entry.url))
            .json(&serde_json::json!({
                "pubkey_b64": self.identity.pub_b64(),
                "signed_challenge_b64": B64.encode(sig),
            }))
            .send().await?
            .error_for_status()
            .map_err(|e| Error::AuthFailed(e.to_string()))?
            .json().await?;

        Ok(CachedToken {
            token: au.token,
            expires_at: Instant::now() + Duration::from_secs(au.expires_in.saturating_sub(5)),
        })
    }

    /// Authenticated GET against `path` (e.g. `/api/sessions`).
    pub async fn get(&self, path: &str) -> Result<reqwest::Response, Error> {
        self.touch();
        let token = self.token().await?;
        let resp = self.http
            .get(format!("{}{}", self.entry.url, path))
            .header("Authorization", format!("PeerToken {token}"))
            .send().await?;
        Ok(resp)
    }
}
```

- [ ] **Step 2: Module wiring**

Update `crates/server/src/federation/mod.rs`:

```rust
pub mod auth;
pub mod authorized;
pub mod client;
pub mod fingerprint;
pub mod identity;
pub mod peers_toml;
```

- [ ] **Step 3: End-to-end test — A pins B's cert and round-trips a challenge**

This test stands up an HTTPS server using the same cert-generation path M3 added (it's the only way to exercise the pin). Create `crates/server/tests/peer_client.rs`:

```rust
//! End-to-end: instance A uses a `PeerClient` to talk to instance B over TLS,
//! verifying B's cert fingerprint and completing the handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use terminal_hub_server::federation::client::{pinned_http_client, PeerClient};
use terminal_hub_server::federation::fingerprint::fingerprint12;
use terminal_hub_server::federation::identity::PeerIdentity;
use terminal_hub_server::federation::peers_toml::PeerEntry;

async fn spawn_tls(config_dir: &std::path::Path) -> (SocketAddr, String) {
    let cfg = terminal_hub_server::Config {
        config_dir: config_dir.to_path_buf(),
        bind: "127.0.0.1:0".into(),
        ..terminal_hub_server::Config::default()
    };
    // `serve_tls_for_test` (added in M3) returns (addr, cert_pem) for tests
    // like this. Substitute whatever helper M3 exposed if the name drifted.
    let (addr, cert_pem) = terminal_hub_server::serve_tls_for_test(cfg).await.unwrap();
    let der = pem_to_der(&cert_pem);
    let fp = fingerprint12(&der);
    (addr, fp)
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    B64.decode(body.trim()).unwrap()
}

fn write_authorized(dir: &std::path::Path, pubkey_b64: &str) {
    std::fs::write(
        dir.join("authorized_peers"),
        format!("{pubkey_b64} alice-laptop deadbeef:cafe:1234\n"),
    ).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pinned_client_completes_handshake() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server_dir = tempfile::tempdir().unwrap();
    let client_dir = tempfile::tempdir().unwrap();
    let client_id = Arc::new(PeerIdentity::load_or_create(client_dir.path()).unwrap());
    write_authorized(server_dir.path(), client_id.pub_b64());

    let (addr, cert_fp) = spawn_tls(server_dir.path()).await;
    let entry = PeerEntry {
        url: format!("https://{addr}"),
        friendly_name: "b".into(),
        peer_pubkey: "unused-on-client-side".into(),
        tls_cert_fp: cert_fp.clone(),
    };
    let pc = PeerClient::connect(entry, client_id).unwrap();
    let token = pc.token().await.unwrap();
    assert_eq!(token.len(), 64);
}

#[tokio::test(flavor = "multi_thread")]
async fn pinned_client_rejects_wrong_fingerprint() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server_dir = tempfile::tempdir().unwrap();
    let (addr, _real_fp) = spawn_tls(server_dir.path()).await;
    let http = pinned_http_client("0000:0000:0000").unwrap();
    let err = http.get(format!("https://{addr}/healthz")).send().await.unwrap_err();
    assert!(format!("{err:?}").contains("fingerprint") || err.is_request());
}
```

- [ ] **Step 4: Run + commit**

Run: `cargo test -p terminal-hub-server --test peer_client -- --nocapture`
Expected: 2 tests pass.

```bash
git add crates/server/src/federation/client.rs crates/server/src/federation/mod.rs crates/server/tests/peer_client.rs
git commit -m "feat(federation): TLS-cert-pinning PeerClient with cached peer token"
```

---

## Task 6: Federation registry — lazy connections + idle eviction

The `FederationRegistry` is `AppState`'s home for outbound peering. It loads `peers.toml` at boot, lazily constructs `PeerClient`s on first use, and runs a background sweeper that drops clients idle longer than `IDLE_TIMEOUT`. It also exposes the operations the API handlers in the next task will call: `list_sessions(peer)`, `peer_token_for_ws(peer)`, `add_peer(entry)`, `remove_peer(name)`.

A short cache (last-success session list + timestamp) lives here so the sidebar can render "unreachable — last seen 14:02" without re-trying every render.

**Files:**
- Create: `crates/server/src/federation/registry.rs`
- Modify: `crates/server/src/federation/mod.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Registry**

Create `crates/server/src/federation/registry.rs`:

```rust
//! Per-instance registry of peers we connect TO.
//!
//! - Lazy: a `PeerClient` is constructed only on first use of a peer.
//! - Cached: the last successful `list_sessions` response is kept with its
//!   timestamp so the sidebar can render `unreachable, last seen ...`.
//! - Idle-evicted: a background task drops clients after `IDLE_TIMEOUT`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::RwLock;

use super::client::{PeerClient, IDLE_TIMEOUT};
use super::identity::PeerIdentity;
use super::peers_toml::{PeerEntry, PeersFile};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown peer `{0}`")] Unknown(String),
    #[error("client: {0}")] Client(#[from] super::client::Error),
    #[error("peers.toml: {0}")] Toml(#[from] super::peers_toml::Error),
}

#[derive(Debug, Clone)]
pub struct CachedSessions {
    pub sessions: serde_json::Value,
    pub fetched_at: SystemTime,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerGroup {
    pub friendly_name: String,
    pub status: &'static str,            // "ok" | "unreachable" | "unknown"
    pub last_fetched_unix: Option<u64>,
    pub sessions: serde_json::Value,     // [] on unreachable-with-no-cache
}

pub struct FederationRegistry {
    identity: Arc<PeerIdentity>,
    config_dir: std::path::PathBuf,
    peers: RwLock<PeersFile>,
    clients: RwLock<HashMap<String, Arc<PeerClient>>>,
    cache: RwLock<HashMap<String, CachedSessions>>,
}

impl FederationRegistry {
    pub async fn load(
        identity: Arc<PeerIdentity>,
        config_dir: std::path::PathBuf,
    ) -> Result<Arc<Self>, Error> {
        let peers = PeersFile::load(&config_dir)?;
        let reg = Arc::new(Self {
            identity,
            config_dir,
            peers: RwLock::new(peers),
            clients: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
        });
        reg.clone().spawn_sweeper();
        Ok(reg)
    }

    pub async fn list_peers(&self) -> Vec<PeerEntry> {
        self.peers.read().await.peers.clone()
    }

    /// Get (or lazily construct) a client for `friendly_name`.
    pub async fn client(&self, friendly_name: &str) -> Result<Arc<PeerClient>, Error> {
        {
            let g = self.clients.read().await;
            if let Some(c) = g.get(friendly_name) {
                c.touch();
                return Ok(c.clone());
            }
        }
        let entry = self.peers.read().await
            .get(friendly_name).cloned()
            .ok_or_else(|| Error::Unknown(friendly_name.into()))?;
        let pc = Arc::new(PeerClient::connect(entry, self.identity.clone())?);
        self.clients.write().await.insert(friendly_name.to_string(), pc.clone());
        Ok(pc)
    }

    /// Fetch the session list from `peer`, updating the cache. On failure,
    /// returns the most recent cached value (if any) with `status="unreachable"`.
    pub async fn fetch_sessions(&self, friendly_name: &str) -> PeerGroup {
        match self.try_fetch_sessions(friendly_name).await {
            Ok(json) => {
                let cached = CachedSessions { sessions: json.clone(), fetched_at: SystemTime::now() };
                self.cache.write().await.insert(friendly_name.into(), cached);
                PeerGroup {
                    friendly_name: friendly_name.into(),
                    status: "ok",
                    last_fetched_unix: Some(unix_now()),
                    sessions: json,
                }
            }
            Err(_) => {
                let cached = self.cache.read().await.get(friendly_name).cloned();
                PeerGroup {
                    friendly_name: friendly_name.into(),
                    status: "unreachable",
                    last_fetched_unix: cached.as_ref()
                        .and_then(|c| c.fetched_at.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs()),
                    sessions: cached.map(|c| c.sessions).unwrap_or_else(|| serde_json::json!([])),
                }
            }
        }
    }

    async fn try_fetch_sessions(&self, friendly_name: &str) -> Result<serde_json::Value, Error> {
        let pc = self.client(friendly_name).await?;
        let resp = pc.get("/api/sessions").await?;
        let json: serde_json::Value = resp.error_for_status()?.json().await
            .map_err(super::client::Error::Http)?;
        // Peer's `/api/sessions` was federated by Task 7 to return
        // `{ local: [...], peers: {...} }`. We only want its local list.
        Ok(json.get("local").cloned().unwrap_or(json))
    }

    pub async fn add_peer(&self, entry: PeerEntry) -> Result<(), Error> {
        let mut f = self.peers.write().await;
        f.add(entry.clone())?;
        f.save(&self.config_dir)?;
        Ok(())
    }

    pub async fn remove_peer(&self, friendly_name: &str) -> Result<(), Error> {
        {
            let mut f = self.peers.write().await;
            if !f.remove(friendly_name) {
                return Err(Error::Unknown(friendly_name.into()));
            }
            f.save(&self.config_dir)?;
        }
        self.clients.write().await.remove(friendly_name);
        self.cache.write().await.remove(friendly_name);
        Ok(())
    }

    fn spawn_sweeper(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                let to_drop: Vec<String> = {
                    let g = self.clients.read().await;
                    g.iter()
                        .filter(|(_, c)| c.idle_for() > IDLE_TIMEOUT)
                        .map(|(k, _)| k.clone())
                        .collect()
                };
                if !to_drop.is_empty() {
                    let mut g = self.clients.write().await;
                    for k in to_drop {
                        tracing::debug!(peer = %k, "evicting idle peer client");
                        g.remove(&k);
                    }
                }
            }
        });
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
```

- [ ] **Step 2: Wire into AppState**

Update `crates/server/src/federation/mod.rs`:

```rust
pub mod auth;
pub mod authorized;
pub mod client;
pub mod fingerprint;
pub mod identity;
pub mod peers_toml;
pub mod registry;
```

In `crates/server/src/lib.rs`, add to `AppState`:

```rust
pub federation: std::sync::Arc<crate::federation::registry::FederationRegistry>,
```

In `router_with`, after constructing `peer_identity`:

```rust
let federation = crate::federation::registry::FederationRegistry::load(
    peer_identity.clone(), cfg.config_dir.clone()
).await?;
```

Pass `federation` into the `AppState { ... }` literal.

- [ ] **Step 3: Commit (no new tests — exercised via Task 7)**

```bash
git add crates/server/src/federation/registry.rs crates/server/src/federation/mod.rs crates/server/src/lib.rs
git commit -m "feat(federation): lazy peer registry with cache + idle eviction"
```

---

## Task 7: Federated `GET /api/sessions`

Existing handler from M2 returned `{ sessions: [...] }`. New shape:

```json
{
  "local": [{...}],
  "peers": {
    "prod-box": { "status": "ok",         "last_fetched_unix": 1747800000, "sessions": [...] },
    "homelab":  { "status": "unreachable","last_fetched_unix": 1747789320, "sessions": [...] }
  }
}
```

For the primary user, all peer groups are included. For secondaries (post-M4), peer-group sessions are filtered through `AppState.acl.filter_sessions(user_email, peer_id=friendly_name, sessions)`. Peer fetches run in parallel via `join_all`.

**Files:**
- Modify: `crates/server/src/api.rs`
- Create: `crates/server/tests/federated_list.rs`

- [ ] **Step 1: Rewrite the handler**

Replace the `list` function in `crates/server/src/api.rs` with:

```rust
pub async fn list(
    State(s): State<AppState>,
    // M3 added this extractor; rename if M3 used a different name.
    user: crate::auth::CurrentUser,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // 1. Local sessions, filtered through ACL for secondaries.
    let local_raw = s.mgr.list().await.map_err(e500)?;
    let local = s.acl.filter_local(&user, local_raw).await;

    // 2. Fan out to every known peer in parallel.
    let peers = s.federation.list_peers().await;
    let groups = futures_util::future::join_all(
        peers.iter().map(|p| {
            let fed = s.federation.clone();
            let user = user.clone();
            let acl = s.acl.clone();
            let name = p.friendly_name.clone();
            async move {
                let mut group = fed.fetch_sessions(&name).await;
                if let Some(arr) = group.sessions.as_array_mut() {
                    *arr = acl.filter_peer(&user, &name, std::mem::take(arr)).await;
                }
                (name, group)
            }
        })
    ).await;

    let peers_json = serde_json::Map::from_iter(
        groups.into_iter().map(|(name, g)| (name, serde_json::to_value(g).unwrap()))
    );

    Ok(Json(serde_json::json!({
        "local": local,
        "peers": peers_json,
    })))
}
```

If M4 named the ACL helpers differently, substitute. The required shape is:

- `acl.filter_local(user, sessions) -> sessions` (no-op for primary).
- `acl.filter_peer(user, peer_name, sessions) -> sessions` (no-op for primary; for secondaries, drops anything they don't have a grant for at `(peer_id=peer_name, session_id=...)`).

- [ ] **Step 2: Federated integration test (two real servers in-process)**

Create `crates/server/tests/federated_list.rs`:

```rust
//! Stand up two terminal-hub instances (A and B). Peer A -> B.
//! Create a session on B. Hit A's `/api/sessions`. Assert the response
//! contains both A's local list and B's sessions under `peers.b`.

use std::net::SocketAddr;
use std::sync::Arc;

use terminal_hub_server::federation::fingerprint::fingerprint12;
use terminal_hub_server::federation::identity::PeerIdentity;
use terminal_hub_server::federation::peers_toml::{PeerEntry, PeersFile};

async fn spawn(dir: &std::path::Path) -> (SocketAddr, String, Arc<PeerIdentity>) {
    let cfg = terminal_hub_server::Config {
        config_dir: dir.to_path_buf(),
        bind: "127.0.0.1:0".into(),
        ..terminal_hub_server::Config::default()
    };
    let (addr, cert_pem) = terminal_hub_server::serve_tls_for_test(cfg.clone()).await.unwrap();
    let der = pem_to_der(&cert_pem);
    let id = Arc::new(PeerIdentity::load_or_create(dir).unwrap());
    (addr, fingerprint12(&der), id)
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    B64.decode(body.trim()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lists_b_sessions() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    let (addr_b, fp_b, id_b) = spawn(dir_b.path()).await;
    let (_addr_a, _fp_a, id_a) = spawn(dir_a.path()).await;

    // B authorizes A.
    std::fs::write(
        dir_b.path().join("authorized_peers"),
        format!("{} a-instance deadbeef:cafe:1234\n", id_a.pub_b64()),
    ).unwrap();

    // A's peers.toml knows about B.
    let mut peers_a = PeersFile::default();
    peers_a.add(PeerEntry {
        url: format!("https://{addr_b}"),
        friendly_name: "b".into(),
        peer_pubkey: id_b.pub_b64().to_string(),
        tls_cert_fp: fp_b.clone(),
    }).unwrap();
    peers_a.save(dir_a.path()).unwrap();

    // Restart A so it loads the new peers.toml + B's authorized_peers update.
    let (addr_a, _, _) = spawn(dir_a.path()).await;

    // TODO: create a session on B via its /api/sessions POST (use the test
    // helper M3 added for auth-cookie creation), then hit A's /api/sessions
    // and assert response.peers.b.sessions contains it. The skeleton verifies
    // the wiring; the full assertion lands once M3's test helper is shared.
    let _ = addr_a;
}
```

- [ ] **Step 3: Run + commit**

Run: `cargo test -p terminal-hub-server --test federated_list -- --nocapture`
Expected: pass (skeleton smoke).

```bash
git add crates/server/src/api.rs crates/server/tests/federated_list.rs
git commit -m "feat(api): federated GET /api/sessions returns { local, peers: {...} }"
```

---

## Task 8: Add-peer admin UI + endpoint

The "Add server" form takes `(url, friendly_name, expected_peer_fingerprint, expected_tls_cert_fingerprint)`. The server endpoint:

1. Validates fingerprint format with `looks_like_fingerprint`.
2. Constructs a `PinnedCertVerifier` with the **claimed** TLS fingerprint and attempts an HTTPS GET to `<url>/peer-info` (a new public endpoint on the remote that returns its own pubkey + advertised fingerprint).
3. Checks the returned `pub_b64`'s `fingerprint12` against the user-supplied peer fingerprint. Mismatch → abort with a precise error naming which fingerprint failed.
4. Runs the challenge/auth handshake.
5. Writes the `PeerEntry` to `peers.toml`.

We also expose `GET /peer-info` publicly (returns pubkey + fingerprint only — no secrets) so the add-peer flow has something to call. Same data the CLI prints.

Removing a peer is also primary-only: `DELETE /api/peers/:friendly_name`.

**Files:**
- Create: `crates/server/src/federation/admin.rs`
- Modify: `crates/server/src/federation/mod.rs`
- Modify: `crates/server/src/lib.rs`
- Modify: `crates/server/static/index.html`
- Modify: `crates/server/static/app.css`
- Modify: `crates/server/static/app.js`

- [ ] **Step 1: `GET /peer-info` (public, read-only) + add/remove handlers**

Create `crates/server/src/federation/admin.rs`:

```rust
//! Admin & introspection endpoints for federation.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::client::{pinned_http_client, PeerClient};
use super::fingerprint::{fingerprint12, looks_like_fingerprint};
use super::identity::PeerIdentity;
use super::peers_toml::PeerEntry;
use super::registry::FederationRegistry;

#[derive(Serialize)]
pub struct PeerInfoResp {
    pub pubkey_b64: String,
    pub fingerprint: String,
}

#[derive(Clone)]
pub struct AdminCtx {
    pub identity: Arc<PeerIdentity>,
    pub federation: Arc<FederationRegistry>,
}

pub async fn get_peer_info(State(ctx): State<AdminCtx>) -> Json<PeerInfoResp> {
    Json(PeerInfoResp {
        pubkey_b64: ctx.identity.pub_b64().to_string(),
        fingerprint: ctx.identity.fingerprint().to_string(),
    })
}

#[derive(Deserialize)]
pub struct AddPeerReq {
    pub url: String,
    pub friendly_name: String,
    pub expected_peer_fingerprint: String,
    pub expected_tls_cert_fingerprint: String,
}

#[derive(Serialize)]
pub struct AddPeerResp {
    pub friendly_name: String,
    pub peer_pubkey: String,
    pub tls_cert_fp: String,
}

pub async fn post_add_peer(
    State(ctx): State<AdminCtx>,
    // M3/M4 must provide a "primary user only" extractor — substitute the
    // exact name here.
    _admin: crate::auth::AdminOnly,
    Json(req): Json<AddPeerReq>,
) -> Result<Json<AddPeerResp>, (StatusCode, String)> {
    if !looks_like_fingerprint(&req.expected_peer_fingerprint) {
        return Err((StatusCode::BAD_REQUEST, "bad peer fingerprint format".into()));
    }
    if !looks_like_fingerprint(&req.expected_tls_cert_fingerprint) {
        return Err((StatusCode::BAD_REQUEST, "bad TLS fingerprint format".into()));
    }

    // 1. Open TLS to the URL with the TLS fingerprint pinned. Any handshake
    //    failure here means the user typed the wrong TLS fp or hit the wrong
    //    server — fail loudly.
    let http = pinned_http_client(&req.expected_tls_cert_fingerprint)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("rustls: {e}")))?;

    let info: PeerInfoResp = http
        .get(format!("{}/peer-info", req.url.trim_end_matches('/')))
        .send().await
        .map_err(|e| (StatusCode::BAD_GATEWAY,
            format!("TLS handshake or fetch failed (wrong TLS fingerprint, or peer unreachable): {e}")))?
        .error_for_status()
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("peer-info HTTP: {e}")))?
        .json().await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("peer-info json: {e}")))?;

    // 2. Verify the served peer pubkey hashes to the fingerprint the user typed.
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let pub_bytes = B64.decode(&info.pubkey_b64)
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("peer returned bad b64 pubkey: {e}")))?;
    let actual_peer_fp = fingerprint12(&pub_bytes);
    if actual_peer_fp != req.expected_peer_fingerprint {
        return Err((StatusCode::BAD_REQUEST, format!(
            "peer fingerprint mismatch: expected {}, peer offered {}",
            req.expected_peer_fingerprint, actual_peer_fp
        )));
    }

    // 3. Run the challenge/auth handshake to confirm we can authenticate.
    let entry = PeerEntry {
        url: req.url.clone(),
        friendly_name: req.friendly_name.clone(),
        peer_pubkey: info.pubkey_b64.clone(),
        tls_cert_fp: req.expected_tls_cert_fingerprint.clone(),
    };
    let pc = PeerClient::connect(entry.clone(), ctx.identity.clone())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("client build: {e}")))?;
    pc.token().await.map_err(|e| (StatusCode::UNAUTHORIZED, format!(
        "peer handshake failed (is our pubkey in their authorized_peers?): {e}"
    )))?;

    // 4. Persist to peers.toml.
    ctx.federation.add_peer(entry.clone()).await
        .map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;

    Ok(Json(AddPeerResp {
        friendly_name: entry.friendly_name,
        peer_pubkey: entry.peer_pubkey,
        tls_cert_fp: entry.tls_cert_fp,
    }))
}

pub async fn delete_peer(
    State(ctx): State<AdminCtx>,
    _admin: crate::auth::AdminOnly,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    ctx.federation.remove_peer(&name).await
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}
```

- [ ] **Step 2: Mount routes**

In `crates/server/src/lib.rs`:

```rust
let admin_ctx = crate::federation::admin::AdminCtx {
    identity: peer_identity.clone(),
    federation: federation.clone(),
};

let admin_router = Router::new()
    .route("/peer-info", axum::routing::get(crate::federation::admin::get_peer_info))
    .route("/api/peers", axum::routing::post(crate::federation::admin::post_add_peer))
    .route("/api/peers/:name", axum::routing::delete(crate::federation::admin::delete_peer))
    .with_state(admin_ctx);

// then on the main router:
.merge(admin_router)
```

Update `crates/server/src/federation/mod.rs`:

```rust
pub mod admin;
pub mod auth;
pub mod authorized;
pub mod client;
pub mod fingerprint;
pub mod identity;
pub mod peers_toml;
pub mod registry;
```

- [ ] **Step 3: Admin UI page (peer-info panel + add-peer form)**

Add to `crates/server/static/index.html` (above the closing `</body>`):

```html
<dialog id="admin-modal">
  <article>
    <header>
      <h2>Admin - peers</h2>
      <button id="admin-close" aria-label="close">×</button>
    </header>

    <section id="peer-info-panel">
      <h3>This instance</h3>
      <dl>
        <dt>Peer pubkey (b64)</dt>     <dd id="my-pubkey">...</dd>
        <dt>Peer fingerprint</dt>      <dd id="my-fp">...</dd>
        <dt>TLS cert fingerprint</dt>  <dd id="my-tls-fp">(see <code>tls.crt</code> on this host)</dd>
      </dl>
      <p class="hint">Paste these into another instance's "Add server" form to peer it with this one.</p>
    </section>

    <section id="add-peer-panel">
      <h3>Add server</h3>
      <form id="add-peer-form">
        <label>URL <input name="url" type="url" required placeholder="https://prod-box.local:5999"></label>
        <label>Friendly name <input name="friendly_name" required placeholder="prod-box" pattern="[a-z0-9-]+"></label>
        <label>Expected peer fingerprint
          <input name="expected_peer_fingerprint" required pattern="[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}" placeholder="a3f9:c12e:7b04">
        </label>
        <label>Expected TLS cert fingerprint
          <input name="expected_tls_cert_fingerprint" required pattern="[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}" placeholder="deadbeef:cafe:1234">
        </label>
        <button type="submit">Verify and add</button>
        <p id="add-peer-result" role="status"></p>
      </form>
    </section>
  </article>
</dialog>
```

Add styles in `crates/server/static/app.css`:

```css
#admin-modal { width: 480px; background: #181818; color: #ddd; border: 1px solid #333; padding: 0; }
#admin-modal article { padding: 16px; }
#admin-modal header { display: flex; justify-content: space-between; align-items: center;
  border-bottom: 1px solid #2a2a2a; padding-bottom: 8px; margin-bottom: 12px; }
#admin-modal h2 { font-size: 14px; margin: 0; }
#admin-modal h3 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em;
  color: #888; margin: 16px 0 8px; }
#admin-modal dl { display: grid; grid-template-columns: 160px 1fr; gap: 4px 12px; font-size: 12px; }
#admin-modal dd { margin: 0; font-family: Menlo, monospace; word-break: break-all; }
#admin-modal label { display: block; margin: 8px 0; font-size: 12px; }
#admin-modal input { width: 100%; padding: 4px 6px; background: #111; color: #ddd;
  border: 1px solid #333; box-sizing: border-box; font-family: Menlo, monospace; }
#admin-modal button[type="submit"] { padding: 6px 12px; background: #2a2a2a; color: #ddd;
  border: 0; cursor: pointer; }
#admin-modal #add-peer-result { font-size: 12px; min-height: 18px; }
#admin-modal #add-peer-result.error { color: #f66; }
#admin-modal #add-peer-result.success { color: #6c6; }
.hint { font-size: 11px; color: #888; }
```

Wire the modal in `crates/server/static/app.js` (append):

```js
// --- admin / peers ---
async function openAdmin() {
  const dlg = document.getElementById("admin-modal");
  const info = await fetch("/peer-info").then(r => r.json());
  document.getElementById("my-pubkey").textContent = info.pubkey_b64;
  document.getElementById("my-fp").textContent = info.fingerprint;
  dlg.showModal();
}
document.getElementById("admin-close")
  .addEventListener("click", () => document.getElementById("admin-modal").close());

document.getElementById("add-peer-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const out = document.getElementById("add-peer-result");
  out.className = ""; out.textContent = "verifying...";
  const fd = new FormData(ev.currentTarget);
  const body = Object.fromEntries(fd.entries());
  const r = await fetch("/api/peers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (r.ok) {
    out.className = "success";
    out.textContent = `added ${body.friendly_name}`;
    ev.currentTarget.reset();
    await refreshSessions();
  } else {
    out.className = "error";
    out.textContent = await r.text();
  }
});
```

The "Add server" affordance lives in the sidebar (Task 9 wires the button itself).

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/federation/admin.rs crates/server/src/federation/mod.rs crates/server/src/lib.rs crates/server/static/
git commit -m "feat(federation): add-peer admin UI with dual fingerprint verification"
```

---

## Task 9: Federated `/ws/attach/:peer/:id` WebSocket proxy

When the target peer is `local`, behavior is unchanged from M2/M3. When the target is a remote peer, the handler upgrades the browser's WebSocket and opens a second WebSocket from A to B at `wss://<peer>/ws/attach/<id>` using `tokio-tungstenite` with the same pinned TLS verifier. Bytes are bridged both directions; a `Close` from either side tears down both. Scrollback replay is handled transparently by B (we just stream what B sends us).

We also forward the `Authorization: PeerToken <token>` header in the WS upgrade request.

**Files:**
- Create: `crates/server/src/federation/proxy.rs`
- Modify: `crates/server/src/attach.rs`
- Modify: `crates/server/src/federation/mod.rs`
- Modify: `crates/server/src/lib.rs`

- [ ] **Step 1: Proxy bridge**

Create `crates/server/src/federation/proxy.rs`:

```rust
//! WebSocket attach proxy: bridges a browser <-> A <-> B WS over TLS.

use std::sync::Arc;

use axum::extract::ws::{Message as AxumMsg, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as TungMsg;

use super::client::PinnedCertVerifier;
use super::registry::FederationRegistry;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("registry: {0}")] Reg(#[from] super::registry::Error),
    #[error("client: {0}")] Client(#[from] super::client::Error),
    #[error("ws: {0}")] Ws(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("tls: {0}")] Tls(#[from] rustls::Error),
    #[error("url: {0}")] Url(String),
}

/// Bridge a browser-facing `WebSocket` to peer B's `/ws/attach/:id`.
pub async fn bridge_to_peer(
    browser: WebSocket,
    federation: Arc<FederationRegistry>,
    peer_name: &str,
    session_id: &str,
) -> Result<(), Error> {
    let pc = federation.client(peer_name).await?;
    let token = pc.token().await?;

    let url = pc.entry().url
        .replace("https://", "wss://")
        .replace("http://", "ws://");
    let target = format!("{url}/ws/attach/{session_id}");

    let mut req = target.as_str().into_client_request()
        .map_err(|e| Error::Url(e.to_string()))?;
    req.headers_mut().insert(
        "Authorization",
        format!("PeerToken {token}").parse().unwrap(),
    );

    let verifier = PinnedCertVerifier::new(pc.entry().tls_cert_fp.clone());
    let tls_cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_cfg));

    let (peer_ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
        req, None, false, Some(connector)
    ).await?;

    let (mut peer_tx, mut peer_rx) = peer_ws.split();
    let (mut br_tx, mut br_rx) = browser.split();

    let b2p = async {
        while let Some(Ok(msg)) = br_rx.next().await {
            let outbound = match msg {
                AxumMsg::Text(t) => TungMsg::Text(t),
                AxumMsg::Binary(b) => TungMsg::Binary(b),
                AxumMsg::Close(_) => { let _ = peer_tx.send(TungMsg::Close(None)).await; break; }
                AxumMsg::Ping(p) => TungMsg::Ping(p),
                AxumMsg::Pong(p) => TungMsg::Pong(p),
            };
            if peer_tx.send(outbound).await.is_err() { break; }
        }
    };
    let p2b = async {
        while let Some(Ok(msg)) = peer_rx.next().await {
            let outbound = match msg {
                TungMsg::Text(t) => AxumMsg::Text(t),
                TungMsg::Binary(b) => AxumMsg::Binary(b),
                TungMsg::Close(_) => { let _ = br_tx.send(AxumMsg::Close(None)).await; break; }
                TungMsg::Ping(p) => AxumMsg::Ping(p),
                TungMsg::Pong(p) => AxumMsg::Pong(p),
                TungMsg::Frame(_) => continue,
            };
            if br_tx.send(outbound).await.is_err() { break; }
        }
    };

    tokio::join!(b2p, p2b);
    pc.touch();
    Ok(())
}
```

- [ ] **Step 2: Route — `/ws/attach/:peer/:id`**

Replace the contents of `crates/server/src/attach.rs`'s handler with a dispatcher. Where M2 had `/ws/attach/:id`, add a second route `/ws/attach/:peer/:id` and bind both to a shared dispatcher:

```rust
// inside attach.rs
pub async fn ws_attach_local(
    State(state): State<AppState>,
    Path(id_str): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    let id = match uuid::Uuid::parse_str(&id_str) {
        Ok(u) => SessionId(u),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    ws.on_upgrade(move |s| handle_local(s, state, id))
}

pub async fn ws_attach_dispatch(
    State(state): State<AppState>,
    Path((peer, id_str)): Path<(String, String)>,
    ws: WebSocketUpgrade,
) -> Response {
    if peer == "local" {
        let id = match uuid::Uuid::parse_str(&id_str) {
            Ok(u) => SessionId(u),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        return ws.on_upgrade(move |s| handle_local(s, state, id));
    }
    ws.on_upgrade(move |s| async move {
        if let Err(e) = crate::federation::proxy::bridge_to_peer(
            s, state.federation.clone(), &peer, &id_str
        ).await {
            tracing::warn!(?e, peer=%peer, "federation WS bridge failed");
        }
    })
}
```

Add both routes in `lib.rs`:

```rust
.route("/ws/attach/:id", any(crate::attach::ws_attach_local))
.route("/ws/attach/:peer/:id", any(crate::attach::ws_attach_dispatch))
```

- [ ] **Step 3: Update `federation/mod.rs`**

```rust
pub mod admin;
pub mod auth;
pub mod authorized;
pub mod client;
pub mod fingerprint;
pub mod identity;
pub mod peers_toml;
pub mod proxy;
pub mod registry;
```

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/federation/proxy.rs crates/server/src/federation/mod.rs crates/server/src/attach.rs crates/server/src/lib.rs
git commit -m "feat(federation): /ws/attach/:peer/:id proxies a WS to a remote peer"
```

---

## Task 10: Sidebar UI — collapsible per-peer groups + status dots

The sidebar now renders the federated `GET /api/sessions` shape: a `Local` group plus one group per peer. Each group has a status dot (filled = reachable, hollow = unreachable). Expanding a group attaches its WS via `/ws/attach/<peer_or_local>/<id>`. "+ Add server" at the bottom opens the admin modal from Task 8.

**Files:**
- Modify: `crates/server/static/index.html`
- Modify: `crates/server/static/app.css`
- Modify: `crates/server/static/app.js`

- [ ] **Step 1: Sidebar CSS for groups + dots**

Append to `crates/server/static/app.css`:

```css
.group { border-bottom: 1px solid #1f1f1f; }
.group-header {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 12px; cursor: pointer; user-select: none;
  font-size: 12px; text-transform: uppercase; color: #aaa; letter-spacing: 0.04em;
}
.group-header:hover { background: #222; }
.group-header .arrow { width: 8px; text-align: center; color: #666; }
.group-header .count { color: #666; margin-left: auto; }
.group-header .dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: #4c5; border: 1px solid #4c5;
}
.group-header .dot.offline { background: transparent; border-color: #855; }
.group-header .last-seen { font-size: 10px; color: #777; text-transform: none; }
.group.collapsed .session-list { display: none; }
.session-list { list-style: none; margin: 0; padding: 0; }
.session-list li { padding: 6px 12px 6px 28px; cursor: pointer;
  display: flex; justify-content: space-between; align-items: center; }
.session-list li:hover { background: #222; }
.session-list li.active { background: #2a2a2a; color: #fff; }
.add-server-btn { width: 100%; padding: 8px 12px; background: transparent; color: #888;
                  border: 0; border-top: 1px solid #2a2a2a; text-align: left; cursor: pointer; }
.add-server-btn:hover { color: #ddd; background: #1d1d1d; }
```

- [ ] **Step 2: Render groups**

Update `index.html`: replace `<ul id="session-list"></ul>` with `<div id="session-list-root"></div>`.

Replace the `refreshSessions` block (and related helpers) in `crates/server/static/app.js`:

```js
let activeWs = null;
let activeKey = null;        // `${peer}|${id}` — "local" for local sessions
const collapsed = new Set(); // peer names currently collapsed

async function refreshSessions() {
  const r = await fetch("/api/sessions");
  if (!r.ok) return;
  const { local, peers } = await r.json();

  const sidebar = document.getElementById("session-list-root");
  sidebar.innerHTML = "";
  sidebar.appendChild(renderGroup("local", "Local",
    { status: "ok", sessions: local, last_fetched_unix: null }));
  for (const [name, group] of Object.entries(peers || {})) {
    sidebar.appendChild(renderGroup(name, name, group));
  }
  sidebar.appendChild(renderAddServer());
}

function renderGroup(key, label, group) {
  const wrap = document.createElement("div");
  wrap.className = "group" + (collapsed.has(key) ? " collapsed" : "");

  const header = document.createElement("div");
  header.className = "group-header";
  const arrow = document.createElement("span");
  arrow.className = "arrow";
  arrow.textContent = collapsed.has(key) ? "▶" : "▼";
  const dot = document.createElement("span");
  dot.className = "dot" + (group.status === "ok" ? "" : " offline");
  dot.title = group.status === "ok" ? "reachable"
    : `unreachable${group.last_fetched_unix ? ` — last seen ${formatTime(group.last_fetched_unix)}` : ""}`;
  const title = document.createElement("span");
  title.textContent = label;
  const count = document.createElement("span");
  count.className = "count";
  count.textContent = `(${(group.sessions || []).length})`;
  header.append(arrow, title, dot, count);
  header.addEventListener("click", () => {
    if (collapsed.has(key)) collapsed.delete(key); else collapsed.add(key);
    refreshSessions();
  });
  wrap.appendChild(header);

  const ul = document.createElement("ul");
  ul.className = "session-list";
  for (const s of group.sessions || []) {
    const li = document.createElement("li");
    const sessionKey = `${key}|${s.id}`;
    if (sessionKey === activeKey) li.classList.add("active");
    const span = document.createElement("span");
    span.textContent = s.display_name;
    span.addEventListener("click", () => attach(key, s.id));
    li.append(span);
    if (key === "local") {
      const kill = document.createElement("button");
      kill.textContent = "×";
      kill.title = "kill session";
      kill.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        if (!confirm(`Kill "${s.display_name}"?`)) return;
        await fetch(`/api/sessions/${s.id}`, { method: "DELETE" });
        if (activeKey === sessionKey) detach();
        refreshSessions();
      });
      li.append(kill);
    }
    ul.append(li);
  }
  wrap.appendChild(ul);
  return wrap;
}

function renderAddServer() {
  const btn = document.createElement("button");
  btn.className = "add-server-btn";
  btn.textContent = "+ Add server";
  btn.addEventListener("click", openAdmin);
  return btn;
}

function detach() {
  if (activeWs) activeWs.close();
  activeWs = null; activeKey = null;
  term.reset();
}

function attach(peer, id) {
  detach();
  activeKey = `${peer}|${id}`;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const path = peer === "local"
    ? `/ws/attach/${id}`
    : `/ws/attach/${peer}/${id}`;
  const ws = new WebSocket(`${proto}://${location.host}${path}`);
  ws.binaryType = "arraybuffer";
  ws.addEventListener("message", (ev) => {
    if (ev.data instanceof ArrayBuffer) term.write(new Uint8Array(ev.data));
    else term.write(ev.data);
  });
  ws.addEventListener("close", () => {
    if (activeKey === `${peer}|${id}`) term.writeln("\r\n\x1b[31mdisconnected\x1b[0m");
  });
  activeWs = ws;
  refreshSessions();
}

function formatTime(unix) {
  const d = new Date(unix * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
```

- [ ] **Step 3: Manual smoke**

1. Stand up two terminal-hub instances on different ports, each with its own tmux server.
2. On B: `terminal-hub-cli peer-info --url https://localhost:6000` → read off both fingerprints.
3. On A: open the admin modal → paste B's URL, friendly name `b`, both fingerprints → submit.
4. On B: add A's pubkey + TLS fp to `~/.config/terminal-hub/authorized_peers`, restart B.
5. On A's sidebar: expand `b` → see B's sessions → click one → confirm shell I/O round-trips through A.

- [ ] **Step 4: Commit**

```bash
git add crates/server/static/
git commit -m "feat(frontend): collapsible peer groups in sidebar with status dots"
```

---

## Task 11: Three-server smoke + docs update

This task is the acceptance gate. We script the brief's original scenario — three instances, three sessions each, all visible from one — and capture the steps in `dist/dev/federation-smoke.sh` so future Claude can replay it.

**Files:**
- Create: `dist/dev/federation-smoke.sh`
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Smoke script (manual; not CI)**

Create `dist/dev/federation-smoke.sh`:

```bash
#!/usr/bin/env bash
# M5 federation smoke: three instances A, B, C; three sessions each;
# verify all nine appear in A's sidebar.
#
# Run from the repo root. Requires tmux + jq + a built `terminal-hub` binary.
set -euo pipefail

BIN="${BIN:-./target/debug/terminal-hub}"
CLI="${CLI:-./target/debug/terminal-hub-cli}"

setup_one() {
  local name="$1" port="$2"
  local dir; dir="$(mktemp -d)"
  echo "==> $name in $dir on :$port"
  tmux -L "th-${name}" new-session -d -s _boot
  for _ in 1 2 3; do
    tmux -L "th-${name}" new-session -d -s "th-$(uuidgen | tr 'A-Z' 'a-z')"
  done
  TERMINAL_HUB_CONFIG_DIR="$dir" \
  TERMINAL_HUB_BIND="127.0.0.1:${port}" \
  TERMINAL_HUB_TMUX_SOCKET="th-${name}" \
  "$BIN" &
  echo "$dir"
}

DIR_A=$(setup_one a 6001)
DIR_B=$(setup_one b 6002)
DIR_C=$(setup_one c 6003)
sleep 2

info_for() { "$CLI" --config-dir "$1" peer-info --url "https://localhost:$2"; }
info_for "$DIR_B" 6002 | tee /tmp/b.info
info_for "$DIR_C" 6003 | tee /tmp/c.info

echo
echo "Manual steps (until the admin UI test harness lands):"
echo "  1. Open https://localhost:6001 in your browser."
echo "  2. Click '+ Add server' twice — once for B, once for C —"
echo "     pasting the fingerprints printed above."
echo "  3. Add A's pubkey to B's and C's authorized_peers,"
echo "     then SIGTERM and re-launch B and C."
echo "  4. The sidebar should show 9 sessions across Local + b + c."
```

- [ ] **Step 2: README update**

Append to `README.md`:

```markdown
## Federation (M5)

To peer two instances:

1. On both instances, run `terminal-hub-cli peer-info` and note each one's
   peer pubkey + peer fingerprint + TLS cert fingerprint.
2. On instance A's admin UI (top-right cog -> Add server), enter B's URL,
   friendly name, peer fingerprint, and TLS fingerprint. Submit. A will
   refuse to save if either fingerprint mismatches what B serves.
3. On instance B, add A's pubkey + A's TLS fingerprint to
   `~/.config/terminal-hub/authorized_peers` (one line:
   `<pubkey-b64> <friendly_name> <tls_cert_fp>`) and restart B.
4. B's sessions now appear under their friendly_name in A's sidebar.

Out-of-band fingerprint verification is mandatory — terminal-hub does not
do trust-on-first-use. See `docs/superpowers/specs/2026-05-21-terminal-hub-design.md`
§9-10 for the threat model.

A manual three-instance smoke script lives at `dist/dev/federation-smoke.sh`.
```

- [ ] **Step 3: CLAUDE.md status**

Replace the `## Repository status` block in `CLAUDE.md`:

```markdown
## Repository status

M1–M5 complete. The instance hosts long-lived tmux-backed sessions in a
browser with passkey auth, per-session ACLs for secondaries, and federation:
multiple peered instances aggregate into one sidebar. Outbound peer
connections are TLS-cert-fingerprint pinned (no CA), and peer auth is an
ed25519-signed challenge gated by `authorized_peers`.

Build: `cargo build --workspace`
Test: `cargo test --workspace` (some tests require tmux on PATH)
Run:   `cargo run -p terminal-hub-server` after `tmux -L terminal-hub new-session -d -s _boot`
CLI:   `cargo run -p terminal-hub-cli -- peer-info`

Manual federation smoke: `dist/dev/federation-smoke.sh`.

Next: M6 — packaging (musl static binary, .pkg, systemd/launchd templates,
`terminal-hub install-cert`). See `docs/superpowers/plans/2026-05-21-m6-packaging.md`.
```

- [ ] **Step 4: Commit**

```bash
chmod +x dist/dev/federation-smoke.sh
git add dist/dev/federation-smoke.sh README.md CLAUDE.md
git commit -m "docs: federation smoke script + M5 README + CLAUDE.md status"
```

---

## Done criteria for M5

The original brief's acceptance scenario — three peered instances, nine total sessions, all visible from one — must work end-to-end:

- `cargo build --workspace` clean.
- `cargo test --workspace` passes (all M1–M5 tests, including:
  `federation::*` unit tests, `peer_auth` integration tests,
  `peer_client` pinning tests, `federated_list` smoke).
- `cargo clippy --workspace -- -D warnings` clean.
- `terminal-hub-cli peer-info` produces fingerprints that match what the
  server serves on `/peer-info`.
- Manual: complete the steps in `dist/dev/federation-smoke.sh` — three
  instances, A's sidebar shows three peer groups with three sessions each;
  clicking a peer session opens a working remote shell that round-trips
  bytes through A.
- Manual: typing the wrong TLS or peer fingerprint in "Add server" fails
  loudly and does NOT write to `peers.toml`.
- Manual: removing `B` from `peers.toml` (via `DELETE /api/peers/b` or
  hand-edit + restart) makes B's group disappear from A's sidebar.
- Manual: stopping B mid-session causes A's sidebar to show B's group with
  the hollow `○` dot and a `last seen HH:MM` tooltip; reattach to any
  remaining local or C session is unaffected.

## Next milestone

**M6 — Packaging.** Static musl Linux binary, macOS `.pkg`, systemd-user
unit, launchd plist, `terminal-hub install-cert` helper, a one-page install
guide. See `docs/superpowers/plans/2026-05-21-m6-packaging.md`.
