//! `peers.toml` file: peers we connect TO.
//!
//! TOML schema:
//!
//! ```toml
//! [[peer]]
//! url           = "https://peer.example:5999/"
//! friendly_name = "prod-box"
//! peer_pubkey   = "<base64>"
//! tls_cert_fp   = "aaaa:bbbb:cccc"
//! ```
//!
//! Hand-editable AND UI-writable. Round-trips via serde+toml — preserving
//! comments is out of scope (the UI is authoritative; hand edits are merged
//! on the next reload).

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    pub url: String,
    pub friendly_name: String,
    pub peer_pubkey: String,
    pub tls_cert_fp: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PeersConfig {
    #[serde(default, rename = "peer")]
    pub peers: Vec<PeerEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("toml serialize: {0}")]
    Ser(#[from] toml::ser::Error),
}

/// Load `peers.toml`; missing file => empty config (no outbound peers).
pub fn load(path: &Path) -> Result<PeersConfig, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PeersConfig::default()),
        Err(e) => return Err(Error::Io(e)),
    };
    Ok(toml::from_str(&text)?)
}

/// Write `peers.toml` atomically (write to `peers.toml.tmp` then rename).
pub fn save(path: &Path, cfg: &PeersConfig) -> Result<(), Error> {
    let text = toml::to_string_pretty(cfg)?;
    let tmp = path.with_extension("toml.tmp");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PeersConfig {
        PeersConfig {
            peers: vec![
                PeerEntry {
                    url: "https://prod-box.local:5999/".into(),
                    friendly_name: "prod-box".into(),
                    peer_pubkey: "AAAAPUBKEYBASE64".into(),
                    tls_cert_fp: "aaaa:bbbb:cccc".into(),
                },
                PeerEntry {
                    url: "https://homelab.local:5999/".into(),
                    friendly_name: "homelab".into(),
                    peer_pubkey: "BBBBOTHERKEY".into(),
                    tls_cert_fp: "dddd:eeee:ffff".into(),
                },
            ],
        }
    }

    #[test]
    fn loads_missing_as_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("peers.toml");
        let c = load(&p).unwrap();
        assert!(c.peers.is_empty());
    }

    #[test]
    fn round_trips_through_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("peers.toml");
        let original = sample();
        save(&p, &original).unwrap();
        let reloaded = load(&p).unwrap();
        assert_eq!(reloaded.peers, original.peers);
    }

    #[test]
    fn save_creates_missing_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("nested/a/b/peers.toml");
        save(&p, &sample()).unwrap();
        assert!(p.exists());
    }
}
