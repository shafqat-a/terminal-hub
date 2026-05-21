//! `authorized_peers` file: peers we accept connections FROM.
//!
//! Line format (one per line):
//!
//! ```text
//! <base64_pubkey> <friendly_name> <tls_cert_fp>
//! ```
//!
//! Blank lines and lines starting with `#` are ignored. Friendly_name and
//! tls_cert_fp must be whitespace-free. Missing file => no inbound peers
//! trusted (empty map). M5 MVP loads this once at boot — no hot reload.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPeer {
    pub pubkey_b64: String,
    pub friendly_name: String,
    pub tls_cert_fp: String,
}

/// Map keyed by `pubkey_b64` for fast lookup at handshake time.
pub type AuthorizedPeers = HashMap<String, AuthorizedPeer>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{path}:{line}: expected 3 whitespace-separated fields, got {got}")]
    BadFields { path: String, line: usize, got: usize },
}

/// Load the file, returning an empty map if it doesn't exist.
pub fn load(path: &Path) -> Result<AuthorizedPeers, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(Error::Io(e)),
    };
    parse(&text, path.display().to_string())
}

fn parse(text: &str, source: String) -> Result<AuthorizedPeers, Error> {
    let mut out = AuthorizedPeers::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(Error::BadFields {
                path: source.clone(),
                line: i + 1,
                got: parts.len(),
            });
        }
        out.insert(
            parts[0].to_string(),
            AuthorizedPeer {
                pubkey_b64: parts[0].to_string(),
                friendly_name: parts[1].to_string(),
                tls_cert_fp: parts[2].to_string(),
            },
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn loads_missing_file_as_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("authorized_peers");
        let m = load(&p).unwrap();
        assert!(m.is_empty());
    }

    #[test]
    fn parses_lines_and_skips_comments() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "# this is a comment").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "AAAA_PUB_A friendly-a aaaa:bbbb:cccc").unwrap();
        writeln!(f, "AAAA_PUB_B friendly-b dddd:eeee:ffff").unwrap();
        let m = load(f.path()).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m["AAAA_PUB_A"].friendly_name, "friendly-a");
        assert_eq!(m["AAAA_PUB_B"].tls_cert_fp, "dddd:eeee:ffff");
    }

    #[test]
    fn rejects_malformed_line() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "only-two-fields whoops").unwrap();
        let err = load(f.path()).unwrap_err();
        assert!(matches!(err, Error::BadFields { line: 1, got: 2, .. }));
    }
}
