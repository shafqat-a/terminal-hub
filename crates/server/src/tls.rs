//! Generates a self-signed TLS cert on first boot and writes it to the config dir.
//!
//! On macOS / Linux, the key file is chmod 0600 so the server refuses to start
//! later if the user has loosened it.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::path::Path;

pub struct CertFiles {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Loaded cert + key (PEM strings) plus the disk locations they live at.
pub struct TlsMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_path: std::path::PathBuf,
    pub key_path: std::path::PathBuf,
}

pub fn ensure(
    cert_path: &Path,
    key_path: &Path,
    hostnames: &[String],
) -> anyhow::Result<CertFiles> {
    if cert_path.exists() && key_path.exists() {
        check_key_perms(key_path)?;
        let cert_pem = std::fs::read_to_string(cert_path)?;
        let key_pem = std::fs::read_to_string(key_path)?;
        return Ok(CertFiles { cert_pem, key_pem });
    }

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(hostnames.to_vec())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "terminal-hub");
    dn.push(DnType::OrganizationName, "terminal-hub");
    params.distinguished_name = dn;
    for h in hostnames {
        if h.parse::<std::net::IpAddr>().is_ok() {
            params
                .subject_alt_names
                .push(SanType::IpAddress(h.parse()?));
        } else {
            params.subject_alt_names.push(SanType::DnsName(h.parse()?));
        }
    }
    // ten years; rotation procedure documented in §10 of the spec.
    params.not_after = rcgen::date_time_ymd(2036, 1, 1);

    let cert = params.self_signed(&key)?;
    let cert_pem = cert.pem();
    let key_pem = key.serialize_pem();

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_path, &cert_pem)?;
    std::fs::write(key_path, &key_pem)?;
    set_key_perms(key_path)?;

    Ok(CertFiles { cert_pem, key_pem })
}

/// Convenience wrapper that returns both the PEMs and the paths they were
/// loaded/created at. Server boot uses this; tests use `ensure` directly.
pub fn ensure_material(
    cert_path: &Path,
    key_path: &Path,
    hostnames: &[String],
) -> anyhow::Result<TlsMaterial> {
    let files = ensure(cert_path, key_path, hostnames)?;
    Ok(TlsMaterial {
        cert_pem: files.cert_pem,
        key_pem: files.key_pem,
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
    })
}

#[cfg(unix)]
fn set_key_perms(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(p)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(p, perms)
}

#[cfg(not(unix))]
fn set_key_perms(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn check_key_perms(p: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(p)?.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode & 0o077 == 0,
        "TLS key {} is world/group readable (mode {:o}); chmod 600",
        p.display(),
        mode
    );
    Ok(())
}

#[cfg(not(unix))]
fn check_key_perms(_p: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// SHA-256 fingerprint of the DER-encoded cert, formatted as colon-hex.
pub fn fingerprint(cert_pem: &str) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let pem = pem::parse(cert_pem.as_bytes())?;
    let mut h = Sha256::new();
    h.update(pem.contents());
    let bytes = h.finalize();
    Ok(bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reuses() {
        let tmp = tempfile::tempdir().unwrap();
        let c = tmp.path().join("tls.crt");
        let k = tmp.path().join("tls.key");
        let a = ensure(&c, &k, &["localhost".into(), "127.0.0.1".into()]).unwrap();
        let b = ensure(&c, &k, &["localhost".into(), "127.0.0.1".into()]).unwrap();
        assert_eq!(a.cert_pem, b.cert_pem);
        assert!(a.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn rejects_loose_perms() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let tmp = tempfile::tempdir().unwrap();
            let c = tmp.path().join("tls.crt");
            let k = tmp.path().join("tls.key");
            ensure(&c, &k, &["localhost".into()]).unwrap();
            let mut perms = std::fs::metadata(&k).unwrap().permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(&k, perms).unwrap();
            assert!(ensure(&c, &k, &["localhost".into()]).is_err());
        }
    }

    #[test]
    fn fingerprint_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let c = tmp.path().join("tls.crt");
        let k = tmp.path().join("tls.key");
        let m = ensure(&c, &k, &["localhost".into()]).unwrap();
        let f1 = fingerprint(&m.cert_pem).unwrap();
        let f2 = fingerprint(&m.cert_pem).unwrap();
        assert_eq!(f1, f2);
        // 32-byte sha256 -> 32 hex pairs joined by 31 colons -> 95 chars
        assert_eq!(f1.len(), 95);
    }
}
