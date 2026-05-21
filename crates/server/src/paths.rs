//! Resolves the per-platform config directory and the files inside it.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    /// Use `TERMINAL_HUB_CONFIG_DIR` (or its alias `TERMINAL_HUB_HOME`) if set
    /// (tests, dev). Otherwise resolve via `directories-next` to the platform's
    /// config dir.
    pub fn resolve() -> anyhow::Result<Self> {
        if let Ok(p) = std::env::var("TERMINAL_HUB_CONFIG_DIR") {
            return Ok(Self::at(PathBuf::from(p)));
        }
        if let Ok(p) = std::env::var("TERMINAL_HUB_HOME") {
            return Ok(Self::at(PathBuf::from(p)));
        }
        let pd = directories_next::ProjectDirs::from("dev", "terminal-hub", "terminal-hub")
            .ok_or_else(|| anyhow::anyhow!("no platform config dir available"))?;
        Ok(Self::at(pd.config_dir().to_path_buf()))
    }

    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn ensure(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        Ok(())
    }

    pub fn db(&self) -> PathBuf {
        self.root.join("state.db")
    }
    pub fn tls_crt(&self) -> PathBuf {
        self.root.join("tls.crt")
    }
    pub fn tls_key(&self) -> PathBuf {
        self.root.join("tls.key")
    }
    pub fn config_toml(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn peer_id(&self) -> PathBuf {
        self.root.join("peer_id")
    }
    pub fn peer_id_pub(&self) -> PathBuf {
        self.root.join("peer_id.pub")
    }
    pub fn authorized_peers(&self) -> PathBuf {
        self.root.join("authorized_peers")
    }
    pub fn peers_toml(&self) -> PathBuf {
        self.root.join("peers.toml")
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_overrides_platform_default() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("TERMINAL_HUB_CONFIG_DIR", tmp.path());
        let p = Paths::resolve().unwrap();
        assert_eq!(p.root(), tmp.path());
        assert_eq!(p.db().file_name().unwrap(), "state.db");
        std::env::remove_var("TERMINAL_HUB_CONFIG_DIR");
    }

    #[test]
    fn ensure_creates_missing_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a/b/c");
        let p = Paths::at(nested.clone());
        p.ensure().unwrap();
        assert!(nested.exists());
    }
}
