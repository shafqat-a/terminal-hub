use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub uuid::Uuid);

impl SessionId {
    pub fn new() -> Self { Self(uuid::Uuid::now_v7()) }
    pub fn tmux_name(&self) -> String { format!("th-{}", self.0) }
    pub fn from_tmux_name(name: &str) -> Option<Self> {
        uuid::Uuid::parse_str(name.strip_prefix("th-")?).ok().map(Self)
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn round_trip() {
        let id = SessionId::new();
        assert_eq!(SessionId::from_tmux_name(&id.tmux_name()).unwrap(), id);
    }
    #[test] fn rejects_unprefixed() { assert!(SessionId::from_tmux_name("scratch").is_none()); }
}
