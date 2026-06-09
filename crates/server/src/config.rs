use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub password: String,
    pub addr: String,
    pub data_dir: PathBuf,
    pub pid_file: Option<PathBuf>,
    pub session_timeout: Duration,
    pub login_max_attempts: u32,
    pub login_window: Duration,
    pub login_lockout: Duration,
}

#[derive(Debug, thiserror::Error)]
#[error("config: invalid value for {key}: {message}")]
pub struct ConfigError {
    pub key: &'static str,
    pub message: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Lookup-injected constructor so tests never touch process env.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        fn duration(
            lookup: &impl Fn(&str) -> Option<String>,
            key: &'static str,
            default: Duration,
        ) -> Result<Duration, ConfigError> {
            match lookup(key) {
                None => Ok(default),
                Some(raw) => humantime::parse_duration(&raw).map_err(|e| ConfigError {
                    key,
                    message: e.to_string(),
                }),
            }
        }

        let login_max_attempts = match lookup("AI_CONDUCTOR_LOGIN_MAX_ATTEMPTS") {
            None => 5,
            Some(raw) => raw.parse().map_err(|_| ConfigError {
                key: "AI_CONDUCTOR_LOGIN_MAX_ATTEMPTS",
                message: format!("not a number: {raw}"),
            })?,
        };

        Ok(Config {
            password: lookup("AI_CONDUCTOR_PASSWORD").unwrap_or_else(|| "admin".into()),
            addr: lookup("AI_CONDUCTOR_ADDR").unwrap_or_else(|| "0.0.0.0:8080".into()),
            data_dir: lookup("AI_CONDUCTOR_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("./data/sessions")),
            pid_file: lookup("AI_CONDUCTOR_PID_FILE").map(PathBuf::from),
            session_timeout: duration(
                &lookup,
                "AI_CONDUCTOR_SESSION_TIMEOUT",
                Duration::from_secs(24 * 3600),
            )?,
            login_max_attempts,
            login_window: duration(
                &lookup,
                "AI_CONDUCTOR_LOGIN_WINDOW",
                Duration::from_secs(60),
            )?,
            login_lockout: duration(
                &lookup,
                "AI_CONDUCTOR_LOGIN_LOCKOUT",
                Duration::from_secs(60),
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn defaults_match_go_implementation() {
        let cfg = Config::from_lookup(empty_env).unwrap();
        assert_eq!(cfg.password, "admin");
        assert_eq!(cfg.addr, "0.0.0.0:8080");
        assert_eq!(cfg.data_dir, std::path::PathBuf::from("./data/sessions"));
        assert_eq!(
            cfg.session_timeout,
            std::time::Duration::from_secs(24 * 3600)
        );
        assert_eq!(cfg.login_max_attempts, 5);
        assert_eq!(cfg.login_window, std::time::Duration::from_secs(60));
        assert_eq!(cfg.login_lockout, std::time::Duration::from_secs(60));
        assert_eq!(cfg.pid_file, None);
    }

    #[test]
    fn env_overrides_are_parsed() {
        let lookup = |key: &str| -> Option<String> {
            match key {
                "AI_CONDUCTOR_PASSWORD" => Some("s3cret".into()),
                "AI_CONDUCTOR_ADDR" => Some("127.0.0.1:5050".into()),
                "AI_CONDUCTOR_SESSION_TIMEOUT" => Some("2h".into()),
                "AI_CONDUCTOR_LOGIN_MAX_ATTEMPTS" => Some("0".into()),
                "AI_CONDUCTOR_PID_FILE" => Some("/tmp/c.pid".into()),
                _ => None,
            }
        };
        let cfg = Config::from_lookup(lookup).unwrap();
        assert_eq!(cfg.password, "s3cret");
        assert_eq!(cfg.addr, "127.0.0.1:5050");
        assert_eq!(cfg.session_timeout, std::time::Duration::from_secs(7200));
        assert_eq!(cfg.login_max_attempts, 0);
        assert_eq!(cfg.pid_file, Some(std::path::PathBuf::from("/tmp/c.pid")));
    }

    #[test]
    fn invalid_duration_is_an_error() {
        let lookup = |key: &str| -> Option<String> {
            (key == "AI_CONDUCTOR_SESSION_TIMEOUT").then(|| "notaduration".to_string())
        };
        assert!(Config::from_lookup(lookup).is_err());
    }
}
