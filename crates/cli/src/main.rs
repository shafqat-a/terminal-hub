#[allow(dead_code)] // `sign_with_agent` is a reusable helper; main.rs uses the inline loop variant.
mod agent;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "terminal-hub-cli", version, about = "terminal-hub admin CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the primary user in the on-disk SQLite DB. Run on the server host.
    Bootstrap {
        #[arg(long)]
        email: String,
        #[arg(long, value_name = "PATH")]
        pubkey: PathBuf,
        #[arg(long, env = "TERMINAL_HUB_CONFIG_DIR")]
        config_dir: Option<PathBuf>,
    },
    /// Sign the server's challenge from this laptop. Prints a bootstrap URL.
    Enroll {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        /// Skip TLS verification (use for self-signed certs on a trusted network).
        #[arg(long, default_value_t = false)]
        insecure: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Bootstrap {
            email,
            pubkey,
            config_dir,
        } => run_bootstrap(email, pubkey, config_dir),
        Cmd::Enroll {
            server,
            email,
            insecure,
        } => run_enroll(server, email, insecure).await,
    }
}

fn run_bootstrap(email: String, pubkey_path: PathBuf, config_dir: Option<PathBuf>) -> Result<()> {
    let pubkey = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("reading {}", pubkey_path.display()))?;
    let pubkey = pubkey.trim().to_string();
    ssh_key::PublicKey::from_openssh(&pubkey)
        .with_context(|| "pubkey file is not in valid OpenSSH format")?;

    let dir = resolve_config_dir(config_dir)?;
    std::fs::create_dir_all(&dir)?;
    let db_path = dir.join("state.db");
    let conn = Connection::open(&db_path)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(include_str!(
        "../../server/src/db/migrations/0001_initial.sql"
    ))?;

    // Refuse if a primary already exists with a different email; allow re-running
    // for the same email (key rotation).
    let existing: Option<String> = conn
        .query_row(
            "SELECT email FROM users WHERE role = 'primary' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok();
    if let Some(other) = existing {
        if other != email {
            bail!(
                "a primary user already exists ({other}); refusing to overwrite. \
                 Delete {} manually if you really want to start over.",
                db_path.display()
            );
        }
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    conn.execute(
        "INSERT INTO users(email, pubkey_openssh, role, enrolled_at)
         VALUES (?1, ?2, 'primary', ?3)
         ON CONFLICT(email) DO UPDATE SET pubkey_openssh = excluded.pubkey_openssh",
        params![email, pubkey, now],
    )?;
    println!("OK: primary user {email} written to {}", db_path.display());
    Ok(())
}

fn resolve_config_dir(override_: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = override_ {
        return Ok(p);
    }
    let pd = directories_next::ProjectDirs::from("dev", "terminal-hub", "terminal-hub")
        .ok_or_else(|| anyhow!("no platform config dir available"))?;
    Ok(pd.config_dir().to_path_buf())
}

#[derive(Deserialize)]
struct ChallengeResp {
    challenge: String,
}

#[derive(Deserialize)]
struct InitiateResp {
    bootstrap_url: String,
    token: String,
}

async fn run_enroll(server: String, email: String, insecure: bool) -> Result<()> {
    let base = url::Url::parse(&server).context("--server is not a valid URL")?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()?;

    // 1. Ask the server for a fresh challenge. We don't fetch the pubkey it has
    //    on file (would be an info leak); instead we iterate every identity in
    //    the local ssh-agent and let the server's verify reject the wrong ones.
    let chal_resp: ChallengeResp = client
        .post(base.join("/auth/challenge")?)
        .json(&serde_json::json!({ "email": &email }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let challenge_bytes =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&chal_resp.challenge)?;
    let payload = auth_core::payload(&challenge_bytes);

    // 2. Iterate identities in the agent until one verifies on the server.
    let sock = std::env::var("SSH_AUTH_SOCK")
        .map_err(|_| anyhow!("SSH_AUTH_SOCK not set; run `ssh-add` first"))?;
    let mut agent = ssh_agent_client_rs::Client::connect(std::path::Path::new(&sock))
        .context("connect to ssh-agent")?;
    let identities = agent.list_identities().context("list-identities")?;
    if identities.is_empty() {
        bail!("ssh-agent has no identities loaded. Run `ssh-add ~/.ssh/id_ed25519`.");
    }

    for id in identities {
        let Ok(sig) = agent.sign(&id, &payload) else {
            continue;
        };
        if sig.algorithm() != ssh_key::Algorithm::Ed25519 {
            continue;
        }
        if sig.as_bytes().len() != 64 {
            continue;
        }
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.as_bytes());
        let resp = client
            .post(base.join("/auth/enroll/initiate")?)
            .json(&serde_json::json!({
                "email": &email,
                "challenge": &chal_resp.challenge,
                "signature": sig_b64,
            }))
            .send()
            .await?;
        if resp.status().is_success() {
            let body: InitiateResp = resp.json().await?;
            println!("\nEnrollment URL (open in your browser within 5 minutes):");
            println!("    {}\n", body.bootstrap_url);
            println!("(token: {})", body.token);
            return Ok(());
        }
        // 401 just means this identity isn't the one on file — try the next.
    }
    bail!("none of the keys in your ssh-agent match the pubkey on the server for {email}");
}
