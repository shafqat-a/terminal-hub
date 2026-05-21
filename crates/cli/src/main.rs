#[allow(dead_code)] // `sign_with_agent` is a reusable helper; main.rs uses the inline loop variant.
mod agent;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::path::PathBuf;
use terminal_hub_server::{db::Store, paths::Paths, users};

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
    /// Add a secondary user. Requires the primary to already be bootstrapped.
    AddUser {
        #[arg(long)]
        email: String,
        /// Path to the user's SSH public key file (.pub).
        #[arg(long, value_name = "PATH")]
        pubkey: PathBuf,
        #[arg(long, env = "TERMINAL_HUB_CONFIG_DIR")]
        config_dir: Option<PathBuf>,
    },
    /// Remove a user and cascade-delete their grants + active session cookies.
    /// Refuses to remove the primary.
    RemoveUser {
        #[arg(long)]
        email: String,
        #[arg(long, env = "TERMINAL_HUB_CONFIG_DIR")]
        config_dir: Option<PathBuf>,
    },
    /// List all users in the local DB.
    ListUsers {
        #[arg(long, env = "TERMINAL_HUB_CONFIG_DIR")]
        config_dir: Option<PathBuf>,
    },
    /// Print this instance's peer identity (pubkey, fingerprint, TLS cert fp,
    /// and a ready-to-paste `[[peer]]` snippet for another instance's peers.toml).
    PeerInfo {
        #[arg(long, env = "TERMINAL_HUB_CONFIG_DIR")]
        config_dir: Option<PathBuf>,
        /// Friendly name to embed in the snippet (e.g. the hostname of this box).
        #[arg(long, default_value = "this-instance")]
        friendly_name: String,
        /// URL where this instance is reachable, for the snippet's `url = ` field.
        #[arg(long, default_value = "https://localhost:5999/")]
        url: String,
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
        } => run_bootstrap(email, pubkey, config_dir).await,
        Cmd::Enroll {
            server,
            email,
            insecure,
        } => run_enroll(server, email, insecure).await,
        Cmd::AddUser {
            email,
            pubkey,
            config_dir,
        } => run_add_user(email, pubkey, config_dir).await,
        Cmd::RemoveUser { email, config_dir } => run_remove_user(email, config_dir).await,
        Cmd::ListUsers { config_dir } => run_list_users(config_dir).await,
        Cmd::PeerInfo {
            config_dir,
            friendly_name,
            url,
        } => run_peer_info(config_dir, friendly_name, url),
    }
}

fn open_store(config_dir: Option<PathBuf>) -> Result<(Store, PathBuf)> {
    let paths = resolve_paths(config_dir)?;
    paths.ensure()?;
    let db_path = paths.db();
    let store = Store::open(&db_path)
        .with_context(|| format!("opening {}", db_path.display()))?;
    Ok((store, db_path))
}

fn resolve_paths(override_: Option<PathBuf>) -> Result<Paths> {
    if let Some(p) = override_ {
        return Ok(Paths::at(p));
    }
    Paths::resolve()
}

async fn run_bootstrap(email: String, pubkey_path: PathBuf, config_dir: Option<PathBuf>) -> Result<()> {
    let pubkey = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("reading {}", pubkey_path.display()))?;
    let pubkey = pubkey.trim().to_string();
    ssh_key::PublicKey::from_openssh(&pubkey)
        .with_context(|| "pubkey file is not in valid OpenSSH format")?;

    let (store, db_path) = open_store(config_dir)?;

    // Refuse if a primary already exists with a different email; allow
    // re-running for the same email (key rotation).
    if let Some(other) = store.primary_email().await? {
        if other != email {
            bail!(
                "a primary user already exists ({other}); refusing to overwrite. \
                 Delete {} manually if you really want to start over.",
                db_path.display()
            );
        }
    }
    store.upsert_user(&email, &pubkey, "primary").await?;
    println!("OK: primary user {email} written to {}", db_path.display());
    Ok(())
}

async fn run_add_user(email: String, pubkey_path: PathBuf, config_dir: Option<PathBuf>) -> Result<()> {
    let raw = std::fs::read_to_string(&pubkey_path)
        .with_context(|| format!("reading {}", pubkey_path.display()))?;
    let trimmed = raw.trim();
    if !(trimmed.starts_with("ssh-") || trimmed.starts_with("ecdsa-")) {
        bail!(
            "not an OpenSSH public key (expected `ssh-…` prefix): {}",
            pubkey_path.display()
        );
    }
    ssh_key::PublicKey::from_openssh(trimmed)
        .with_context(|| "pubkey file is not in valid OpenSSH format")?;
    let (store, _) = open_store(config_dir)?;
    let row = users::add_secondary(&store, &email, trimmed)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    println!(
        "added secondary: {} (enrolled_at={})",
        row.email, row.enrolled_at
    );
    println!(
        "next: have the user run `terminal-hub-cli enroll --server <URL> --email {}` from their laptop",
        row.email
    );
    Ok(())
}

async fn run_remove_user(email: String, config_dir: Option<PathBuf>) -> Result<()> {
    let (store, _) = open_store(config_dir)?;
    users::remove(&store, &email).await.map_err(|e| anyhow!("{e}"))?;
    println!("removed: {email}");
    Ok(())
}

fn run_peer_info(
    config_dir: Option<PathBuf>,
    friendly_name: String,
    url: String,
) -> Result<()> {
    use base64::engine::general_purpose::STANDARD as B64;
    use terminal_hub_server::peer::fingerprint::fingerprint_b64;

    let paths = resolve_paths(config_dir)?;
    let pub_path = paths.peer_id_pub();
    let crt_path = paths.tls_crt();

    let pub_b64 = std::fs::read_to_string(&pub_path)
        .with_context(|| format!("reading {}", pub_path.display()))?
        .trim()
        .to_string();
    let pub_bytes = B64
        .decode(&pub_b64)
        .with_context(|| "peer_id.pub is not valid base64")?;
    let peer_fp = fingerprint_b64(&pub_bytes);

    let cert_pem = std::fs::read_to_string(&crt_path)
        .with_context(|| format!("reading {}", crt_path.display()))?;
    let cert_der = pem::parse(cert_pem.as_bytes())
        .with_context(|| "tls.crt is not valid PEM")?
        .into_contents();
    let tls_fp = fingerprint_b64(&cert_der);

    println!("Peer pubkey (base64): {}", pub_b64);
    println!("Peer fingerprint:     {}", peer_fp);
    println!("TLS cert fingerprint: {}", tls_fp);
    println!();
    println!("Paste this into another instance's peers.toml to add this box as a peer:");
    println!();
    println!("[[peer]]");
    println!("url             = \"{}\"", url);
    println!("friendly_name   = \"{}\"", friendly_name);
    println!("peer_pubkey     = \"{}\"", pub_b64);
    println!("tls_cert_fp     = \"{}\"", tls_fp);
    Ok(())
}

async fn run_list_users(config_dir: Option<PathBuf>) -> Result<()> {
    let (store, _) = open_store(config_dir)?;
    let rows = users::list(&store).await.map_err(|e| anyhow!("{e}"))?;
    if rows.is_empty() {
        println!("(no users)");
        return Ok(());
    }
    for r in rows {
        println!(
            "{:9} {:30} passkey={} enrolled_at={}",
            r.role,
            r.email,
            if r.passkey_registered { "yes" } else { "no " },
            r.enrolled_at,
        );
    }
    Ok(())
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
