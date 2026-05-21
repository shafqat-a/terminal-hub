use crate::session_id::SessionId;
use serde::Serialize;
use std::sync::Arc;
use tmux_client::conn::Connection;
use tmux_client::protocol::Event;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SessionInfo {
    pub id: SessionId,
    pub display_name: String,
    pub owner: String,
    pub created_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tmux: {0}")] Tmux(#[from] tmux_client::conn::Error),
    #[error("tmux cmd error: {0}")] Cmd(String),
}

pub struct Manager {
    ctl: Arc<Mutex<Connection>>,
}

impl Manager {
    pub async fn connect(socket: &str, boot_session: &str) -> Result<Self, Error> {
        let mut conn = Connection::attach(socket, boot_session).await?;
        // tmux -C emits an initial empty %begin/%end block on attach. Drain it
        // so the first real command's response isn't shadowed.
        loop {
            match conn.recv().await {
                Some(Event::CommandOk { .. }) | Some(Event::CommandErr { .. }) => break,
                Some(_) => continue,
                None => return Err(Error::Cmd("tmux closed before initial block".into())),
            }
        }
        Ok(Self { ctl: Arc::new(Mutex::new(conn)) })
    }

    async fn run(&self, cmd: &str) -> Result<String, Error> {
        let mut c = self.ctl.lock().await;
        c.send_command(cmd).await?;
        loop {
            match c.recv().await {
                Some(Event::CommandOk { body }) => return Ok(body),
                Some(Event::CommandErr { body }) => return Err(Error::Cmd(body)),
                Some(_) => continue,
                None => return Err(Error::Cmd("connection closed".into())),
            }
        }
    }

    pub async fn list(&self) -> Result<Vec<SessionInfo>, Error> {
        let fmt = "#{session_name}|#{?@display-name,#{@display-name},(unnamed)}|\
                   #{?@owner-email,#{@owner-email},?}|#{?@created-at,#{@created-at},0}";
        let body = self.run(&format!("list-sessions -F '{fmt}'")).await?;
        Ok(body.lines().filter_map(|line| {
            let p: Vec<&str> = line.splitn(4, '|').collect();
            if p.len() != 4 { return None; }
            Some(SessionInfo {
                id: SessionId::from_tmux_name(p[0])?,
                display_name: p[1].into(),
                owner: p[2].into(),
                created_at: p[3].parse().unwrap_or(0),
            })
        }).collect())
    }

    pub async fn create(&self, display_name: &str, owner: &str) -> Result<SessionInfo, Error> {
        let id = SessionId::new();
        let name = id.tmux_name();
        let now = now_secs();
        self.run(&format!("new-session -d -s '{name}'")).await?;
        self.run(&format!("set-option -t '{name}' @display-name '{}'", esc(display_name))).await?;
        self.run(&format!("set-option -t '{name}' @owner-email '{}'", esc(owner))).await?;
        self.run(&format!("set-option -t '{name}' @created-at {now}")).await?;
        Ok(SessionInfo { id, display_name: display_name.into(), owner: owner.into(), created_at: now })
    }

    pub async fn rename(&self, id: &SessionId, new_display: &str) -> Result<(), Error> {
        self.run(&format!("set-option -t '{}' @display-name '{}'", id.tmux_name(), esc(new_display))).await?;
        Ok(())
    }

    pub async fn kill(&self, id: &SessionId) -> Result<(), Error> {
        self.run(&format!("kill-session -t '{}'", id.tmux_name())).await?;
        Ok(())
    }
}

fn esc(s: &str) -> String { s.replace('\'', "'\\''") }
fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
