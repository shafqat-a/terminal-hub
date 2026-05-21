//! Manages the lifecycle of a `tmux -CC` child process.

use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;

use crate::protocol::{Decoder, Event};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tmux io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tmux exited unexpectedly")]
    Exited,
}

pub struct Connection {
    _child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<Event>,
}

impl Connection {
    pub async fn attach(socket: &str, session: &str) -> Result<Self, Error> {
        let mut cmd = Command::new("tmux");
        // Use `-C` (single dash) rather than `-CC`: -CC requires a TTY on stdio
        // and tcgetattr-fails when stdio is a pipe (as it is here). -C emits the
        // identical %begin/%end/%output control protocol our decoder parses.
        cmd.args(["-L", socket, "-C", "attach-session", "-t", session])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn()?;
        let stdin = child.stdin.take().ok_or(Error::Exited)?;
        let stdout = child.stdout.take().ok_or(Error::Exited)?;

        let (tx, rx) = mpsc::channel::<Event>(256);
        tokio::spawn(read_loop(stdout, tx));

        Ok(Self { _child: child, stdin, rx })
    }

    pub async fn send_command(&mut self, cmd: &str) -> Result<(), Error> {
        self.stdin.write_all(cmd.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}

async fn read_loop(stdout: tokio::process::ChildStdout, tx: mpsc::Sender<Event>) {
    let reader = BufReader::new(stdout);
    let mut lines = reader.lines();
    let mut decoder = Decoder::default();
    while let Ok(Some(line)) = lines.next_line().await {
        for ev in decoder.push_line(&line) {
            if tx.send(ev).await.is_err() {
                break;
            }
        }
    }
}
