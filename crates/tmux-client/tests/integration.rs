use std::process::Command;
use tmux_client::conn::Connection;
use tmux_client::protocol::Event;

fn ensure_server(socket: &str, session: &str) {
    let _ = Command::new("tmux")
        .args(["-L", socket, "new-session", "-d", "-s", session])
        .status();
}

fn kill_server(socket: &str) {
    let _ = Command::new("tmux").args(["-L", socket, "kill-server"]).status();
}

#[tokio::test(flavor = "multi_thread")]
async fn list_sessions_round_trip() {
    let socket = "terminal-hub-test-m1";
    let session = "smoke";
    ensure_server(socket, session);

    let mut conn = Connection::attach(socket, session).await.expect("attach");
    conn.send_command("list-sessions -F '#{session_name}'").await.unwrap();

    // tmux -C emits an initial empty %begin/%end block on attach before our
    // command response, so skip empty CommandOk bodies until we see one that
    // matches our list-sessions output.
    let mut got = None;
    for _ in 0..200 {
        if let Some(Event::CommandOk { body }) = conn.recv().await {
            if !body.trim().is_empty() {
                got = Some(body);
                break;
            }
        }
    }
    kill_server(socket);

    let body = got.expect("a CommandOk before timeout");
    assert!(body.lines().any(|l| l == session), "expected {session} in {body:?}");
}
