use std::process::Command;
use terminal_hub_server::sessions::Manager;

const SOCKET: &str = "terminal-hub-test-m2-sessions";
const BOOT: &str = "_boot";

fn ensure() { let _ = Command::new("tmux").args(["-L", SOCKET, "new-session", "-d", "-s", BOOT]).status(); }
fn kill() { let _ = Command::new("tmux").args(["-L", SOCKET, "kill-server"]).status(); }

#[tokio::test(flavor = "multi_thread")]
async fn crud() {
    ensure();
    let m = Manager::connect(SOCKET, BOOT).await.unwrap();
    let info = m.create("build", "you@example.com").await.unwrap();
    assert!(m.list().await.unwrap().iter().any(|s| s.id == info.id));
    m.rename(&info.id, "renamed").await.unwrap();
    assert!(m.list().await.unwrap().iter().any(|s| s.display_name == "renamed"));
    m.kill(&info.id).await.unwrap();
    assert!(!m.list().await.unwrap().iter().any(|s| s.id == info.id));
    kill();
}
