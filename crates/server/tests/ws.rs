use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

async fn spawn_app() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = terminal_hub_server::router();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn ws_echoes_text() {
    let addr = spawn_app().await;
    let url = format!("ws://{addr}/ws/echo");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.expect("connect");
    ws.send(Message::Text("hello".into())).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply, Message::Text("hello".into()));
}
