//! Embedded web assets (templates + static files), compiled into the binary.

use axum::extract::Path;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../web"]
pub struct WebAssets;

fn serve(path: &str) -> Response {
    match WebAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref().to_string())],
                file.data,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn login_page() -> Response {
    serve("templates/login.html")
}

pub async fn static_file(Path(rest): Path<String>) -> Response {
    serve(&format!("static/{rest}"))
}
