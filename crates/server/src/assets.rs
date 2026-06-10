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

/// Serve an embedded file with `__BASE_PATH__` placeholder replaced by
/// `base_path` at serve time.
///
/// No cache is used: files are small (a few KB) and substitution is trivial.
/// Caching would require a `OnceLock<Mutex<HashMap<...>>>` keyed on
/// `(path, base_path)` — that complexity is deferred to U4 when we actually
/// have a non-empty base_path in production; for U2/U3 base_path is always ""
/// so the output bytes are identical to a direct `serve()` call.
pub fn serve_substituted(path: &str, base_path: &str, status: StatusCode) -> Response {
    match WebAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let raw: Vec<u8> = match std::str::from_utf8(&file.data) {
                Ok(s) => s.replace("__BASE_PATH__", base_path).into_bytes(),
                // Non-UTF8 binary asset — return unchanged (no placeholders possible).
                Err(_) => file.data.into_owned(),
            };
            (
                status,
                [(header::CONTENT_TYPE, mime.as_ref().to_string())],
                raw,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn login_page() -> Response {
    serve("templates/login.html")
}

pub async fn terminal_page() -> Response {
    serve("templates/terminal.html")
}

pub async fn static_file(Path(rest): Path<String>) -> Response {
    serve(&format!("static/{rest}"))
}
