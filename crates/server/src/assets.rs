//! Embedded web assets (templates + static files), compiled into the binary.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::RustEmbed;

use crate::app::SharedState;

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

/// Cache key: (asset path, base_path the bytes were substituted with).
type SubstitutedKey = (String, String);

/// Cache of `__BASE_PATH__`-substituted asset bytes. base_path is fixed for
/// the lifetime of a production process, but tests build several apps with
/// different base_paths inside one test binary, so the key carries both the
/// asset path and the base_path it was substituted with.
static SUBSTITUTED: OnceLock<Mutex<HashMap<SubstitutedKey, Vec<u8>>>> = OnceLock::new();

/// Serve an embedded file with `__BASE_PATH__` placeholder replaced by
/// `base_path` at serve time. Substituted bytes are cached per
/// (path, base_path); files are a few KB so the clone per request is cheap.
pub fn serve_substituted(path: &str, base_path: &str, status: StatusCode) -> Response {
    let cache = SUBSTITUTED.get_or_init(|| Mutex::new(HashMap::new()));
    let key = (path.to_string(), base_path.to_string());
    let cached = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned();
    let bytes = match cached {
        Some(bytes) => bytes,
        None => {
            let Some(file) = WebAssets::get(path) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let raw: Vec<u8> = match std::str::from_utf8(&file.data) {
                Ok(s) => s.replace("__BASE_PATH__", base_path).into_bytes(),
                // Non-UTF8 binary asset — return unchanged (no placeholders possible).
                Err(_) => file.data.into_owned(),
            };
            cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, raw.clone());
            raw
        }
    };
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    (
        status,
        [(header::CONTENT_TYPE, mime.as_ref().to_string())],
        bytes,
    )
        .into_response()
}

pub async fn login_page(State(state): State<SharedState>) -> Response {
    serve_substituted("templates/login.html", &state.cfg.base_path, StatusCode::OK)
}

pub async fn terminal_page(State(state): State<SharedState>) -> Response {
    serve_substituted(
        "templates/terminal.html",
        &state.cfg.base_path,
        StatusCode::OK,
    )
}

pub async fn static_file(State(state): State<SharedState>, Path(rest): Path<String>) -> Response {
    // Reject any ".." path segment before lookup. Embedded assets cannot
    // traverse, but debug builds serve rust-embed assets straight from the
    // filesystem, where "static/../templates/x" would escape the static dir.
    if rest.split('/').any(|seg| seg == "..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = format!("static/{rest}");
    // Only text assets that can carry `__BASE_PATH__` placeholders go through
    // substitution; everything else (css, images, ...) is served verbatim.
    if path.ends_with(".js") || path.ends_with(".html") {
        serve_substituted(&path, &state.cfg.base_path, StatusCode::OK)
    } else {
        serve(&path)
    }
}
