//! HTTP server for serving bootstrap files and the built-in web UI.

use std::path::PathBuf;

/// Web UI files, embedded at compile time.
const INDEX_HTML: &str = include_str!("../web/index.html");
const TOR_FAST_BOOTSTRAP_JS: &str = include_str!("../web/torFastBootstrap.js");

use anyhow::Result;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct AppState {
    output_dir: PathBuf,
}

/// Start the HTTP server. Runs forever; call via `tokio::spawn`.
pub async fn run(output_dir: PathBuf, port: u16, allow_uncompressed: bool) -> Result<()> {
    let state = AppState { output_dir };
    let mut app = Router::new()
        .route("/", get(handle_index))
        .route("/torFastBootstrap.js", get(handle_js))
        .route("/metadata.json", get(handle_metadata))
        .route("/bootstrap.zip.br", get(handle_bootstrap_zip_br));
    if allow_uncompressed {
        app = app.route("/bootstrap.zip", get(handle_bootstrap_zip));
    }
    let app = app.layer(CorsLayer::permissive()).with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("HTTP server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Which pre-compressed variant to serve, if any.
enum Encoding {
    Brotli,
    Gzip,
    Identity,
}

/// Pick the best encoding the client accepts. Prefer brotli > gzip > identity.
fn best_encoding(headers: &HeaderMap) -> Encoding {
    let accept = headers
        .get_all(header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",");

    if accept.split(',').any(|p| p.trim().starts_with("br")) {
        Encoding::Brotli
    } else if accept.split(',').any(|p| {
        let t = p.trim();
        t.starts_with("gzip") || t.starts_with("x-gzip")
    }) {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

/// Read the cached ETag from disk, or compute it from bootstrap.zip if missing.
async fn read_etag(dir: &PathBuf) -> Option<String> {
    if let Ok(s) = tokio::fs::read_to_string(dir.join("bootstrap.etag")).await {
        return Some(format!("\"{}\"", s.trim()));
    }
    // Fallback: hash the zip on disk and write the etag file for next time.
    let data = tokio::fs::read(dir.join("bootstrap.zip")).await.ok()?;
    use digest::Digest;
    let hash = hex::encode(sha3::Sha3_256::digest(&data));
    let _ = tokio::fs::write(dir.join("bootstrap.etag"), hash.as_bytes()).await;
    Some(format!("\"{}\"", hash))
}

/// Check If-None-Match against the current ETag. Returns Some(304) if matched.
fn check_not_modified(headers: &HeaderMap, etag: &str) -> Option<Response> {
    let if_none_match = headers.get(header::IF_NONE_MATCH)?.to_str().ok()?;
    if if_none_match == etag || if_none_match == "*" {
        Some(StatusCode::NOT_MODIFIED.into_response())
    } else {
        None
    }
}

/// Serve a file with content-negotiation over pre-compressed variants.
/// Tries `.br` (brotli) or `.gz` (gzip) on disk, falls back to identity.
async fn serve_file(
    dir: &PathBuf,
    filename: &str,
    content_type: &str,
    headers: &HeaderMap,
) -> Response {
    match best_encoding(headers) {
        Encoding::Brotli => {
            if let Ok(data) = tokio::fs::read(dir.join(format!("{}.br", filename))).await {
                return (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, content_type),
                        (header::CONTENT_ENCODING, "br"),
                    ],
                    data,
                )
                    .into_response();
            }
        }
        Encoding::Gzip => {
            if let Ok(data) = tokio::fs::read(dir.join(format!("{}.gz", filename))).await {
                return (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, content_type),
                        (header::CONTENT_ENCODING, "gzip"),
                    ],
                    data,
                )
                    .into_response();
            }
        }
        Encoding::Identity => {}
    }

    match tokio::fs::read(dir.join(filename)).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type)],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

/// GET / — web UI.
async fn handle_index() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        INDEX_HTML,
    )
        .into_response()
}

/// GET /torFastBootstrap.js
async fn handle_js() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        TOR_FAST_BOOTSTRAP_JS,
    )
        .into_response()
}

/// GET /metadata.json — identity, gzip, or brotli.
async fn handle_metadata(State(state): State<AppState>, headers: HeaderMap) -> Response {
    serve_file(&state.output_dir, "metadata.json", "application/json", &headers).await
}

/// GET /bootstrap.zip — identity, gzip, or brotli. Supports ETag/304.
async fn handle_bootstrap_zip(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let etag = read_etag(&state.output_dir).await;
    if let Some(ref etag) = etag {
        if let Some(not_modified) = check_not_modified(&headers, etag) {
            return not_modified;
        }
    }
    let mut res = serve_file(
        &state.output_dir,
        "bootstrap.zip",
        "application/zip",
        &headers,
    )
    .await;
    if let Some(etag) = etag {
        res.headers_mut()
            .insert(header::ETAG, etag.parse().unwrap());
    }
    res
}

/// GET /bootstrap.zip.br — always serves the brotli-compressed bytes. Supports ETag/304.
/// If the client accepts brotli, respond with `Content-Type: application/zip`
/// and `Content-Encoding: br` so the browser decompresses transparently.
/// Otherwise, serve raw bytes as `application/octet-stream` for manual decoding.
///
/// Both paths include `X-Decompressed-Content-Length` with the uncompressed zip
/// size, so clients can show accurate download progress even when the browser
/// handles decompression transparently (where `Content-Length` reflects the
/// compressed size but the stream delivers decompressed bytes).
async fn handle_bootstrap_zip_br(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let etag = read_etag(&state.output_dir).await;
    if let Some(ref etag) = etag {
        if let Some(not_modified) = check_not_modified(&headers, etag) {
            return not_modified;
        }
    }
    let data = match tokio::fs::read(state.output_dir.join("bootstrap.zip.br")).await {
        Ok(d) => d,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    // Get decompressed size from the uncompressed zip on disk.
    let decompressed_len = tokio::fs::metadata(state.output_dir.join("bootstrap.zip"))
        .await
        .map(|m| m.len().to_string())
        .unwrap_or_default();
    let mut res = if matches!(best_encoding(&headers), Encoding::Brotli) {
        (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/zip"),
                (header::CONTENT_ENCODING, "br"),
            ],
            data,
        )
            .into_response()
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response()
    };
    if !decompressed_len.is_empty() {
        res.headers_mut().insert(
            "x-decompressed-content-length",
            decompressed_len.parse().unwrap(),
        );
    }
    if let Some(etag) = etag {
        res.headers_mut()
            .insert(header::ETAG, etag.parse().unwrap());
    }
    res
}
