//! HTTP server for serving bootstrap files.

use std::path::PathBuf;

use anyhow::Result;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

#[derive(Clone)]
struct AppState {
    output_dir: PathBuf,
}

/// Start the HTTP server. Runs forever; call via `tokio::spawn`.
pub async fn run(output_dir: PathBuf, port: u16) -> Result<()> {
    let state = AppState { output_dir };
    let app = Router::new()
        .route("/metadata.json", get(handle_metadata))
        .route("/bootstrap.zip", get(handle_bootstrap_zip))
        .route("/bootstrap.zip.br", get(handle_bootstrap_zip_br))
        .with_state(state);

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

/// GET /metadata.json — identity, gzip, or brotli.
async fn handle_metadata(State(state): State<AppState>, headers: HeaderMap) -> Response {
    serve_file(&state.output_dir, "metadata.json", "application/json", &headers).await
}

/// GET /bootstrap.zip — identity, gzip, or brotli.
async fn handle_bootstrap_zip(State(state): State<AppState>, headers: HeaderMap) -> Response {
    serve_file(
        &state.output_dir,
        "bootstrap.zip",
        "application/zip",
        &headers,
    )
    .await
}

/// GET /bootstrap.zip.br — raw brotli bytes, no Content-Encoding header.
async fn handle_bootstrap_zip_br(State(state): State<AppState>) -> Response {
    match tokio::fs::read(state.output_dir.join("bootstrap.zip.br")).await {
        Ok(data) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
