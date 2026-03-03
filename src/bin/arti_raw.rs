//! Hybrid prototype: arti-client handles bootstrapping & connectivity,
//! while we make custom raw directory requests.
//!
//! Uses `TorClient::create_bootstrapped()` for production-quality guard
//! management, directory refresh, and circuit management.  Then accesses
//! `circmgr()` (via the `experimental-api` feature) to get managed dir
//! circuits and sends raw HTTP/1.0 requests over BEGINDIR streams.

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tor_circmgr::DirInfo;
use tor_netdir::Timeliness;

use arti_client::{TorClient, TorClientConfig};

/// A directory client backed by a fully bootstrapped TorClient.
///
/// The TorClient handles guard selection, directory consensus refresh,
/// and circuit management.  This struct provides a simple `get(path)`
/// method for raw HTTP-over-BEGINDIR requests.
struct DirClient {
    client: TorClient<tor_rtcompat::PreferredRuntime>,
}

/// Raw HTTP/1.0 response from a directory cache.
struct DirResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl DirResponse {
    fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

impl DirClient {
    /// Bootstrap a full TorClient and return a DirClient wrapping it.
    async fn connect() -> Result<Self> {
        tracing::info!("bootstrapping TorClient...");
        let config = TorClientConfig::default();
        let client = TorClient::create_bootstrapped(config)
            .await
            .context("bootstrapping TorClient")?;
        tracing::info!("TorClient bootstrapped");
        Ok(Self { client })
    }

    /// Send a raw GET request to a directory cache and return the response.
    ///
    /// Uses the TorClient's circuit manager to get a managed dir circuit,
    /// then opens a BEGINDIR stream and sends raw HTTP/1.0.
    async fn get(&self, path: &str) -> Result<DirResponse> {
        // Get the current network directory from the bootstrapped client
        let netdir = self
            .client
            .dirmgr()
            .netdir(Timeliness::Timely)
            .map_err(|e| anyhow::anyhow!("getting network directory: {}", e))?;

        // Get a managed directory circuit
        let dir_tunnel = self
            .client
            .circmgr()
            .get_or_launch_dir(DirInfo::Directory(&netdir))
            .await
            .map_err(|e| anyhow::anyhow!("getting dir circuit: {}", e))?;

        // Open a BEGINDIR stream
        let mut stream = dir_tunnel
            .begin_dir_stream()
            .await
            .map_err(|e| anyhow::anyhow!("opening BEGINDIR stream: {}", e))?;

        // Send HTTP/1.0 request
        let request = format!(
            "GET {} HTTP/1.0\r\n\
             Accept-Encoding: deflate, identity, x-tor-lzma, x-zstd\r\n\
             \r\n",
            path
        );
        stream
            .write_all(request.as_bytes())
            .await
            .context("writing request")?;
        stream.flush().await.context("flushing request")?;

        // Parse HTTP/1.0 response
        let mut reader = BufReader::new(stream);
        let mut header_buf = String::new();
        loop {
            let mut line = String::new();
            let n = reader
                .read_line(&mut line)
                .await
                .context("reading header line")?;
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            header_buf.push_str(&line);
        }

        // Parse status line
        let status_line = header_buf
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);

        // Parse headers
        let mut headers = Vec::new();
        for line in header_buf.lines().skip(1) {
            if let Some((key, val)) = line.split_once(':') {
                headers.push((key.trim().to_string(), val.trim().to_string()));
            }
        }

        // Read body
        let mut body = Vec::new();
        let _ = reader.read_to_end(&mut body).await;

        // Decompress based on Content-Encoding
        let encoding = headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == "content-encoding")
            .map(|(_, v)| v.as_str());

        let body = decompress(encoding, &body)
            .await
            .context("decompressing body")?;

        Ok(DirResponse {
            status,
            headers,
            body,
        })
    }
}

async fn decompress(encoding: Option<&str>, data: &[u8]) -> Result<Vec<u8>> {
    use async_compression::futures::bufread::*;

    let mut out = Vec::new();
    match encoding {
        None | Some("identity") => {
            out = data.to_vec();
        }
        Some("deflate") => {
            let mut decoder = ZlibDecoder::new(data);
            decoder
                .read_to_end(&mut out)
                .await
                .context("deflate decode")?;
        }
        Some("x-tor-lzma") => {
            let mut decoder = XzDecoder::new(data);
            decoder.read_to_end(&mut out).await.context("xz decode")?;
        }
        Some("x-zstd") => {
            let mut decoder = ZstdDecoder::new(data);
            decoder
                .read_to_end(&mut out)
                .await
                .context("zstd decode")?;
        }
        Some(other) => bail!("unsupported encoding: {}", other),
    }
    Ok(out)
}

#[derive(Parser)]
#[command(name = "tor-arti-raw")]
#[command(about = "Arti-backed raw Tor directory protocol client")]
struct Cli {
    /// Paths to request, e.g. /tor/status-vote/current/consensus-microdesc
    paths: Vec<String>,

    /// Output directory (files named by last path component)
    #[arg(short, long, default_value = ".")]
    output_dir: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    if cli.paths.is_empty() {
        bail!("provide at least one path, e.g. /tor/status-vote/current/consensus-microdesc");
    }
    std::fs::create_dir_all(&cli.output_dir)?;

    let client = DirClient::connect().await?;

    for path in &cli.paths {
        tracing::info!("GET {}", path);
        let resp = client.get(path).await?;

        tracing::info!(
            "  status={} body={} bytes encoding={:?}",
            resp.status,
            resp.body.len(),
            resp.header("Content-Encoding"),
        );

        if resp.status != 200 {
            tracing::warn!("  non-200 status, skipping write");
            continue;
        }

        // Derive filename from the last path component
        let filename = path
            .rsplit('/')
            .find(|s| !s.is_empty())
            .unwrap_or("response");
        let out_path = cli.output_dir.join(filename);
        std::fs::write(&out_path, &resp.body)
            .with_context(|| format!("writing {:?}", out_path))?;
        tracing::info!("  wrote {} ({} bytes)", out_path.display(), resp.body.len());
    }

    Ok(())
}
