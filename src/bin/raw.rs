//! Raw directory protocol prototype.
//!
//! Provides a `DirClient` with an async `get()` method that takes
//! an arbitrary path like `/tor/status-vote/current/consensus-microdesc`
//! and returns the raw response bytes over a Tor BEGINDIR stream.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use rand::seq::SliceRandom;
use tor_chanmgr::{ChanMgr, ChanMgrConfig, ChannelUsage, Dormancy};
use tor_circmgr::build::exit_circparams_from_netparams;
use tor_memquota::MemoryQuotaTracker;
use tor_netdir::params::NetParameters;
use tor_proto::client::ClientTunnel;
use tor_rtcompat::{PreferredRuntime, SpawnExt};

/// A minimal Tor directory protocol client.
///
/// Wraps a 1-hop circuit to a fallback directory cache.
/// Call `get("/tor/status-vote/current/consensus-microdesc")` etc.
struct DirClient {
    tunnel: Arc<ClientTunnel>,
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
    /// Connect to a random fallback directory cache and build a 1-hop circuit.
    async fn connect(runtime: &PreferredRuntime) -> Result<Self> {
        let fallbacks = tor_dircommon::fallback::FallbackListBuilder::default()
            .build()
            .context("building fallback list")?;
        if fallbacks.is_empty() {
            bail!("no fallback directories available");
        }

        let mut fallback_vec = fallbacks.iter().collect::<Vec<_>>();
        fallback_vec.shuffle(&mut rand::rng());

        let memquota = MemoryQuotaTracker::new_noop();
        let chanmgr = ChanMgr::new(
            runtime.clone(),
            ChanMgrConfig::default(),
            Dormancy::Active,
            &NetParameters::default(),
            memquota,
        )
        .context("creating channel manager")?;

        // Try fallbacks until one connects
        let mut last_err = None;
        let mut channel = None;
        for (i, fallback) in fallback_vec.iter().take(3).enumerate() {
            tracing::info!("connecting to fallback directory cache (attempt {})...", i + 1);
            match chanmgr.get_or_launch(*fallback, ChannelUsage::Dir).await {
                Ok((ch, _)) => {
                    channel = Some(ch);
                    break;
                }
                Err(e) => {
                    tracing::warn!("fallback {} failed: {}", i + 1, e);
                    last_err = Some(e);
                }
            }
        }
        let channel = channel.ok_or_else(|| {
            anyhow::anyhow!(
                "all fallbacks failed, last error: {}",
                last_err.map(|e| e.to_string()).unwrap_or_default()
            )
        })?;

        let timeout_estimator = Arc::new(FixedTimeout);
        let (pending, reactor) = channel
            .new_tunnel(timeout_estimator)
            .await
            .context("creating tunnel")?;

        runtime
            .spawn(async move {
                let _ = reactor.run().await;
            })
            .context("spawning reactor")?;

        let circ_params = exit_circparams_from_netparams(&NetParameters::default())
            .map_err(|e| anyhow::anyhow!("building circuit params: {}", e))?;
        let tunnel = pending
            .create_firsthop_fast(circ_params)
            .await
            .context("CREATE_FAST handshake")?;

        tracing::info!("circuit established");
        Ok(Self {
            tunnel: Arc::new(tunnel),
        })
    }

    /// Send a raw GET request to the directory cache and return the response.
    ///
    /// `path` is the HTTP path, e.g. `/tor/status-vote/current/consensus-microdesc`.
    ///
    /// The response body is decompressed automatically if the server uses
    /// deflate, x-tor-lzma, or x-zstd encoding.
    async fn get(&self, path: &str) -> Result<DirResponse> {
        let mut stream = self
            .tunnel
            .clone()
            .begin_dir_stream()
            .await
            .context("opening BEGINDIR stream")?;

        // Send HTTP/1.0 request — same format Tor uses
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

        let body = decompress(encoding, &body).await.context("decompressing body")?;

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
            decoder.read_to_end(&mut out).await.context("deflate decode")?;
        }
        Some("x-tor-lzma") => {
            let mut decoder = XzDecoder::new(data);
            decoder.read_to_end(&mut out).await.context("xz decode")?;
        }
        Some("x-zstd") => {
            let mut decoder = ZstdDecoder::new(data);
            decoder.read_to_end(&mut out).await.context("zstd decode")?;
        }
        Some(other) => bail!("unsupported encoding: {}", other),
    }
    Ok(out)
}

struct FixedTimeout;
impl tor_proto::client::circuit::TimeoutEstimator for FixedTimeout {
    fn circuit_build_timeout(&self, _length: usize) -> Duration {
        Duration::from_secs(60)
    }
}

#[derive(Parser)]
#[command(name = "tor-raw")]
#[command(about = "Raw Tor directory protocol client — fetch any path")]
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

    let runtime =
        PreferredRuntime::current().context("failed to get tokio runtime")?;
    let client = DirClient::connect(&runtime).await?;

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
