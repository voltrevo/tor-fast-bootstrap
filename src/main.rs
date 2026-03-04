mod dir;
mod server;
mod store;
mod sync;

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::Parser;

use arti_client::{TorClient, TorClientConfig};

#[derive(Parser)]
#[command(name = "tor-fast-bootstrap")]
#[command(about = "Long-running Tor directory cache — syncs like a relay")]
struct Cli {
    /// Output directory for cached documents
    #[arg(short, long)]
    output_dir: PathBuf,

    /// Exit after the first successful sync instead of looping
    #[arg(long)]
    once: bool,

    /// HTTP server port (0 to disable)
    #[arg(short, long, default_value_t = 42298)]
    port: u16,
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
    std::fs::create_dir_all(&cli.output_dir)
        .with_context(|| format!("creating output dir {:?}", cli.output_dir))?;

    // Start HTTP server (unless disabled with --port 0)
    if cli.port != 0 {
        let output_dir = cli.output_dir.clone();
        let port = cli.port;
        tokio::spawn(async move {
            if let Err(e) = server::run(output_dir, port).await {
                tracing::error!("HTTP server failed: {:#}", e);
            }
        });
    }

    // Load stores from previous run
    let mut stores = store::Stores::load(&cli.output_dir, &SystemTime::now())?;

    tracing::info!("bootstrapping TorClient...");
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config)
        .await
        .context("bootstrapping TorClient")?;
    tracing::info!("TorClient bootstrapped");

    loop {
        match sync::sync_once(&client, &cli.output_dir, &mut stores).await {
            Ok(Some(lifetime)) => {
                if cli.once {
                    return Ok(());
                }
                let delay =
                    sync::relay_sync_delay(lifetime.fresh_until(), lifetime.valid_until());
                tracing::info!(
                    "next sync in {} (at ~{})",
                    humantime::format_duration(delay),
                    humantime::format_rfc3339(SystemTime::now() + delay),
                );
                tokio::time::sleep(delay).await;
            }
            Ok(None) => {
                let retry = Duration::from_secs(60);
                tracing::info!("retrying in {}", humantime::format_duration(retry));
                tokio::time::sleep(retry).await;
            }
            Err(e) => {
                tracing::error!("sync failed: {:#}", e);
                let retry = Duration::from_secs(60);
                tracing::info!("retrying in {}", humantime::format_duration(retry));
                tokio::time::sleep(retry).await;
            }
        }
    }
}
