use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use rand::prelude::IndexedRandom;
use tor_chanmgr::{ChanMgr, ChanMgrConfig, ChannelUsage, Dormancy};
use tor_checkable::{ExternallySigned, Timebound};
use tor_circmgr::build::exit_circparams_from_netparams;
use tor_dirclient::request::{ConsensusRequest, MicrodescRequest, Requestable};
use tor_memquota::MemoryQuotaTracker;
use tor_netdir::params::NetParameters;
use tor_netdoc::doc::netstatus::{ConsensusFlavor, MdConsensus};
use tor_rtcompat::{PreferredRuntime, SpawnExt};

#[derive(Parser)]
#[command(name = "tor-fast-bootstrap")]
#[command(about = "Download Tor consensus and microdescriptors via Tor's directory protocol")]
struct Cli {
    /// Output directory for downloaded documents
    #[arg(short, long)]
    output_dir: PathBuf,
}

/// Simple fixed-duration timeout estimator for circuit building.
struct FixedTimeout;

impl tor_proto::client::circuit::TimeoutEstimator for FixedTimeout {
    fn circuit_build_timeout(&self, _length: usize) -> Duration {
        Duration::from_secs(60)
    }
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

    let runtime = PreferredRuntime::current()
        .context("failed to get tokio runtime for tor-rtcompat")?;

    // Build the fallback directory list
    let fallbacks = tor_dircommon::fallback::FallbackListBuilder::default()
        .build()
        .context("building fallback list")?;
    if fallbacks.is_empty() {
        bail!("no fallback directories available");
    }

    // Pick a random fallback
    let fallback_vec = fallbacks.iter().collect::<Vec<_>>();
    let fallback = fallback_vec
        .choose(&mut rand::rng())
        .expect("fallbacks not empty");
    tracing::info!("selected fallback directory cache");

    // Create a minimal channel manager
    let memquota = MemoryQuotaTracker::new_noop();
    let chanmgr = ChanMgr::new(
        runtime.clone(),
        ChanMgrConfig::default(),
        Dormancy::Active,
        &NetParameters::default(),
        memquota,
    )
    .context("creating channel manager")?;

    // Connect to the fallback
    tracing::info!("connecting to fallback directory cache...");
    let (channel, _provenance) = chanmgr
        .get_or_launch(*fallback, ChannelUsage::Dir)
        .await
        .context("connecting to fallback directory")?;
    tracing::info!("channel established");

    // Build a 1-hop circuit (CREATE_FAST, standard for dir fetches)
    let timeout_estimator = Arc::new(FixedTimeout);
    let (pending_tunnel, reactor) = channel
        .new_tunnel(timeout_estimator)
        .await
        .context("creating tunnel")?;

    // Spawn the reactor — it processes cells for this circuit
    runtime.spawn(async move {
        let _ = reactor.run().await;
    }).context("spawning reactor")?;

    let circ_params = exit_circparams_from_netparams(&NetParameters::default())
        .map_err(|e| anyhow::anyhow!("building circuit params: {}", e))?;
    let tunnel = pending_tunnel
        .create_firsthop_fast(circ_params)
        .await
        .context("CREATE_FAST handshake")?;
    let tunnel = Arc::new(tunnel);
    tracing::info!("circuit established");

    // --- Download consensus ---
    tracing::info!("downloading consensus...");
    let consensus_req = ConsensusRequest::new(ConsensusFlavor::Microdesc);
    tracing::debug!("request: {:?}", consensus_req.debug_request());

    let mut stream = tunnel
        .clone()
        .begin_dir_stream()
        .await
        .context("opening dir stream for consensus")?;

    let response = tor_dirclient::send_request(&runtime, &consensus_req, &mut stream, None)
        .await
        .context("sending consensus request")?;

    let consensus_bytes = response
        .into_output()
        .map_err(|e| anyhow::anyhow!("consensus download failed: {}", e))?;
    let consensus_text =
        String::from_utf8(consensus_bytes).context("consensus is not valid UTF-8")?;
    tracing::info!("consensus downloaded ({} bytes)", consensus_text.len());

    // --- Parse consensus to extract microdesc digests ---
    let (_signed, _remainder, unchecked) =
        MdConsensus::parse(&consensus_text).context("parsing consensus")?;
    let consensus = unchecked
        .dangerously_assume_timely()
        .dangerously_assume_wellsigned();

    let lifetime = consensus.lifetime();
    let num_relays = consensus.relays().len();
    tracing::info!(
        "consensus has {} relays, valid until {:?}",
        num_relays,
        lifetime.valid_until()
    );

    let digests: Vec<_> = consensus
        .relays()
        .iter()
        .map(|rs| *rs.md_digest())
        .collect();
    tracing::info!("{} microdescriptor digests to fetch", digests.len());

    // --- Download microdescriptors in batches ---
    let batch_size = 500;
    let mut all_microdescs = Vec::new();

    for (batch_idx, batch) in digests.chunks(batch_size).enumerate() {
        tracing::info!(
            "downloading microdescs batch {}/{} ({} digests)...",
            batch_idx + 1,
            (digests.len() + batch_size - 1) / batch_size,
            batch.len()
        );

        let req: MicrodescRequest = batch.iter().copied().collect();

        let mut stream = tunnel
            .clone()
            .begin_dir_stream()
            .await
            .with_context(|| format!("opening dir stream for microdesc batch {}", batch_idx))?;

        let response = tor_dirclient::send_request(&runtime, &req, &mut stream, None)
            .await
            .with_context(|| format!("microdesc batch {} request", batch_idx))?;

        let md_bytes = response
            .into_output()
            .map_err(|e| anyhow::anyhow!("microdesc batch {} download failed: {}", batch_idx, e))?;

        all_microdescs.extend_from_slice(&md_bytes);
    }

    let microdescs_text =
        String::from_utf8(all_microdescs).context("microdescs are not valid UTF-8")?;
    tracing::info!(
        "all microdescriptors downloaded ({} bytes)",
        microdescs_text.len()
    );

    // --- Write output files ---
    let consensus_path = cli.output_dir.join("consensus-microdesc");
    std::fs::write(&consensus_path, &consensus_text)
        .with_context(|| format!("writing {:?}", consensus_path))?;
    tracing::info!("wrote {}", consensus_path.display());

    let microdescs_path = cli.output_dir.join("microdescs");
    std::fs::write(&microdescs_path, &microdescs_text)
        .with_context(|| format!("writing {:?}", microdescs_path))?;
    tracing::info!("wrote {}", microdescs_path.display());

    let metadata = serde_json::json!({
        "consensus_flavor": "microdesc",
        "valid_after": humantime::format_rfc3339(lifetime.valid_after()).to_string(),
        "fresh_until": humantime::format_rfc3339(lifetime.fresh_until()).to_string(),
        "valid_until": humantime::format_rfc3339(lifetime.valid_until()).to_string(),
        "num_relays": num_relays,
        "num_microdescs_requested": digests.len(),
        "microdescs_bytes": microdescs_text.len(),
    });
    let metadata_path = cli.output_dir.join("metadata.json");
    std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)
        .with_context(|| format!("writing {:?}", metadata_path))?;
    tracing::info!("wrote {}", metadata_path.display());

    tracing::info!("done!");
    Ok(())
}
