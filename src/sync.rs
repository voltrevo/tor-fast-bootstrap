//! Consensus + microdescriptor sync logic with relay-style scheduling.

use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use base64ct::Encoding as _;
use rand::Rng;
use tor_checkable::{ExternallySigned, TimeValidityError, Timebound};
use tor_netdoc::doc::netstatus::{Lifetime, MdConsensus};

use arti_client::TorClient;

use crate::cache::MicrodescCache;

/// Fetch consensus, parse it, fetch missing microdescs, write everything to disk.
/// Returns the consensus lifetime for scheduling the next sync.
pub async fn sync_once(
    client: &TorClient<tor_rtcompat::PreferredRuntime>,
    output_dir: &Path,
    cache: &mut MicrodescCache,
) -> Result<Lifetime> {
    // --- Fetch consensus ---
    tracing::info!("fetching consensus...");
    let consensus_bytes =
        crate::dir::get(client, "/tor/status-vote/current/consensus-microdesc").await?;
    let consensus_text =
        String::from_utf8(consensus_bytes).context("consensus is not valid UTF-8")?;

    // --- Parse consensus ---
    let (_signed, _remainder, unchecked) =
        MdConsensus::parse(&consensus_text).context("parsing consensus")?;
    let now = SystemTime::now();
    let consensus = unchecked
        .check_valid_at(&now)
        .map_err(|e: TimeValidityError| anyhow::anyhow!("consensus not timely: {}", e))?
        .dangerously_assume_wellsigned();

    let lifetime = consensus.lifetime().clone();
    let num_relays = consensus.relays().len();
    tracing::info!(
        "consensus: {} relays, valid_after={}, fresh_until={}, valid_until={}",
        num_relays,
        humantime::format_rfc3339(lifetime.valid_after()),
        humantime::format_rfc3339(lifetime.fresh_until()),
        humantime::format_rfc3339(lifetime.valid_until()),
    );

    // --- Fetch authority certificates ---
    tracing::info!("fetching authority certificates...");
    let certs_bytes = crate::dir::get(client, "/tor/keys/all").await?;
    let certs_text =
        String::from_utf8(certs_bytes).context("authority certs are not valid UTF-8")?;
    tracing::info!("fetched authority certificates ({} bytes)", certs_text.len());

    // --- Extract microdesc digests and diff against cache ---
    let digests: Vec<_> = consensus
        .relays()
        .iter()
        .map(|rs| *rs.md_digest())
        .collect();

    cache.retain(&digests);
    let missing = cache.missing(&digests);
    tracing::info!(
        "microdescs: {} in consensus, {} cached, {} to fetch",
        digests.len(),
        cache.len(),
        missing.len(),
    );

    // --- Fetch only missing microdescs in batches ---
    let batch_size = 500;
    if !missing.is_empty() {
        let total_batches = (missing.len() + batch_size - 1) / batch_size;
        for (batch_idx, batch) in missing.chunks(batch_size).enumerate() {
            tracing::info!(
                "fetching microdescs batch {}/{}...",
                batch_idx + 1,
                total_batches,
            );

            let digests_str: Vec<String> = batch
                .iter()
                .map(|d| base64ct::Base64Unpadded::encode_string(d))
                .collect();
            let path = format!("/tor/micro/d/{}", digests_str.join("-"));

            match crate::dir::get(client, &path).await {
                Ok(bytes) => {
                    let text = String::from_utf8(bytes)
                        .context("microdesc response is not valid UTF-8")?;
                    let added = cache.ingest(&text);
                    tracing::debug!("batch {}: added {} microdescs", batch_idx + 1, added);
                }
                Err(e) => {
                    tracing::warn!("microdesc batch {} failed: {}", batch_idx + 1, e);
                }
            }
        }
    }

    let still_missing = cache.missing(&digests);
    tracing::info!(
        "microdescs: {} cached ({} still missing)",
        cache.len(),
        still_missing.len(),
    );

    // --- Write files atomically (write to .tmp, then rename) ---
    atomic_write(output_dir, "consensus-microdesc", consensus_text.as_bytes())?;
    tracing::info!(
        "wrote consensus-microdesc ({} bytes)",
        consensus_text.len()
    );

    atomic_write(output_dir, "authority-certs", certs_text.as_bytes())?;
    tracing::info!("wrote authority-certs ({} bytes)", certs_text.len());

    let microdescs_blob = cache.to_concatenated();
    atomic_write(output_dir, "microdescs", &microdescs_blob)?;
    tracing::info!("wrote microdescs ({} bytes)", microdescs_blob.len());

    let metadata = serde_json::json!({
        "consensus_flavor": "microdesc",
        "valid_after": humantime::format_rfc3339(lifetime.valid_after()).to_string(),
        "fresh_until": humantime::format_rfc3339(lifetime.fresh_until()).to_string(),
        "valid_until": humantime::format_rfc3339(lifetime.valid_until()).to_string(),
        "num_relays": num_relays,
        "authority_certs_bytes": certs_text.len(),
        "num_microdescs_in_cache": cache.len(),
        "num_microdescs_missing": still_missing.len(),
        "microdescs_bytes": microdescs_blob.len(),
        "synced_at": humantime::format_rfc3339(SystemTime::now()).to_string(),
    });
    atomic_write(
        output_dir,
        "metadata.json",
        serde_json::to_string_pretty(&metadata)?.as_bytes(),
    )?;

    Ok(lifetime)
}

/// Compute the relay-style sync delay: random time in the first half-interval
/// after `fresh_until`.
///
/// Per dir-spec: "the cache downloads a new consensus document at a randomly
/// chosen time in the first half-interval after its current consensus stops
/// being fresh."
pub fn relay_sync_delay(fresh_until: SystemTime, valid_until: SystemTime) -> Duration {
    let half_interval = valid_until
        .duration_since(fresh_until)
        .unwrap_or(Duration::from_secs(1800))
        / 2;
    let offset = rand::rng().random_range(Duration::ZERO..=half_interval);
    let target = fresh_until + offset;
    target
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO)
}

/// Write `data` to `dir/name` atomically via a `.tmp` intermediate.
fn atomic_write(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    let tmp = dir.join(format!("{}.tmp", name));
    let dst = dir.join(name);
    std::fs::write(&tmp, data).with_context(|| format!("writing {:?}", tmp))?;
    std::fs::rename(&tmp, &dst).with_context(|| format!("renaming to {:?}", dst))?;
    Ok(())
}
