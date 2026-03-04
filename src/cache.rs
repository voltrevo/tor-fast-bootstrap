//! In-memory caches for consensus, authority certs, and microdescriptors.

use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result};
use digest::Digest;
use tor_checkable::{SelfSigned, Timebound};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdoc::doc::authcert::AuthCert;
use tor_netdoc::doc::microdesc::{MdDigest, MicrodescReader};
use tor_netdoc::doc::netstatus::MdConsensus;
use tor_netdoc::AllowAnnotations;

/// Parse a consensus timestamp line like `valid-after YYYY-MM-DD HH:MM:SS`.
fn parse_timestamp(text: &str, prefix: &str) -> Option<SystemTime> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            let rfc3339 = format!("{}Z", rest.trim().replace(' ', "T"));
            return humantime::parse_rfc3339(&rfc3339).ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// ConsensusCache
// ---------------------------------------------------------------------------

/// Cached consensus text and SHA3-256 digest of its signed portion.
/// Used to request diffs on subsequent fetches.
pub struct ConsensusCache {
    state: Option<ConsensusState>,
}

struct ConsensusState {
    text: String,
    sha3_of_signed: [u8; 32],
    valid_after: SystemTime,
    fresh_until: SystemTime,
}

impl ConsensusCache {
    /// Create an empty cache (no previous consensus).
    pub fn new() -> Self {
        Self { state: None }
    }

    /// Load a previous consensus from disk and compute its signed-portion SHA3-256.
    /// Returns an empty cache if the file doesn't exist or can't be parsed.
    pub fn load_from_file(path: &Path) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("no existing consensus file, starting fresh");
                return Self::new();
            }
            Err(e) => {
                tracing::warn!("failed to read previous consensus: {}", e);
                return Self::new();
            }
        };
        let valid_after = match parse_timestamp(&text, "valid-after ") {
            Some(t) => t,
            None => {
                tracing::warn!("no valid-after in cached consensus");
                return Self::new();
            }
        };
        let fresh_until = match parse_timestamp(&text, "fresh-until ") {
            Some(t) => t,
            None => {
                tracing::warn!("no fresh-until in cached consensus");
                return Self::new();
            }
        };
        match MdConsensus::parse(&text) {
            Ok((signed, _remainder, _unchecked)) => {
                let sha3: [u8; 32] = sha3::Sha3_256::digest(signed.as_bytes()).into();
                tracing::info!(
                    "loaded previous consensus ({} bytes, valid_after={}, fresh_until={}, sha3={})",
                    text.len(),
                    humantime::format_rfc3339(valid_after),
                    humantime::format_rfc3339(fresh_until),
                    hex::encode(sha3),
                );
                Self {
                    state: Some(ConsensusState {
                        text,
                        sha3_of_signed: sha3,
                        valid_after,
                        fresh_until,
                    }),
                }
            }
            Err(e) => {
                tracing::warn!("failed to parse previous consensus: {}", e);
                Self::new()
            }
        }
    }

    /// Hex-encoded SHA3-256 of the signed portion, for the
    /// `X-Or-Diff-From-Consensus` request header.
    pub fn diff_hex(&self) -> Option<String> {
        self.state.as_ref().map(|s| hex::encode(s.sha3_of_signed))
    }

    /// The previous consensus text (needed to apply diffs).
    pub fn text(&self) -> Option<&str> {
        self.state.as_ref().map(|s| s.text.as_str())
    }

    /// Whether the cached consensus is still fresh (i.e. `now < fresh_until`).
    pub fn is_fresh(&self) -> bool {
        self.state
            .as_ref()
            .map(|s| SystemTime::now() < s.fresh_until)
            .unwrap_or(false)
    }

    /// Resolve a consensus response: apply diff if needed, then update cache.
    /// Returns the full consensus text ready for parsing.
    /// Errors if the response contains an older consensus than what we have.
    pub fn resolve_response(&mut self, response: String) -> Result<String> {
        let consensus_text = if tor_consdiff::looks_like_diff(&response) {
            let old_text = self
                .text()
                .ok_or_else(|| anyhow::anyhow!("got diff but no previous consensus"))?;
            tracing::info!(
                "applying consensus diff ({} bytes diff, {} bytes old)",
                response.len(),
                old_text.len(),
            );
            let result = tor_consdiff::apply_diff(old_text, &response, None)
                .context("applying consensus diff")?;
            result
                .check_digest()
                .context("consensus diff digest mismatch")?;
            result.to_string()
        } else {
            tracing::info!("got full consensus ({} bytes)", response.len());
            response
        };

        // Extract timestamps from text and compute SHA3-256 of signed portion
        let new_valid_after = parse_timestamp(&consensus_text, "valid-after ")
            .context("no valid-after in consensus response")?;
        let new_fresh_until = parse_timestamp(&consensus_text, "fresh-until ")
            .context("no fresh-until in consensus response")?;

        // Reject if older than what we already have
        if let Some(ref state) = self.state {
            if new_valid_after < state.valid_after {
                anyhow::bail!(
                    "ignoring older consensus (valid_after={}, have={})",
                    humantime::format_rfc3339(new_valid_after),
                    humantime::format_rfc3339(state.valid_after),
                );
            }
        }

        let (signed, _remainder, _unchecked) =
            MdConsensus::parse(&consensus_text).context("parsing consensus for digest")?;
        let sha3: [u8; 32] = sha3::Sha3_256::digest(signed.as_bytes()).into();
        self.state = Some(ConsensusState {
            text: consensus_text.clone(),
            sha3_of_signed: sha3,
            valid_after: new_valid_after,
            fresh_until: new_fresh_until,
        });

        Ok(consensus_text)
    }
}

// ---------------------------------------------------------------------------
// AuthCertCache
// ---------------------------------------------------------------------------

/// Cached authority certificates (raw text + parsed certs).
/// Re-fetch is only needed when not all trusted authorities have a valid cert.
pub struct AuthCertCache {
    text: String,
    certs: Vec<AuthCert>,
}

impl AuthCertCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            text: String::new(),
            certs: Vec::new(),
        }
    }

    /// Load authority certs from a file on disk, parse and validate them.
    /// Returns an empty cache if the file doesn't exist.
    pub fn load_from_file(path: &Path, now: &SystemTime, trusted_ids: &[RsaIdentity]) -> Self {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("no existing authority-certs file, starting fresh");
                return Self::new();
            }
            Err(e) => {
                tracing::warn!("failed to read authority certs: {}", e);
                return Self::new();
            }
        };
        let certs = parse_and_validate_certs(&text, now, trusted_ids);
        tracing::info!(
            "loaded {} valid authority certs from cache ({} bytes)",
            certs.len(),
            text.len(),
        );
        Self { text, certs }
    }

    /// Check whether we have a valid cert for every trusted authority.
    pub fn has_all(&self, trusted_ids: &[RsaIdentity]) -> bool {
        trusted_ids
            .iter()
            .all(|id| self.certs.iter().any(|c| c.id_fingerprint() == id))
    }

    /// Re-validate cached certs against current time, dropping any that expired.
    pub fn refresh(&mut self, now: &SystemTime, trusted_ids: &[RsaIdentity]) {
        let before = self.certs.len();
        self.certs = parse_and_validate_certs(&self.text, now, trusted_ids);
        let dropped = before.saturating_sub(self.certs.len());
        if dropped > 0 {
            tracing::info!("dropped {} expired authority certs", dropped);
        }
    }

    /// Replace the cache contents with a freshly fetched response.
    pub fn update(&mut self, text: String, now: &SystemTime, trusted_ids: &[RsaIdentity]) {
        self.certs = parse_and_validate_certs(&text, now, trusted_ids);
        self.text = text;
    }

    /// The parsed, validated certs (for consensus signature verification).
    pub fn certs(&self) -> &[AuthCert] {
        &self.certs
    }

    /// The raw concatenated cert text (for writing to disk).
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Parse authority certs from text, keeping only valid certs from trusted authorities.
fn parse_and_validate_certs(
    text: &str,
    now: &SystemTime,
    trusted_ids: &[RsaIdentity],
) -> Vec<AuthCert> {
    let iter = match AuthCert::parse_multiple(text) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!("failed to parse authority certs: {}", e);
            return Vec::new();
        }
    };
    let mut certs = Vec::new();
    for item in iter {
        match item {
            Ok(unchecked) => match unchecked.check_signature() {
                Ok(timebound) => match timebound.check_valid_at(now) {
                    Ok(cert) => {
                        if trusted_ids.contains(cert.id_fingerprint()) {
                            certs.push(cert);
                        }
                    }
                    Err(_) => {}
                },
                Err(_) => {}
            },
            Err(_) => {}
        }
    }
    certs
}

// ---------------------------------------------------------------------------
// MicrodescCache
// ---------------------------------------------------------------------------

/// In-memory cache of microdescriptors keyed by their SHA-256 digest.
pub struct MicrodescCache {
    /// Map from digest to raw microdescriptor text.
    entries: HashMap<MdDigest, String>,
}

impl MicrodescCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Load cached microdescs from a file on disk (the concatenated microdescs file).
    /// Parses individual microdescs and indexes them by digest.
    /// Errors in individual microdescs are logged and skipped.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("no existing microdescs file, starting with empty cache");
                return Ok(Self::new());
            }
            Err(e) => return Err(e).context("reading microdescs file"),
        };

        let mut cache = Self::new();
        let reader = MicrodescReader::new(&text, &AllowAnnotations::AnnotationsNotAllowed)
            .context("parsing microdescs file")?;
        for item in reader {
            match item {
                Ok(annotated) => {
                    let digest = *annotated.md().digest();
                    if let Some(raw) = annotated.within(&text) {
                        cache.entries.insert(digest, raw.to_string());
                    }
                }
                Err(e) => {
                    tracing::warn!("skipping unparseable microdesc: {}", e);
                }
            }
        }
        tracing::info!("loaded {} microdescs from cache", cache.entries.len());
        Ok(cache)
    }

    /// Return digests from `wanted` that are not in the cache.
    pub fn missing(&self, wanted: &[MdDigest]) -> Vec<MdDigest> {
        wanted
            .iter()
            .filter(|d| !self.entries.contains_key(*d))
            .copied()
            .collect()
    }

    /// Ingest a concatenated microdesc response, adding new entries to the cache.
    /// Returns the number of new microdescs added.
    pub fn ingest(&mut self, text: &str) -> usize {
        let reader = match MicrodescReader::new(text, &AllowAnnotations::AnnotationsNotAllowed) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("failed to parse microdesc response: {}", e);
                return 0;
            }
        };
        let mut added = 0;
        for item in reader {
            match item {
                Ok(annotated) => {
                    let digest = *annotated.md().digest();
                    if let Some(raw) = annotated.within(text) {
                        self.entries.entry(digest).or_insert_with(|| {
                            added += 1;
                            raw.to_string()
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!("skipping unparseable microdesc in response: {}", e);
                }
            }
        }
        added
    }

    /// Retain only entries whose digest is in `wanted`, dropping the rest.
    pub fn retain(&mut self, wanted: &[MdDigest]) {
        let before = self.entries.len();
        let wanted_set: std::collections::HashSet<&MdDigest> = wanted.iter().collect();
        self.entries.retain(|k, _| wanted_set.contains(k));
        let dropped = before - self.entries.len();
        if dropped > 0 {
            tracing::info!("dropped {} stale microdescs from cache", dropped);
        }
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Serialize all cached microdescs as a concatenated blob.
    pub fn to_concatenated(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for text in self.entries.values() {
            out.extend_from_slice(text.as_bytes());
        }
        out
    }
}
