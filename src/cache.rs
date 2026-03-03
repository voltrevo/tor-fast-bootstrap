//! In-memory microdescriptor cache keyed by SHA-256 digest.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use tor_netdoc::doc::microdesc::{MdDigest, MicrodescReader};
use tor_netdoc::AllowAnnotations;

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
