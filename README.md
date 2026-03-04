# tor-fast-bootstrap

Long-running Tor directory cache daemon that syncs consensus documents, authority certificates, and microdescriptors directly from the Tor network using the directory protocol. Serves a pre-built bootstrap archive over HTTP for fast client bootstrapping.

## How it works

The daemon uses [Arti](https://gitlab.torproject.org/tpo/core/arti) to connect to Tor directory authorities via BEGINDIR streams. It follows the relay-style sync schedule from [dir-spec §5.3](https://spec.torproject.org/dir-spec/directory-cache-operation.html#download-ns-from-auth), fetching a new consensus shortly after the current one stops being fresh.

Each sync cycle:

1. Opens a dedicated directory circuit (retired immediately so it's never reused by other code)
2. Fetches the microdescriptor consensus (requesting a diff via `X-Or-Diff-From-Consensus` if a previous consensus is cached)
3. Fetches authority certificates (only if any trusted authority is missing a valid cert)
4. Verifies the consensus (timeliness + authority signatures)
5. Fetches only missing microdescriptors in batches of 500
6. Writes all files atomically to the output directory
7. Builds a `bootstrap.zip` archive with pre-compressed brotli and gzip variants

## Building

Requires Rust 1.89+. Arti dependencies are fetched from the [official GitLab repo](https://gitlab.torproject.org/tpo/core/arti) at a pinned commit.

```
cargo build --release
```

## Usage

```
tor-fast-bootstrap --output-dir ./data
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `-o, --output-dir` | (required) | Directory for cached documents and bootstrap archive |
| `-p, --port` | `42298` | HTTP server port (`0` to disable) |
| `--once` | off | Exit after the first successful sync instead of looping |

### Environment

Set `RUST_LOG` to control log verbosity (default: `info`). Example:

```
RUST_LOG=debug tor-fast-bootstrap -o ./data
```

## HTTP endpoints

| Path | Content-Type | Content negotiation | Description |
|---|---|---|---|
| `/metadata.json` | `application/json` | brotli, gzip, identity | Sync metadata (timestamps, relay count, file sizes) |
| `/bootstrap.zip` | `application/zip` | brotli, gzip, identity | Bootstrap archive containing all three documents |
| `/bootstrap.zip.br` | `application/octet-stream` | none | Raw brotli-compressed archive (no `Content-Encoding` header) |

All endpoints return `503 Service Unavailable` before the first successful sync.

The server negotiates `Accept-Encoding` and serves pre-compressed `.br` or `.gz` variants from disk — no on-the-fly compression.

## Output files

After a successful sync, the output directory contains:

| File | Description |
|---|---|
| `consensus-microdesc.txt` | Current microdescriptor consensus |
| `authority-certs.txt` | Trusted authority certificates |
| `microdescs.txt` | Concatenated microdescriptors for all relays in the consensus |
| `metadata.json` | Sync metadata (consensus lifetime, relay count, file sizes, sync timestamp) |
| `bootstrap.zip` | Uncompressed zip archive of the three `.txt` files (stored, no zip-level compression) |
| `bootstrap.zip.br` | Brotli-compressed bootstrap.zip (quality 6) |
| `bootstrap.zip.gz` | Gzip-compressed bootstrap.zip |

The zip archive uses `Stored` compression (no deflate) since the outer brotli/gzip layer handles compression. Files inside the archive are under a `bootstrap/` prefix.

All files are written atomically via a `.tmp` intermediate to avoid serving partial data.
