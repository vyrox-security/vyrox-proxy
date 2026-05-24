//! Audit Logging for Vyrox Proxy
//!
//! Append-only audit log for every containment action the proxy
//! executes. Two properties make this log compliance-grade:
//!
//! 1. **Append-only on disk.** Files are opened with the `append`
//!    flag and never overwritten. Even a programming bug here cannot
//!    rewrite history.
//! 2. **SHA-256 hash chain across entries.** Every entry carries the
//!    hash of its predecessor plus its own canonical-JSON hash. A
//!    single tampered byte breaks the chain at that point, and an
//!    auditor can detect the break by recomputing the chain.
//!
//! The hash chain is the property the Python side (`shared/audit.py`)
//! has always carried. Until 2026-05-23 the Rust proxy wrote
//! unchained JSONL, so `/audit/export` outputs from the proxy were
//! not tamper-evident and a compliance team auditing a SOC 2
//! evidence sample would (correctly) reject them. This module
//! brings the two sides into agreement.
//!
//! ## On-disk format
//!
//! Each line is a single JSON object:
//!
//! ```json
//! {
//!   "timestamp": 1700000000,
//!   "tenant_id": "abc123",
//!   "action_type": "HOST_ISOLATION",
//!   "host": "workstation-01",
//!   "approved_by": "analyst@company.com",
//!   "dry_run": false,
//!   "previous_hash": "0000...0000",
//!   "hash": "e3b0c4..."
//! }
//! ```
//!
//! - `previous_hash` is the `hash` of the most recently written
//!   entry, or 64 zeros for the very first entry (the "genesis"
//!   entry).
//! - `hash` is the SHA-256 of the bytes
//!   `previous_hash || canonical_json(payload_fields)`, where
//!   `payload_fields` is everything in the entry except `hash`
//!   itself. The canonical JSON form uses sorted keys and no
//!   whitespace so the chain is reproducible across writers and
//!   platforms.
//!
//! ## Chain continuity across restarts
//!
//! The chain state lives in `ChainState`, which the binary
//! constructs at startup by reading the last hash from the most
//! recent log file. A clean restart picks up exactly where the
//! previous process left off. If the log file does not exist yet
//! (fresh deploy), the chain starts at the genesis hash.

use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// Sentinel value used as `previous_hash` for the first entry in a
/// brand-new log file. Sixty-four ASCII zeros — chosen because the
/// Python side uses the same convention so both chains agree on what
/// "no predecessor" looks like.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One entry on disk.
///
/// Wire-stable: every field appears in the on-disk JSON object,
/// including `previous_hash` and `hash`. Adding or removing a field
/// here breaks any tooling that consumes the JSONL stream, so treat
/// the layout as a compatibility contract.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    /// Unix timestamp (UTC) when the entry was recorded.
    pub timestamp: i64,

    /// Tenant identifier for multi-tenant isolation.
    pub tenant_id: String,

    /// Type of containment action (HOST_ISOLATION, KILL_PROCESS, ...).
    pub action_type: String,

    /// Target hostname or device ID.
    pub host: String,

    /// Discord username who approved this action.
    pub approved_by: String,

    /// Whether this was a dry-run.
    pub dry_run: bool,

    /// SHA-256 hash of the previous entry (or `GENESIS_HASH` for
    /// the very first entry). Together with `hash` this forms the
    /// tamper-evident chain — see module docs.
    #[serde(default = "default_genesis")]
    pub previous_hash: String,

    /// SHA-256 hash of `previous_hash || canonical_json(payload)`.
    /// Computed by `append_audit` immediately before write; the
    /// caller does not set this field.
    #[serde(default)]
    pub hash: String,
}

fn default_genesis() -> String {
    GENESIS_HASH.to_string()
}

/// Running state for the hash chain.
///
/// The state is shared (via `Arc<Mutex<...>>`) so concurrent
/// `append_audit` calls serialize at the chain boundary. The mutex
/// is held only for the brief window between "read last hash" and
/// "write new entry," which is microseconds — there is no real
/// contention at our request rates.
#[derive(Clone)]
pub struct ChainState {
    inner: Arc<Mutex<ChainStateInner>>,
}

struct ChainStateInner {
    last_hash: String,
}

impl ChainState {
    /// Build a chain state initialized to the genesis hash.
    ///
    /// Useful for tests and for the first-boot path when no audit
    /// log exists yet.
    #[allow(dead_code)]
    pub fn genesis() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChainStateInner {
                last_hash: GENESIS_HASH.to_string(),
            })),
        }
    }

    /// Build a chain state seeded from the most recent entry in an
    /// existing log file.
    ///
    /// Reads the file, finds the last well-formed entry, and uses its
    /// `hash` as the seed. If the file does not exist or is empty,
    /// the chain starts at `GENESIS_HASH`. Errors fall through to
    /// genesis as well — better to start fresh than to refuse to
    /// boot. If you want strict mode, swap in a fail-loud helper.
    pub async fn from_file(path: &str) -> Self {
        let last = read_last_hash(path)
            .await
            .unwrap_or_else(|_| GENESIS_HASH.to_string());
        Self {
            inner: Arc::new(Mutex::new(ChainStateInner { last_hash: last })),
        }
    }
}

/// Append an audit entry to the log file, linking it into the chain.
///
/// The caller passes a partially-populated `AuditEntry` (whatever
/// `build_entry` returned, with `previous_hash`/`hash` left at their
/// default values). This function:
///
/// 1. Locks the chain state so concurrent appends serialize.
/// 2. Stamps `previous_hash` from the chain state.
/// 3. Computes `hash` as SHA-256 of `previous_hash` plus the
///    canonical JSON of the entry's payload fields (everything
///    except `hash` itself).
/// 4. Writes the full entry as one JSONL line to disk.
/// 5. Advances the chain state to the new entry's hash.
///
/// Any I/O failure is propagated to the caller, which currently
/// releases the nonce and surfaces HTTP 500 so the bot can retry.
pub async fn append_audit(
    path: &str,
    state: &ChainState,
    mut entry: AuditEntry,
) -> Result<(), std::io::Error> {
    let mut guard = state.inner.lock().await;

    // Stamp the chain link before computing the hash so the hash
    // covers the linkage too.
    entry.previous_hash = guard.last_hash.clone();
    entry.hash = String::new(); // explicit — hash never participates in its own input

    let computed = compute_entry_hash(&entry);
    entry.hash = computed.clone();

    let line = serde_json::to_string(&entry)
        .map_err(|err| std::io::Error::other(format!("serialize entry: {err}")))?;

    // `create(true).append(true)` opens for append and creates the
    // file if it does not exist. The `append` flag is honoured by
    // the kernel, so two appenders cannot stomp each other.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;

    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    // fsync the file before we declare the entry durable. Audit
    // logs are infrequent; the cost is negligible and the alternative
    // is losing the entry on a power cut between write() and the
    // kernel's writeback.
    file.flush().await?;
    file.sync_data().await?;

    guard.last_hash = computed;
    Ok(())
}

/// Construct a fresh `AuditEntry` with the current UTC timestamp
/// and the chain-link / hash fields left blank for `append_audit`
/// to fill in.
pub fn build_entry(
    tenant_id: String,
    action_type: String,
    host: String,
    approved_by: String,
    dry_run: bool,
) -> AuditEntry {
    AuditEntry {
        timestamp: Utc::now().timestamp(),
        tenant_id,
        action_type,
        host,
        approved_by,
        dry_run,
        previous_hash: GENESIS_HASH.to_string(),
        hash: String::new(),
    }
}

/// Read and parse audit log entries from file.
///
/// Used by `GET /audit/export`. Silently skips malformed lines so a
/// single bad entry does not block the whole file from being read.
/// Returns an empty vec if the file does not exist (the request
/// authenticated successfully but the tenant has no history yet).
pub async fn read_audit_logs(path: &str) -> Result<Vec<AuditEntry>, std::io::Error> {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut entries = Vec::new();
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Read the hash of the most recently written entry from a log file.
///
/// Used at startup to seed the chain state. Returns the file's last
/// valid entry's `hash`. If no valid entry exists (empty file, all
/// lines malformed, file not found), returns `GENESIS_HASH`.
pub async fn read_last_hash(path: &str) -> Result<String, std::io::Error> {
    let entries = read_audit_logs(path).await?;
    Ok(entries
        .last()
        .map(|e| e.hash.clone())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| GENESIS_HASH.to_string()))
}

/// Compute the SHA-256 hash of an audit entry's payload fields,
/// linked to the previous entry via `previous_hash`.
///
/// The "canonical payload" is a sorted-key, no-whitespace JSON
/// object containing every field EXCEPT `hash` (which is the output
/// of this function and cannot participate in its own input). Using
/// canonical JSON makes the hash reproducible byte-for-byte across
/// platforms and across the Python / Rust split.
fn compute_entry_hash(entry: &AuditEntry) -> String {
    // We serialise a manual struct so we can control field ordering
    // independently of the `Serialize` derive on `AuditEntry`.
    // `serde_json` already sorts keys alphabetically when given a
    // BTreeMap, but constructing one inline keeps the code obvious.
    let payload = serde_json::json!({
        "action_type": entry.action_type,
        "approved_by": entry.approved_by,
        "dry_run": entry.dry_run,
        "host": entry.host,
        "previous_hash": entry.previous_hash,
        "tenant_id": entry.tenant_id,
        "timestamp": entry.timestamp,
    });
    let canonical = serde_json::to_vec(&payload).expect("payload always serialises");

    let mut hasher = Sha256::new();
    hasher.update(entry.previous_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(&canonical);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn fresh_chain_starts_at_genesis() {
        let state = ChainState::genesis();
        let guard = state.inner.lock().await;
        assert_eq!(guard.last_hash, GENESIS_HASH);
    }

    #[tokio::test]
    async fn append_links_previous_hash() {
        let tmp = NamedTempFile::new().expect("tmp");
        let path = tmp.path().to_str().unwrap().to_string();
        let state = ChainState::genesis();

        let entry_a = build_entry(
            "t1".into(),
            "HOST_ISOLATION".into(),
            "host-a".into(),
            "alice".into(),
            true,
        );
        append_audit(&path, &state, entry_a)
            .await
            .expect("append a");

        let entry_b = build_entry(
            "t1".into(),
            "HOST_ISOLATION".into(),
            "host-b".into(),
            "bob".into(),
            true,
        );
        append_audit(&path, &state, entry_b)
            .await
            .expect("append b");

        let entries = read_audit_logs(&path).await.expect("read");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].previous_hash, GENESIS_HASH);
        assert_eq!(entries[1].previous_hash, entries[0].hash);
        assert_ne!(entries[0].hash, entries[1].hash);
        assert!(!entries[1].hash.is_empty());
    }

    #[tokio::test]
    async fn chain_survives_restart() {
        let tmp = NamedTempFile::new().expect("tmp");
        let path = tmp.path().to_str().unwrap().to_string();

        // "First boot" — write one entry.
        let state1 = ChainState::genesis();
        let entry_a = build_entry(
            "t1".into(),
            "HOST_ISOLATION".into(),
            "host-a".into(),
            "alice".into(),
            true,
        );
        append_audit(&path, &state1, entry_a).await.expect("a");

        // Capture the hash we wrote.
        let entries = read_audit_logs(&path).await.expect("read");
        let saved_hash = entries[0].hash.clone();

        // "Restart" — load chain state from the existing file.
        let state2 = ChainState::from_file(&path).await;
        {
            let guard = state2.inner.lock().await;
            assert_eq!(guard.last_hash, saved_hash, "chain seed should match");
        }

        // Append one more and confirm the link is preserved.
        let entry_b = build_entry(
            "t1".into(),
            "HOST_ISOLATION".into(),
            "host-b".into(),
            "bob".into(),
            true,
        );
        append_audit(&path, &state2, entry_b).await.expect("b");

        let entries = read_audit_logs(&path).await.expect("read");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].previous_hash, saved_hash);
    }

    #[tokio::test]
    async fn tampering_breaks_chain() {
        let tmp = NamedTempFile::new().expect("tmp");
        let path = tmp.path().to_str().unwrap().to_string();
        let state = ChainState::genesis();

        let entry_a = build_entry(
            "t1".into(),
            "HOST_ISOLATION".into(),
            "host-a".into(),
            "alice".into(),
            true,
        );
        append_audit(&path, &state, entry_a).await.expect("a");

        // Re-read, mutate `host` in the on-disk entry, and confirm
        // recomputing the hash produces a different value than what
        // is stored.
        let entries = read_audit_logs(&path).await.expect("read");
        let mut tampered = entries[0].clone();
        tampered.host = "host-evil".into();
        let recomputed = compute_entry_hash(&tampered);
        assert_ne!(recomputed, entries[0].hash, "tamper must be detectable");
    }
}
