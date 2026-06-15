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
//!   "simulated": false,
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
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/// Sentinel value used as `previous_hash` for the first entry in a
/// brand-new log file. Sixty-four ASCII zeros - chosen because the
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

    /// Honesty label recording that the action targeted a demo/mock fleet
    /// rather than a real customer EDR. Set from the tenant's `is_demo` flag
    /// on the Python side and carried inside the signed request body. It is a
    /// label ONLY: the proxy still performs the real EDR call (which, for a
    /// demo tenant, lands on the bundled mock EDR), so this records WHAT was
    /// targeted, not WHETHER an action ran.
    pub simulated: bool,

    /// SHA-256 hash of the previous entry (or `GENESIS_HASH` for
    /// the very first entry). Together with `hash` this forms the
    /// tamper-evident chain - see module docs.
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
/// "write new entry," which is microseconds - there is no real
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
    /// genesis as well - better to start fresh than to refuse to
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
    // Open OUTSIDE the chain lock. `create(true).append(true)` opens for append
    // and creates the file if absent; the kernel-honoured append flag means two
    // appenders cannot stomp each other. Opening here rather than inside the
    // lock keeps a slow open() off the critical section, so it never serializes
    // one tenant's containment behind another's (T72). The chain link + write +
    // fsync below stay under the lock, so the on-disk order still matches the
    // chain order.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;

    let mut guard = state.inner.lock().await;

    // Stamp the chain link before computing the hash so the hash
    // covers the linkage too.
    entry.previous_hash = guard.last_hash.clone();
    entry.hash = String::new(); // explicit - hash never participates in its own input

    let computed = compute_entry_hash(&entry);
    entry.hash = computed.clone();

    let line = serde_json::to_string(&entry)
        .map_err(|err| std::io::Error::other(format!("serialize entry: {err}")))?;

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
    simulated: bool,
) -> AuditEntry {
    AuditEntry {
        timestamp: Utc::now().timestamp(),
        tenant_id,
        action_type,
        host,
        approved_by,
        simulated,
        previous_hash: GENESIS_HASH.to_string(),
        hash: String::new(),
    }
}

/// Read and parse ALL audit log entries from file into memory.
///
/// Silently skips malformed lines so a single bad entry does not block the
/// whole file from being read. Returns an empty vec if the file does not exist.
///
/// This loads the entire file into RAM. The `GET /audit/export` path uses the
/// streaming, tenant-filtered `read_tenant_entries_streaming` instead (PRX-04)
/// so file-size x concurrent exports cannot become an unbounded-memory
/// amplifier. This whole-file reader stays for the tests and the chain-seed
/// helper, where the input is small and bounded.
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

/// Stream the audit log line-by-line, returning only the entries for one
/// tenant (PRX-04).
///
/// Unlike `read_audit_logs`, this never holds the whole file in memory: it
/// reads one line at a time through a `BufReader` and keeps only the entries
/// whose `tenant_id` matches. Peak memory is one line plus the filtered result,
/// not the full file, so a large log and many concurrent `/audit/export` calls
/// no longer multiply into an unbounded-memory amplifier. (The matched result
/// is still materialised because the endpoint returns a JSON array; a tenant's
/// own slice is bounded by that tenant's history, not by the global file.)
///
/// Malformed lines are skipped, mirroring `read_audit_logs`. A missing file
/// yields an empty vec (authenticated request, tenant has no history yet).
pub async fn read_tenant_entries_streaming(
    path: &str,
    tenant_id: &str,
) -> Result<Vec<AuditEntry>, std::io::Error> {
    let file = match File::open(path).await {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut lines = BufReader::new(file).lines();
    let mut entries = Vec::new();
    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
            if entry.tenant_id == tenant_id {
                entries.push(entry);
            }
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
///
/// ## Canonical form (must match `shared/audit.py` EXACTLY)
///
/// The tamper-evident chain only cross-verifies if both languages hash the
/// same bytes. The spec, pinned by the cross-language fixture test below:
///
/// - keys sorted ascending by Unicode code point,
/// - compact separators (`,` and `:`, no spaces),
/// - UTF-8, non-ASCII NOT escaped (`é` is the two raw bytes `0xC3 0xA9`,
///   never `é`).
///
/// We build the payload from a `BTreeMap`, which guarantees the sorted-key
/// ordering by construction rather than by hand-written field order. The
/// previous code used `serde_json::json!{}` (an insertion-ordered Map), so the
/// canonical form rested on the author keeping the literal alphabetical, one
/// reorder away from silently diverging the two chains (PRX-02). `serde_json`'s
/// default compact serializer already emits raw UTF-8 (it does not escape
/// non-ASCII), so the spec holds without any extra flags. The cross-language
/// fixture `canonical_hash_matches_python_fixture` is the regression guard.
fn compute_entry_hash(entry: &AuditEntry) -> String {
    let canonical = canonical_payload_bytes(entry);

    let mut hasher = Sha256::new();
    hasher.update(entry.previous_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(&canonical);
    hex::encode(hasher.finalize())
}

/// Serialize an entry's payload fields into the canonical byte form the hash
/// is computed over: every field except `hash`, keys sorted ascending by code
/// point, compact separators, raw UTF-8.
///
/// Factored out so the canonical-form spec lives in one place and the
/// cross-language fixture test can exercise the exact serializer the hash uses.
/// A `BTreeMap` enforces the sorted-key ordering by type, not by discipline.
fn canonical_payload_bytes(entry: &AuditEntry) -> Vec<u8> {
    use serde_json::Value;
    use std::collections::BTreeMap;

    let mut payload: BTreeMap<String, Value> = BTreeMap::new();
    payload.insert("action_type".into(), Value::from(entry.action_type.clone()));
    payload.insert("approved_by".into(), Value::from(entry.approved_by.clone()));
    payload.insert("host".into(), Value::from(entry.host.clone()));
    payload.insert(
        "previous_hash".into(),
        Value::from(entry.previous_hash.clone()),
    );
    payload.insert("simulated".into(), Value::from(entry.simulated));
    payload.insert("tenant_id".into(), Value::from(entry.tenant_id.clone()));
    payload.insert("timestamp".into(), Value::from(entry.timestamp));
    serde_json::to_vec(&payload).expect("payload always serialises")
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

        // "First boot" - write one entry.
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

        // "Restart" - load chain state from the existing file.
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

    /// Cross-language canonical-serializer fixture (PRX-02, theme 2).
    ///
    /// The Rust and Python audit chains are only cross-verifiable, the core
    /// tamper-evidence claim, if both hash the same canonical bytes. This pins
    /// the exact serializer to the spec: keys sorted ascending by code point,
    /// compact separators (`,`/`:`, no spaces), raw UTF-8 (non-ASCII NOT
    /// escaped). The constant is asserted by the Python side too, so if either
    /// serializer drifts, this test (and its Python twin) goes red.
    ///
    /// Input `{"a":"x","m":1,"z":"é"}` must serialise to the exact bytes
    /// `{"a":"x","m":1,"z":"é"}` (with `é` as the two UTF-8 bytes 0xC3 0xA9,
    /// not the escape `é`), whose sha256 is the constant below.
    #[test]
    fn canonical_hash_matches_python_fixture() {
        use serde_json::Value;
        use std::collections::BTreeMap;

        let mut payload: BTreeMap<String, Value> = BTreeMap::new();
        // Insert OUT of order on purpose: the BTreeMap must sort them.
        payload.insert("z".into(), Value::from("é"));
        payload.insert("a".into(), Value::from("x"));
        payload.insert("m".into(), Value::from(1));

        let bytes = serde_json::to_vec(&payload).expect("serialise fixture");

        // Byte-exact canonical form: sorted keys, compact, raw UTF-8 (é is the
        // two bytes 0xC3 0xA9, never an escaped é).
        assert_eq!(
            bytes, b"{\"a\":\"x\",\"m\":1,\"z\":\"\xc3\xa9\"}",
            "canonical bytes must match the Python ensure_ascii=False sort_keys form"
        );

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let digest = hex::encode(hasher.finalize());
        assert_eq!(
            digest, "766b45d54caad1b76f358687b74b45108a81ea40f94cfa6d048eb1efd77583e9",
            "canonical sha256 must equal the constant the Python audit chain asserts"
        );
    }

    /// The entry payload serializer (the one the chain hash covers) must emit
    /// sorted keys, the `simulated` field, and raw non-ASCII bytes. Guards the
    /// dry_run->simulated rename and the BTreeMap canonicalisation together.
    #[test]
    fn canonical_payload_is_sorted_compact_and_uses_simulated() {
        let mut entry = build_entry(
            "tén".into(),
            "HostIsolation".into(),
            "host-é".into(),
            "alice".into(),
            true,
        );
        entry.timestamp = 1_700_000_000;
        entry.previous_hash = GENESIS_HASH.to_string();

        let bytes = canonical_payload_bytes(&entry);
        let text = String::from_utf8(bytes.clone()).expect("utf-8");

        // Compact (no spaces after separators) and key-sorted: action_type,
        // approved_by, host, previous_hash, simulated, tenant_id, timestamp.
        assert!(
            text.starts_with("{\"action_type\":"),
            "first key sorted: {text}"
        );
        assert!(
            text.contains("\"simulated\":true"),
            "uses simulated, not dry_run"
        );
        assert!(!text.contains("dry_run"), "old field name must be gone");
        assert!(!text.contains(": "), "compact separators, no spaces");
        // Raw UTF-8, not escaped: the é in host-é stays two bytes, not é.
        assert!(text.contains("host-é"), "non-ASCII must not be escaped");
        assert!(!text.contains("\\u00e9"), "non-ASCII must not be escaped");
    }

    #[tokio::test]
    async fn streaming_export_filters_by_tenant_and_skips_other_tenants() {
        // PRX-04: the streaming reader must return only the requested tenant's
        // entries (tenant isolation enforced in the read, not after) and must
        // not choke on a malformed line. Also covers the missing-file path.
        let tmp = NamedTempFile::new().expect("tmp");
        let path = tmp.path().to_str().unwrap().to_string();
        let state = ChainState::genesis();

        append_audit(
            &path,
            &state,
            build_entry(
                "t1".into(),
                "HostIsolation".into(),
                "h-1".into(),
                "a".into(),
                false,
            ),
        )
        .await
        .expect("t1 entry");
        append_audit(
            &path,
            &state,
            build_entry(
                "t2".into(),
                "HostIsolation".into(),
                "h-2".into(),
                "b".into(),
                true,
            ),
        )
        .await
        .expect("t2 entry");
        // A malformed line in the middle must be skipped, not abort the read.
        {
            use tokio::io::AsyncWriteExt as _;
            let mut f = OpenOptions::new().append(true).open(&path).await.unwrap();
            f.write_all(b"{ not valid json\n").await.unwrap();
            f.flush().await.unwrap();
        }
        append_audit(
            &path,
            &state,
            build_entry(
                "t1".into(),
                "HostIsolation".into(),
                "h-3".into(),
                "c".into(),
                false,
            ),
        )
        .await
        .expect("second t1 entry");

        let t1 = read_tenant_entries_streaming(&path, "t1")
            .await
            .expect("t1 read");
        assert_eq!(t1.len(), 2, "only t1 entries, malformed line skipped");
        assert!(t1.iter().all(|e| e.tenant_id == "t1"));

        let t2 = read_tenant_entries_streaming(&path, "t2")
            .await
            .expect("t2 read");
        assert_eq!(t2.len(), 1);
        assert!(
            t2[0].simulated,
            "t2 entry carried simulated=true through the read"
        );

        // No history for an unknown tenant, and a missing file is empty, not an
        // error.
        let none = read_tenant_entries_streaming(&path, "nope")
            .await
            .expect("empty");
        assert!(none.is_empty());
        let missing = read_tenant_entries_streaming("/nonexistent/audit.jsonl", "t1")
            .await
            .expect("missing file is empty, not an error");
        assert!(missing.is_empty());
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
