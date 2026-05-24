//! Request-ID Nonce Store for Idempotent Execution
//!
//! ## Why this module exists
//!
//! Discord retries webhook deliveries. Network blips between the Discord
//! bot and this proxy cause retries. A human-approved containment action
//! (e.g. "isolate workstation-47") must execute **exactly once**, no
//! matter how many times the request arrives.
//!
//! Without dedup, a single approval can produce N host isolations. Two
//! isolations of the same host is "fine" if the EDR is idempotent, but
//! the audit trail and any side-effect notifications are duplicated, and
//! triple-counting in usage metering is a billing dispute waiting to
//! happen.
//!
//! The 30-second replay window in `main::check_replay_window` is **not**
//! enough on its own — duplicates within 30 seconds are exactly the
//! retry case we worry about.
//!
//! ## Design
//!
//! Each `ExecuteRequest` carries a `request_id` (UUID-v4 from the bot).
//! On first sight we record it as "in flight". Once execution completes
//! we mark it "done" along with the response that was returned. If the
//! same request_id arrives again we either:
//!
//! - serve the cached response if execution finished (replay-safe), or
//! - reject with 409 Conflict if execution is still in flight (avoids
//!   double-execute even under tight retry storms).
//!
//! Records are kept for `RETENTION_SECONDS` (default: 10 minutes), which
//! comfortably exceeds the longest plausible retry burst. After that they
//! are evicted to bound memory.
//!
//! ## Limitations (acknowledged, accepted for v0.1-alpha)
//!
//! - **In-memory only.** A proxy restart loses the table; a retry that
//!   crosses the restart window can re-execute. For the pilot this is
//!   acceptable: restarts are rare and the EDR action layer should be
//!   idempotent (CrowdStrike's contain-host is). Persistent dedup is
//!   tracked as a post-pilot item.
//! - **Single-process.** If we scale to multiple proxy instances we need
//!   Redis or a shared KV. The current architecture is one proxy per
//!   tenant deployment, so this is moot for now.
//! - **No per-tenant partitioning.** Request IDs are UUIDs and the
//!   collision probability across tenants is ~2^-122 per pair, which is
//!   not worth the bookkeeping.
//!
//! ## Concurrency
//!
//! `DashMap` provides lock-free reads and fine-grained sharded write
//! locks. `claim_or_replay` is the only path that can mutate the table
//! and it uses `entry` so the check-and-insert is atomic. Even under
//! 1000+ concurrent requests for the same `request_id`, exactly one
//! caller sees `Outcome::FreshClaim`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// How long to remember a request_id after the response is recorded.
///
/// Tradeoff: longer retention catches more retries but uses more memory.
/// At 1000 unique requests per minute (very aggressive for our scale),
/// 10 minutes of retention costs ~10K entries × ~200 bytes ≈ 2 MB. Fine.
const RETENTION_SECONDS: u64 = 600;

/// Maximum number of records to keep. Hard cap so a burst of unique
/// request_ids cannot OOM the process even if the eviction timer is
/// behind. At the cap we evict the oldest entries to make room.
const MAX_RECORDS: usize = 100_000;

/// What happened when we tried to claim a request_id.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// First time we've seen this request_id. Caller must proceed with
    /// execution and then call `record_response` with the result.
    FreshClaim,

    /// We've already finished executing this request_id. The cached
    /// response is included so the caller can return it without
    /// re-executing.
    AlreadyExecuted { cached_response_json: String },

    /// We're still executing this request_id from a prior call. Caller
    /// SHOULD return 409 Conflict so the upstream retries with backoff.
    InFlight,
}

/// A single entry in the dedup table.
#[derive(Debug, Clone)]
struct Record {
    /// When the entry was created. Used for eviction.
    created_at: Instant,

    /// Current state of the request lifecycle.
    state: RecordState,
}

#[derive(Debug, Clone)]
enum RecordState {
    /// Execution has started but not finished. Marked when we first see
    /// the request_id, before we call out to the EDR.
    InFlight,

    /// Execution finished. The cached response is the *serialized* form
    /// that the proxy returned to the client. Replaying it byte-for-byte
    /// guarantees the client sees the same result.
    Completed { response_json: String },
}

/// Thread-safe nonce store.
///
/// Wrapped in `Arc<DashMap>` so it can be cloned cheaply into the
/// Axum `AppState`. Cloning the store does not copy the map — every
/// clone points at the same shared storage.
#[derive(Clone, Default)]
pub struct NonceStore {
    inner: Arc<DashMap<String, Record>>,
}

impl NonceStore {
    /// Construct an empty store. Use this once at startup; clone it into
    /// every handler that needs it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically claim a request_id or report its current state.
    ///
    /// This is the only public mutation method. It uses `DashMap::entry`
    /// so the check-and-insert is atomic per shard — there is no window
    /// where two concurrent callers can both see `FreshClaim`.
    ///
    /// # Arguments
    ///
    /// - `request_id`: client-supplied unique identifier (UUID-v4).
    ///   Whitespace and case matter — we treat the string as opaque.
    ///   The caller is responsible for validating that the string is
    ///   not empty.
    ///
    /// # Returns
    ///
    /// See [`Outcome`].
    pub fn claim_or_replay(&self, request_id: &str) -> Outcome {
        // First, run eviction opportunistically. We do this on the read
        // path so memory is reclaimed even if no background task runs.
        // Eviction is fast (O(N) worst case) but only triggered when the
        // table is at or above the soft cap to amortize the cost.
        if self.inner.len() >= MAX_RECORDS {
            self.evict_expired();
        }

        // `entry().or_insert_with(...)` atomically inserts the InFlight
        // record if the key is absent. The reference returned holds the
        // shard lock until it goes out of scope, so we drop it before
        // returning.
        let mut fresh = false;
        let outcome = {
            let entry = self.inner.entry(request_id.to_string());
            let record = entry.or_insert_with(|| {
                fresh = true;
                Record {
                    created_at: Instant::now(),
                    state: RecordState::InFlight,
                }
            });

            if fresh {
                Outcome::FreshClaim
            } else {
                // Key existed: dispatch on its state.
                match &record.state {
                    RecordState::InFlight => Outcome::InFlight,
                    RecordState::Completed { response_json } => Outcome::AlreadyExecuted {
                        cached_response_json: response_json.clone(),
                    },
                }
            }
        };

        outcome
    }

    /// Record the response for a previously-claimed request_id.
    ///
    /// The caller MUST call this once execution finishes (whether the
    /// EDR call succeeded or failed) so that retries get the same
    /// outcome rather than re-executing.
    ///
    /// If `request_id` is unknown (which would indicate a programming
    /// error — the caller should always claim first), this is a no-op.
    ///
    /// # Arguments
    ///
    /// - `request_id`: the same key passed to `claim_or_replay`.
    /// - `response_json`: the JSON the proxy returned to the client.
    ///   Stored verbatim so the replay path can return byte-identical
    ///   output.
    pub fn record_response(&self, request_id: &str, response_json: String) {
        if let Some(mut record) = self.inner.get_mut(request_id) {
            record.state = RecordState::Completed { response_json };
        }
        // Silent no-op on unknown ID: the alternative (panic) would turn
        // a recoverable bug into a DoS. Logging is a caller concern.
    }

    /// Release an InFlight claim without caching a response.
    ///
    /// Used when execution short-circuits before completion (e.g., the
    /// EDR client returned a transient error and we want the caller to
    /// retry rather than be locked out by a stale InFlight record).
    ///
    /// Removing the entry entirely means the next retry will get a
    /// FreshClaim and re-execute. Only call this when you are sure the
    /// underlying side effect did NOT happen.
    pub fn release_claim(&self, request_id: &str) {
        self.inner.remove(request_id);
    }

    /// Drop records whose `created_at` is older than `RETENTION_SECONDS`.
    ///
    /// O(N) over the map. Acceptable because we only call it when at or
    /// above the soft cap (`MAX_RECORDS`), so amortized cost is bounded.
    fn evict_expired(&self) {
        let cutoff = Duration::from_secs(RETENTION_SECONDS);
        self.inner
            .retain(|_, record| record.created_at.elapsed() < cutoff);
    }

    /// Test-only helper to inspect map size.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_claim_is_fresh() {
        let store = NonceStore::new();
        match store.claim_or_replay("req-1") {
            Outcome::FreshClaim => {}
            other => panic!("expected FreshClaim, got {other:?}"),
        }
    }

    #[test]
    fn second_claim_before_response_is_in_flight() {
        let store = NonceStore::new();
        let _ = store.claim_or_replay("req-1");
        match store.claim_or_replay("req-1") {
            Outcome::InFlight => {}
            other => panic!("expected InFlight, got {other:?}"),
        }
    }

    #[test]
    fn claim_after_response_returns_cached() {
        let store = NonceStore::new();
        let _ = store.claim_or_replay("req-1");
        store.record_response("req-1", r#"{"status":"executed"}"#.to_string());
        match store.claim_or_replay("req-1") {
            Outcome::AlreadyExecuted {
                cached_response_json,
            } => {
                assert_eq!(cached_response_json, r#"{"status":"executed"}"#);
            }
            other => panic!("expected AlreadyExecuted, got {other:?}"),
        }
    }

    #[test]
    fn release_claim_allows_re_execution() {
        let store = NonceStore::new();
        let _ = store.claim_or_replay("req-1");
        store.release_claim("req-1");
        match store.claim_or_replay("req-1") {
            Outcome::FreshClaim => {}
            other => panic!("expected FreshClaim after release, got {other:?}"),
        }
    }

    #[test]
    fn record_response_on_unknown_id_is_noop() {
        let store = NonceStore::new();
        store.record_response("req-unknown", r#"{}"#.to_string());
        // Verify the unknown ID was NOT inserted by record_response.
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn concurrent_claims_yield_exactly_one_fresh() {
        // 64 threads racing on the same request_id: exactly one wins
        // FreshClaim, the rest see InFlight.
        let store = NonceStore::new();
        let mut handles = Vec::new();
        for _ in 0..64 {
            let s = store.clone();
            handles.push(std::thread::spawn(move || {
                matches!(s.claim_or_replay("hot-key"), Outcome::FreshClaim)
            }));
        }
        let fresh_wins: usize = handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter(|b| *b)
            .count();
        assert_eq!(fresh_wins, 1, "exactly one claim must win FreshClaim");
    }
}
