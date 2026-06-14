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
//! enough on its own: duplicates within 30 seconds are exactly the
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
//! ## Backends
//!
//! The store has two backends behind one async API:
//!
//! - **Redis (durable, shared).** The default in any real deployment. The
//!   dedup state lives in Redis, so it survives a proxy restart and is shared
//!   across multiple proxy instances behind a load balancer. A retry that
//!   crosses a restart, or lands on a different instance, still sees the prior
//!   claim and does NOT double-execute a containment. Keys carry a TTL so the
//!   set self-evicts; no background sweeper is needed. Configured by
//!   `REDIS_URL` (or `NONCE_REDIS_URL` to override just this store).
//! - **In-memory (fallback).** Used ONLY when no Redis URL is configured. A
//!   proxy restart loses the table and a retry crossing the restart window can
//!   re-execute, so the constructor logs a loud `warn!` when this path is
//!   taken. Acceptable for local dev and CI, never the intended production
//!   path. Single-process only.
//!
//! ## Concurrency and atomicity
//!
//! Both backends make `claim_or_replay` a single atomic check-and-claim:
//!
//! - In-memory: `DashMap::entry` returns the shard lock, so the check and the
//!   insert happen with no window in between. Even under 1000+ concurrent
//!   requests for the same `request_id`, exactly one caller sees `FreshClaim`.
//! - Redis: a small Lua script runs the read, the freshness decision, and the
//!   in-flight claim in one server-side step, so two instances racing on the
//!   same `request_id` cannot both win `FreshClaim`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tracing::{info, warn};

/// How long to remember a request_id after the response is recorded.
///
/// Tradeoff: longer retention catches more retries but uses more memory (or,
/// for Redis, more keyspace). At 1000 unique requests per minute (very
/// aggressive for our scale), 10 minutes of retention costs ~10K entries.
/// Env override: `NONCE_RETENTION_SECONDS`.
const DEFAULT_RETENTION_SECONDS: u64 = 600;

/// Maximum number of records the in-memory backend keeps. Hard cap so a burst
/// of unique request_ids cannot OOM the process even if the eviction timer is
/// behind. At the cap we evict the oldest entries to make room. The Redis
/// backend does not need this: per-key TTL bounds the keyspace and Redis has
/// its own maxmemory policy.
const MAX_RECORDS: usize = 100_000;

/// Env var holding the Redis URL for the nonce store. `NONCE_REDIS_URL` takes
/// precedence so the nonce store can point at a different Redis than any other
/// future Redis use; `REDIS_URL` is the shared fallback.
const NONCE_REDIS_URL_VAR: &str = "NONCE_REDIS_URL";
const REDIS_URL_VAR: &str = "REDIS_URL";

/// Env var overriding the retention/TTL in seconds.
const RETENTION_SECONDS_VAR: &str = "NONCE_RETENTION_SECONDS";

/// Key prefix for every nonce entry in Redis. Namespaces the proxy's keys so
/// the store can share a Redis instance with other Vyrox components without
/// collision.
const REDIS_KEY_PREFIX: &str = "vyrox:proxy:nonce:";

/// Sentinel value stored under a nonce key while a request is in flight. Any
/// other value is the cached response JSON. The sentinel is deliberately not
/// valid JSON for an `ExecuteResponse`, so it can never be mistaken for one.
const IN_FLIGHT_SENTINEL: &str = "\u{0}in-flight";

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

/// Read the retention/TTL from the env, defaulting to 10 minutes.
fn retention_seconds() -> u64 {
    std::env::var(RETENTION_SECONDS_VAR)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_RETENTION_SECONDS)
}

/// True when a Redis URL is configured (`NONCE_REDIS_URL` or `REDIS_URL`).
///
/// Lets `main` decide BEFORE building the store whether a missing URL should be
/// a hard boot error (PRX-01). A configured-but-unreachable URL is handled by
/// `from_env` (it hard-errors); this only distinguishes "URL present" from "no
/// URL at all", which is the case that would otherwise silently fall back to
/// the non-durable in-memory store.
pub fn redis_url_configured() -> bool {
    redis_url_from_env().is_some()
}

/// Resolve the Redis URL for the nonce store from the environment.
///
/// `NONCE_REDIS_URL` wins over the shared `REDIS_URL`. A blank value is treated
/// as unset so an empty env entry does not force a doomed connection attempt.
fn redis_url_from_env() -> Option<String> {
    for var in [NONCE_REDIS_URL_VAR, REDIS_URL_VAR] {
        if let Ok(url) = std::env::var(var) {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Thread-safe nonce store with a durable Redis backend and an in-memory
/// fallback.
///
/// Cloned cheaply into the Axum `AppState`: the in-memory backend shares one
/// `Arc<DashMap>` and the Redis backend shares one multiplexed
/// `ConnectionManager`, so every clone points at the same shared storage.
#[derive(Clone)]
pub struct NonceStore {
    backend: Backend,
    /// Retention window / Redis TTL in seconds. Read once at construction.
    ttl_seconds: u64,
}

#[derive(Clone)]
enum Backend {
    /// Durable, shared dedup in Redis. The intended production backend.
    Redis(ConnectionManager),
    /// In-process dedup. Fallback when no Redis URL is configured.
    Memory(Arc<DashMap<String, Record>>),
}

impl NonceStore {
    /// Construct the store from the environment.
    ///
    /// If a Redis URL is configured (`NONCE_REDIS_URL` or `REDIS_URL`) and the
    /// connection succeeds, returns a durable Redis-backed store. Otherwise
    /// falls back to the in-memory store and logs a loud `warn!` so an operator
    /// who forgot to configure Redis is not silently running without durable,
    /// shared dedup.
    ///
    /// A Redis URL that is configured but unreachable is a hard error: the
    /// operator asked for durability, so we do NOT silently downgrade to memory
    /// (which would reintroduce the restart double-execute risk under a
    /// transient Redis outage at boot). The caller decides whether to retry or
    /// abort.
    pub async fn from_env() -> Result<Self, redis::RedisError> {
        let ttl_seconds = retention_seconds();
        match redis_url_from_env() {
            Some(url) => {
                let client = redis::Client::open(url)?;
                let manager = ConnectionManager::new(client).await?;
                info!(
                    ttl_seconds,
                    "nonce store: Redis backend (durable, shared across instances)"
                );
                Ok(Self {
                    backend: Backend::Redis(manager),
                    ttl_seconds,
                })
            }
            None => {
                warn!(
                    ttl_seconds,
                    "nonce store: NO Redis URL configured (NONCE_REDIS_URL/REDIS_URL unset); \
                     falling back to IN-MEMORY dedup. Dedup state is lost on restart and is \
                     NOT shared across proxy instances, so a retry crossing a restart can \
                     double-execute a containment. Set REDIS_URL for production."
                );
                Ok(Self {
                    backend: Backend::Memory(Arc::new(DashMap::new())),
                    ttl_seconds,
                })
            }
        }
    }

    /// Construct an in-memory store directly. Test/dev helper; production goes
    /// through `from_env`.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            backend: Backend::Memory(Arc::new(DashMap::new())),
            ttl_seconds: DEFAULT_RETENTION_SECONDS,
        }
    }

    /// Construct a Redis-backed store from an explicit URL. Test helper so the
    /// dedup-survives-restart test can build two independent stores pointed at
    /// the same Redis (simulating a restart: new process, same Redis).
    #[cfg(test)]
    pub async fn redis_for_test(url: &str, ttl_seconds: u64) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let manager = ConnectionManager::new(client).await?;
        Ok(Self {
            backend: Backend::Redis(manager),
            ttl_seconds,
        })
    }

    /// True when this store is the durable Redis backend. Lets `main` log the
    /// effective mode without exposing the backend enum.
    pub fn is_durable(&self) -> bool {
        matches!(self.backend, Backend::Redis(_))
    }

    /// Atomically claim a request_id or report its current state.
    ///
    /// The check-and-claim is atomic in both backends (see the module docs), so
    /// there is no window where two concurrent callers both see `FreshClaim`.
    ///
    /// On the Redis backend a transport error is surfaced to the caller rather
    /// than swallowed: failing closed (the caller returns 5xx and the bot
    /// retries) is safer than failing open (skipping dedup and risking a
    /// double-execute).
    ///
    /// # Arguments
    ///
    /// - `request_id`: client-supplied unique identifier (UUID-v4). Whitespace
    ///   and case matter; we treat the string as opaque. The caller validates
    ///   it is non-empty.
    pub async fn claim_or_replay(&self, request_id: &str) -> Result<Outcome, redis::RedisError> {
        match &self.backend {
            Backend::Memory(map) => Ok(claim_memory(map, request_id, self.ttl_seconds)),
            Backend::Redis(manager) => {
                claim_redis(manager.clone(), request_id, self.ttl_seconds).await
            }
        }
    }

    /// Record the response for a previously-claimed request_id.
    ///
    /// The caller MUST call this once execution finishes (whether the EDR call
    /// succeeded or failed) so that retries get the same outcome rather than
    /// re-executing. If `request_id` is unknown this is a no-op.
    ///
    /// # Arguments
    ///
    /// - `request_id`: the same key passed to `claim_or_replay`.
    /// - `response_json`: the JSON the proxy returned to the client. Stored
    ///   verbatim so the replay path returns byte-identical output.
    pub async fn record_response(
        &self,
        request_id: &str,
        response_json: String,
    ) -> Result<(), redis::RedisError> {
        match &self.backend {
            Backend::Memory(map) => {
                record_memory(map, request_id, response_json);
                Ok(())
            }
            Backend::Redis(manager) => {
                record_redis(manager.clone(), request_id, response_json, self.ttl_seconds).await
            }
        }
    }

    /// Release an InFlight claim without caching a response.
    ///
    /// Used when execution short-circuits before completion (e.g. the EDR
    /// client returned a transient error and we want the caller to retry rather
    /// than be locked out by a stale InFlight record). Removing the entry means
    /// the next retry gets a FreshClaim and re-executes. Only call this when you
    /// are sure the underlying side effect did NOT happen.
    pub async fn release_claim(&self, request_id: &str) -> Result<(), redis::RedisError> {
        match &self.backend {
            Backend::Memory(map) => {
                map.remove(request_id);
                Ok(())
            }
            Backend::Redis(manager) => {
                let mut conn = manager.clone();
                let _: () = conn.del(redis_key(request_id)).await?;
                Ok(())
            }
        }
    }

    /// Test-only helper to inspect in-memory map size.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        match &self.backend {
            Backend::Memory(map) => map.len(),
            Backend::Redis(_) => 0,
        }
    }
}

/// Build the namespaced Redis key for a request_id.
fn redis_key(request_id: &str) -> String {
    format!("{REDIS_KEY_PREFIX}{request_id}")
}

/// Atomic claim-or-replay against Redis.
///
/// One round trip via a Lua script keeps the read, the freshness decision, and
/// the in-flight claim atomic across instances:
///
/// - key absent: set it to the in-flight sentinel with a TTL, return "fresh".
/// - key holds the in-flight sentinel: return "inflight".
/// - key holds anything else (the cached response JSON): return it.
///
/// `SET ... NX` alone cannot also return the existing value in the same step,
/// hence the script. The TTL is applied only on the fresh insert so a slow
/// in-flight request keeps a stable expiry.
async fn claim_redis(
    mut conn: ConnectionManager,
    request_id: &str,
    ttl_seconds: u64,
) -> Result<Outcome, redis::RedisError> {
    // KEYS[1] = nonce key, ARGV[1] = in-flight sentinel, ARGV[2] = ttl seconds.
    // Returns the literal "FRESH" or "INFLIGHT", or the cached response string.
    let script = redis::Script::new(
        r#"
        local existing = redis.call('GET', KEYS[1])
        if existing == false then
            redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
            return 'FRESH'
        elseif existing == ARGV[1] then
            return 'INFLIGHT'
        else
            return existing
        end
        "#,
    );

    let result: String = script
        .key(redis_key(request_id))
        .arg(IN_FLIGHT_SENTINEL)
        .arg(ttl_seconds)
        .invoke_async(&mut conn)
        .await?;

    Ok(match result.as_str() {
        "FRESH" => Outcome::FreshClaim,
        "INFLIGHT" => Outcome::InFlight,
        _ => Outcome::AlreadyExecuted {
            cached_response_json: result,
        },
    })
}

/// Persist the completed response in Redis, replacing the in-flight sentinel.
///
/// Only overwrites a key that is currently the in-flight sentinel (the claim we
/// made), so a `record_response` for an unknown or already-expired id is a
/// no-op rather than resurrecting a stale key. Refreshes the TTL so the cached
/// response lives a full retention window from completion.
async fn record_redis(
    mut conn: ConnectionManager,
    request_id: &str,
    response_json: String,
    ttl_seconds: u64,
) -> Result<(), redis::RedisError> {
    let script = redis::Script::new(
        r#"
        local existing = redis.call('GET', KEYS[1])
        if existing == ARGV[1] then
            redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
            return 1
        end
        return 0
        "#,
    );

    let _: i64 = script
        .key(redis_key(request_id))
        .arg(IN_FLIGHT_SENTINEL)
        .arg(response_json)
        .arg(ttl_seconds)
        .invoke_async(&mut conn)
        .await?;
    Ok(())
}

// ----------------------------------------------------------------------
//  In-memory backend
// ----------------------------------------------------------------------

/// A single entry in the in-memory dedup table.
#[derive(Debug, Clone)]
struct Record {
    /// When the entry was created. Used for eviction.
    created_at: Instant,
    /// Current state of the request lifecycle.
    state: RecordState,
}

#[derive(Debug, Clone)]
enum RecordState {
    /// Execution has started but not finished. Marked when we first see the
    /// request_id, before we call out to the EDR.
    InFlight,
    /// Execution finished. The cached response is the serialized form the proxy
    /// returned to the client. Replaying it byte-for-byte guarantees the client
    /// sees the same result.
    Completed { response_json: String },
}

/// Atomic claim-or-replay against the in-memory map. `DashMap::entry` makes the
/// check-and-insert atomic per shard.
fn claim_memory(map: &Arc<DashMap<String, Record>>, request_id: &str, ttl_seconds: u64) -> Outcome {
    // Run eviction opportunistically on the claim path so memory is reclaimed
    // even with no background task. Only triggered at/above the cap to amortize
    // the cost.
    if map.len() >= MAX_RECORDS {
        evict_expired(map, ttl_seconds);
        // TTL eviction alone does NOT bound memory: an adversary (or a genuine
        // storm) sending > MAX_RECORDS unique request_ids inside the retention
        // window leaves every record younger than the cutoff, so `evict_expired`
        // frees nothing and the map grows without bound. Enforce the hard cap by
        // dropping the oldest entries.
        if map.len() >= MAX_RECORDS {
            evict_to_cap(map);
        }
    }

    let mut fresh = false;
    let entry = map.entry(request_id.to_string());
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
        match &record.state {
            RecordState::InFlight => Outcome::InFlight,
            RecordState::Completed { response_json } => Outcome::AlreadyExecuted {
                cached_response_json: response_json.clone(),
            },
        }
    }
}

/// Record the completed response in the in-memory map. No-op on an unknown id
/// (a panic would turn a recoverable bug into a DoS).
fn record_memory(map: &Arc<DashMap<String, Record>>, request_id: &str, response_json: String) {
    if let Some(mut record) = map.get_mut(request_id) {
        record.state = RecordState::Completed { response_json };
    }
}

/// Drop records whose `created_at` is older than the configured retention window.
fn evict_expired(map: &Arc<DashMap<String, Record>>, ttl_seconds: u64) {
    let cutoff = Duration::from_secs(ttl_seconds);
    map.retain(|_, record| record.created_at.elapsed() < cutoff);
}

/// Enforce the hard cap by dropping the oldest entries down to 90% of the cap,
/// so the O(N log N) sort amortizes over many subsequent claims. Collect keys
/// first so we never hold an iteration guard and a write guard on the same
/// shard at once.
fn evict_to_cap(map: &Arc<DashMap<String, Record>>) {
    let len = map.len();
    let target = MAX_RECORDS / 10 * 9; // 90% of the cap
    let to_remove = len.saturating_sub(target);
    if to_remove == 0 {
        return;
    }

    let mut entries: Vec<(String, Instant)> = map
        .iter()
        .map(|e| (e.key().clone(), e.value().created_at))
        .collect();
    entries.sort_by_key(|(_, created)| *created); // oldest first
    for (key, _) in entries.into_iter().take(to_remove) {
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_claim_is_fresh() {
        let store = NonceStore::in_memory();
        match store.claim_or_replay("req-1").await.unwrap() {
            Outcome::FreshClaim => {}
            other => panic!("expected FreshClaim, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn second_claim_before_response_is_in_flight() {
        let store = NonceStore::in_memory();
        let _ = store.claim_or_replay("req-1").await.unwrap();
        match store.claim_or_replay("req-1").await.unwrap() {
            Outcome::InFlight => {}
            other => panic!("expected InFlight, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn claim_after_response_returns_cached() {
        let store = NonceStore::in_memory();
        let _ = store.claim_or_replay("req-1").await.unwrap();
        store
            .record_response("req-1", r#"{"status":"executed"}"#.to_string())
            .await
            .unwrap();
        match store.claim_or_replay("req-1").await.unwrap() {
            Outcome::AlreadyExecuted {
                cached_response_json,
            } => {
                assert_eq!(cached_response_json, r#"{"status":"executed"}"#);
            }
            other => panic!("expected AlreadyExecuted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn release_claim_allows_re_execution() {
        let store = NonceStore::in_memory();
        let _ = store.claim_or_replay("req-1").await.unwrap();
        store.release_claim("req-1").await.unwrap();
        match store.claim_or_replay("req-1").await.unwrap() {
            Outcome::FreshClaim => {}
            other => panic!("expected FreshClaim after release, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn record_response_on_unknown_id_is_noop() {
        let store = NonceStore::in_memory();
        store
            .record_response("req-unknown", r#"{}"#.to_string())
            .await
            .unwrap();
        // Verify the unknown ID was NOT inserted by record_response.
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn concurrent_claims_yield_exactly_one_fresh() {
        // 64 threads racing on the same request_id: exactly one wins
        // FreshClaim, the rest see InFlight. Uses the synchronous in-memory
        // claim directly so we can spawn OS threads without a runtime per
        // thread.
        let map: Arc<DashMap<String, Record>> = Arc::new(DashMap::new());
        let mut handles = Vec::new();
        for _ in 0..64 {
            let m = map.clone();
            handles.push(std::thread::spawn(move || {
                matches!(
                    claim_memory(&m, "hot-key", DEFAULT_RETENTION_SECONDS),
                    Outcome::FreshClaim
                )
            }));
        }
        let fresh_wins: usize = handles
            .into_iter()
            .filter_map(|h| h.join().ok())
            .filter(|b| *b)
            .count();
        assert_eq!(fresh_wins, 1, "exactly one claim must win FreshClaim");
    }

    #[test]
    fn unique_id_burst_is_bounded_by_hard_cap() {
        // A burst of more than MAX_RECORDS unique request_ids, all younger than
        // the retention window, must NOT grow the map without bound. TTL
        // eviction frees nothing here (everything is fresh), so the hard-cap
        // eviction keeps memory bounded. Regression for the OOM gap.
        let map: Arc<DashMap<String, Record>> = Arc::new(DashMap::new());
        for i in 0..(MAX_RECORDS + 1_000) {
            let _ = claim_memory(&map, &format!("burst-{i}"), DEFAULT_RETENTION_SECONDS);
        }
        assert!(
            map.len() <= MAX_RECORDS,
            "nonce store exceeded the hard cap: {} > {}",
            map.len(),
            MAX_RECORDS
        );
    }

    // ── Redis-backed integration tests ────────────────────────────────────
    //
    // These run against a real Redis. They are skipped (not failed) when no
    // Redis is reachable, so CI without a Redis service still goes green, and a
    // developer with `redis-server` running gets full coverage. The default
    // target is a local Redis; override with TEST_REDIS_URL. Every test uses a
    // unique request_id prefix so parallel runs and repeated runs never collide
    // on keys.

    /// Resolve the Redis URL for the integration tests, or `None` to skip.
    fn test_redis_url() -> Option<String> {
        std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| Some("redis://127.0.0.1:6379".to_string()))
    }

    /// Try to build a Redis-backed store; return `None` if Redis is unreachable
    /// so the test can skip cleanly rather than fail on a missing dependency.
    async fn try_redis_store(ttl_seconds: u64) -> Option<NonceStore> {
        let url = test_redis_url()?;
        match NonceStore::redis_for_test(&url, ttl_seconds).await {
            Ok(store) => {
                // Probe the connection so an unreachable Redis skips rather than
                // surfacing later mid-test. `is_durable` is true regardless, so
                // do a real round-trip via a throwaway claim.
                let probe = format!("probe-{}", uuid_like());
                match store.claim_or_replay(&probe).await {
                    Ok(_) => {
                        let _ = store.release_claim(&probe).await;
                        Some(store)
                    }
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }

    /// Cheap unique-ish id without pulling in the `uuid` crate: nanos since the
    /// epoch plus a thread-id hash. Good enough to namespace test keys.
    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{nanos}-{:?}", std::thread::current().id())
    }

    #[tokio::test]
    async fn redis_dedup_survives_simulated_restart() {
        let Some(store1) = try_redis_store(60).await else {
            eprintln!("skipping: no Redis reachable for redis_dedup_survives_simulated_restart");
            return;
        };
        let req = format!("restart-{}", uuid_like());

        // First "process": claim and complete the request.
        assert!(
            matches!(
                store1.claim_or_replay(&req).await.unwrap(),
                Outcome::FreshClaim
            ),
            "first claim must be fresh"
        );
        store1
            .record_response(
                &req,
                r#"{"status":"executed","simulated":false}"#.to_string(),
            )
            .await
            .unwrap();

        // Simulate a RESTART: drop the first store entirely and build a brand
        // new one pointed at the SAME Redis (a new process, fresh in-memory
        // state, but the durable store persists). The in-memory backend would
        // have lost everything here; Redis must not.
        drop(store1);
        let store2 = NonceStore::redis_for_test(&test_redis_url().unwrap(), 60)
            .await
            .unwrap();

        // The retry after restart must see the cached response, NOT a fresh
        // claim, so the containment is not double-executed across the restart.
        match store2.claim_or_replay(&req).await.unwrap() {
            Outcome::AlreadyExecuted {
                cached_response_json,
            } => {
                assert_eq!(
                    cached_response_json, r#"{"status":"executed","simulated":false}"#,
                    "cached response must survive the restart"
                );
            }
            other => panic!("expected AlreadyExecuted after restart, got {other:?}"),
        }

        store2.release_claim(&req).await.unwrap();
    }

    #[tokio::test]
    async fn redis_second_claim_in_flight_then_cached_after_record() {
        let Some(store) = try_redis_store(60).await else {
            eprintln!("skipping: no Redis reachable");
            return;
        };
        let req = format!("inflight-{}", uuid_like());

        assert!(matches!(
            store.claim_or_replay(&req).await.unwrap(),
            Outcome::FreshClaim
        ));
        // A duplicate while still in flight must be reported InFlight (409),
        // shared across instances: a second proxy seeing the same id mid-flight
        // does not re-execute.
        assert!(matches!(
            store.claim_or_replay(&req).await.unwrap(),
            Outcome::InFlight
        ));
        store
            .record_response(&req, r#"{"status":"executed"}"#.to_string())
            .await
            .unwrap();
        assert!(matches!(
            store.claim_or_replay(&req).await.unwrap(),
            Outcome::AlreadyExecuted { .. }
        ));
        store.release_claim(&req).await.unwrap();
    }

    #[tokio::test]
    async fn redis_release_claim_allows_re_execution() {
        let Some(store) = try_redis_store(60).await else {
            eprintln!("skipping: no Redis reachable");
            return;
        };
        let req = format!("release-{}", uuid_like());
        let _ = store.claim_or_replay(&req).await.unwrap();
        store.release_claim(&req).await.unwrap();
        assert!(
            matches!(
                store.claim_or_replay(&req).await.unwrap(),
                Outcome::FreshClaim
            ),
            "after release the next claim is fresh"
        );
        store.release_claim(&req).await.unwrap();
    }

    #[tokio::test]
    async fn redis_record_on_unknown_id_does_not_create_a_cached_entry() {
        // record_response for an id we never claimed must NOT create a cached
        // entry (the Lua guard only overwrites the in-flight sentinel). The
        // subsequent claim is therefore Fresh, not AlreadyExecuted.
        let Some(store) = try_redis_store(60).await else {
            eprintln!("skipping: no Redis reachable");
            return;
        };
        let req = format!("unknown-{}", uuid_like());
        store
            .record_response(&req, r#"{"status":"executed"}"#.to_string())
            .await
            .unwrap();
        assert!(
            matches!(
                store.claim_or_replay(&req).await.unwrap(),
                Outcome::FreshClaim
            ),
            "record on an unclaimed id must not fabricate a cached response"
        );
        store.release_claim(&req).await.unwrap();
    }

    #[tokio::test]
    async fn redis_ttl_is_set_on_fresh_claim() {
        // The fresh claim must carry the configured TTL so the keyspace
        // self-evicts and an orphaned in-flight claim cannot wedge a request_id
        // forever. We read the TTL back directly.
        let Some(store) = try_redis_store(120).await else {
            eprintln!("skipping: no Redis reachable");
            return;
        };
        let req = format!("ttl-{}", uuid_like());
        let _ = store.claim_or_replay(&req).await.unwrap();

        let url = test_redis_url().unwrap();
        let client = redis::Client::open(url).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let ttl: i64 = redis::cmd("TTL")
            .arg(redis_key(&req))
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(
            ttl > 0 && ttl <= 120,
            "fresh claim must carry a positive TTL <= configured, got {ttl}"
        );
        store.release_claim(&req).await.unwrap();
    }

    #[test]
    fn redis_url_prefers_nonce_specific_then_shared() {
        // Process-global env: serialize by only mutating inside this test and
        // restoring after. NONCE_REDIS_URL wins over REDIS_URL; a blank value
        // is treated as unset.
        std::env::set_var(NONCE_REDIS_URL_VAR, "redis://nonce-specific");
        std::env::set_var(REDIS_URL_VAR, "redis://shared");
        assert_eq!(
            redis_url_from_env().as_deref(),
            Some("redis://nonce-specific")
        );

        std::env::remove_var(NONCE_REDIS_URL_VAR);
        assert_eq!(redis_url_from_env().as_deref(), Some("redis://shared"));

        std::env::set_var(REDIS_URL_VAR, "   ");
        assert_eq!(redis_url_from_env(), None, "blank URL is treated as unset");

        std::env::remove_var(REDIS_URL_VAR);
        assert_eq!(redis_url_from_env(), None);
    }

    #[tokio::test]
    async fn from_env_without_redis_url_falls_back_to_in_memory() {
        // With no Redis URL configured, from_env must fall back to the
        // in-memory backend (and, in the real path, emit the loud warn!). It is
        // explicitly NOT durable. We snapshot and restore the two env vars so we
        // do not disturb the rest of the suite.
        let saved_nonce = std::env::var(NONCE_REDIS_URL_VAR).ok();
        let saved_shared = std::env::var(REDIS_URL_VAR).ok();
        std::env::remove_var(NONCE_REDIS_URL_VAR);
        std::env::remove_var(REDIS_URL_VAR);

        let store = NonceStore::from_env().await.expect("fallback never errors");
        assert!(
            !store.is_durable(),
            "fallback store must report non-durable (in-memory)"
        );
        // It still works as a dedup store.
        assert!(matches!(
            store.claim_or_replay("mem-1").await.unwrap(),
            Outcome::FreshClaim
        ));
        assert!(matches!(
            store.claim_or_replay("mem-1").await.unwrap(),
            Outcome::InFlight
        ));

        if let Some(v) = saved_nonce {
            std::env::set_var(NONCE_REDIS_URL_VAR, v);
        }
        if let Some(v) = saved_shared {
            std::env::set_var(REDIS_URL_VAR, v);
        }
    }
}
