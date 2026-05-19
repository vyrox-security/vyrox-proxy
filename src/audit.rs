//! Audit Logging for Vyrox Proxy
//!
//! This module provides append-only audit logging for all containment
//! actions executed by the proxy. Audit logs are critical for:
//!
//! - Compliance (SOC 2, HIPAA, GDPR)
//! - Incident investigation and forensics
//! - Detecting unauthorized or anomalous actions
//! - Tenant isolation verification
//!
//! ## Log Format
//!
//! Logs are stored in JSONL format (one JSON object per line):
//! ```json
//! {"timestamp":1699999999,"tenant_id":"abc123","action_type":"HOST_ISOLATION","host":"workstation-01","approved_by":"analyst@company.com","dry_run":false}
//! ```
//!
//! ## Security Properties
//!
//! - Append-only: Files are opened with append flag, never overwritten
//! - Tenant-scoped: Each entry includes tenant_id for isolation
//! - Timestamped: All entries include UTC timestamps
//! - Non-blocking: Async I/O prevents blocking request handling

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

/// Single audit log entry representing one action execution.
///
/// This struct is serialized to JSON for storage in the audit log.
/// Each field captures important context for investigation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    /// Unix timestamp (UTC) when the action was recorded.
    /// Use this for chronological ordering and time-based queries.
    pub timestamp: i64,

    /// Tenant identifier for multi-tenant isolation.
    /// This field enables per-tenant audit log filtering and export.
    pub tenant_id: String,

    /// Type of containment action (HOST_ISOLATION, KILL_PROCESS, etc).
    /// Corresponds to the actions::ActionType enum.
    pub action_type: String,

    /// Target hostname or IP address of the action.
    /// This is the endpoint where the action was applied.
    pub host: String,

    /// Discord username who approved this action.
    /// Used for accountability - who made the decision to contain.
    pub approved_by: String,

    /// Whether this was a dry-run (no actual execution).
    /// In development mode, actions are logged but not executed.
    pub dry_run: bool,
}

/// Append an audit entry to the log file.
///
/// This function opens the audit log in append mode and writes
/// a single JSON-formatted entry. It never modifies existing content,
/// ensuring the log is append-only.
///
/// ## Arguments
///
/// - `path`: File path to the audit log (JSONL format)
/// - `entry`: AuditEntry to append
///
/// ## Returns
///
/// - `Ok(())` on successful write
/// - `Err(std::io::Error)` if the file cannot be opened or written
///
/// ## Notes
///
/// - Creates the file if it doesn't exist
/// - Flushes after write to ensure durability
/// - Thread-safe for concurrent writes (OS handles locking)
pub async fn append_audit(path: &str, entry: AuditEntry) -> Result<(), std::io::Error> {
    // Open file in append mode - creates if not exists
    // The append flag ensures we never overwrite existing entries
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;

    // Serialize entry to JSON with no extra whitespace for efficiency
    let line = serde_json::to_string(&entry).expect("audit entry serialization should not fail");

    // Write the JSON line followed by newline
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;

    // Flush to ensure data is written to disk (not just buffered)
    file.flush().await?;

    Ok(())
}

/// Build a new audit entry with current timestamp.
///
/// This is a convenience constructor that captures the current time
/// and packages all action details into an AuditEntry.
///
/// ## Arguments
///
/// - `tenant_id`: Tenant identifier
/// - `action_type`: Type of action from actions::ActionType
/// - `host`: Target hostname
/// - `approved_by`: Username who approved
/// - `dry_run`: Whether this is a simulation (no actual execution)
///
/// ## Returns
///
/// A fully-populated AuditEntry with current timestamp
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
    }
}

/// Read and parse audit log entries from file.
///
/// This function reads the entire audit log file and parses each
/// line as an AuditEntry. It is used by the /audit/export endpoint
/// to retrieve filtered audit logs.
///
/// ## Arguments
///
/// - `path`: File path to the audit log
///
/// ## Returns
///
/// - `Ok(Vec<AuditEntry>)` containing all parsed entries
/// - `Err(std::io::Error)` if the file cannot be read
///
/// ## Notes
///
/// - Silently skips malformed lines (defensive parsing)
/// - Memory-intensive for large logs - consider pagination for production
pub async fn read_audit_logs(path: &str) -> Result<Vec<AuditEntry>, std::io::Error> {
    // Read entire file into memory
    let content = tokio::fs::read_to_string(path).await?;

    // Parse each line as a JSON audit entry
    // Using simple loop rather than iterator for clarity
    let mut entries = Vec::new();
    for line in content.lines() {
        // Skip empty lines
        if line.is_empty() {
            continue;
        }

        // Parse JSON, skip malformed entries
        // This defensive parsing ensures one bad entry doesn't fail the whole file
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}
