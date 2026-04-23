use chrono::Utc;
use serde::Serialize;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub action_type: String,
    pub host: String,
    pub approved_by: String,
    pub dry_run: bool,
}

pub async fn append_audit(path: &str, entry: AuditEntry) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().create(true).append(true).open(path).await?;
    let line = serde_json::to_string(&entry).expect("audit entry serialization should not fail");
    file.write_all(line.as_bytes()).await?;
    file.write_all(b"\n").await?;
    file.flush().await?;
    Ok(())
}

pub fn build_entry(action_type: String, host: String, approved_by: String, dry_run: bool) -> AuditEntry {
    AuditEntry {
        timestamp: Utc::now().timestamp(),
        action_type,
        host,
        approved_by,
        dry_run,
    }
}
