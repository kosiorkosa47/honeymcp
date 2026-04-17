//! Structured request/response logging.
//!
//! Writes each interaction to SQLite (primary) and optionally mirrors to JSONL (human-grep).
//! The goal is to make threat-intel analysis trivial: `sqlite3 hive.db 'select ...'` or `jq`
//! over the JSONL tail — no custom tooling required.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

/// A single request/response interaction that we persist for later analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp_ms: i64,
    pub method: String,
    pub params_hash: String,
    pub params: Option<Value>,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub session_id: String,
    pub response_summary: String,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub remote_addr: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub client_meta: Option<Value>,
}

pub fn hash_params(params: &Option<Value>) -> String {
    let mut hasher = Sha256::new();
    match params {
        Some(v) => {
            let canonical = serde_json::to_vec(v).unwrap_or_default();
            hasher.update(&canonical);
        }
        None => hasher.update(b""),
    }
    hex::encode(hasher.finalize())
}

/// Combined SQLite+JSONL logger. Clonable via Arc so multiple tasks can share it.
#[derive(Clone)]
pub struct Logger {
    inner: Arc<LoggerInner>,
}

struct LoggerInner {
    db: Mutex<Connection>,
    jsonl: Mutex<Option<tokio::fs::File>>,
    jsonl_path: Option<PathBuf>,
}

impl Logger {
    pub async fn open(db_path: &Path, jsonl_path: Option<&Path>) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.ok();
            }
        }
        let db = Connection::open(db_path)
            .with_context(|| format!("opening sqlite db at {}", db_path.display()))?;
        db.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS events (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_ms    INTEGER NOT NULL,
                session_id      TEXT    NOT NULL,
                method          TEXT    NOT NULL,
                params_hash     TEXT    NOT NULL,
                params          TEXT,
                client_name     TEXT,
                client_version  TEXT,
                response_summary TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_method    ON events(method);
            CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_ms);
            "#,
        )
        .context("initializing events schema")?;

        // Backward-compatible column additions. SQLite has no ALTER TABLE ... ADD COLUMN
        // IF NOT EXISTS, so we inspect pragma_table_info and add only what's missing.
        add_column_if_missing(&db, "events", "transport", "TEXT")?;
        add_column_if_missing(&db, "events", "remote_addr", "TEXT")?;
        add_column_if_missing(&db, "events", "user_agent", "TEXT")?;
        add_column_if_missing(&db, "events", "client_meta", "TEXT")?;

        let jsonl = match jsonl_path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() {
                        tokio::fs::create_dir_all(parent).await.ok();
                    }
                }
                let f = tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .await
                    .with_context(|| format!("opening jsonl at {}", p.display()))?;
                Some(f)
            }
            None => None,
        };

        Ok(Self {
            inner: Arc::new(LoggerInner {
                db: Mutex::new(db),
                jsonl: Mutex::new(jsonl),
                jsonl_path: jsonl_path.map(Path::to_path_buf),
            }),
        })
    }

    pub fn jsonl_path(&self) -> Option<&Path> {
        self.inner.jsonl_path.as_deref()
    }

    pub async fn record(&self, entry: &LogEntry) -> Result<()> {
        {
            let db = self.inner.db.lock().await;
            let params_str = entry
                .params
                .as_ref()
                .map(|v| serde_json::to_string(v).unwrap_or_default());
            let client_meta_str = entry
                .client_meta
                .as_ref()
                .map(|v| serde_json::to_string(v).unwrap_or_default());
            db.execute(
                "INSERT INTO events
                    (timestamp_ms, session_id, method, params_hash, params,
                     client_name, client_version, response_summary,
                     transport, remote_addr, user_agent, client_meta)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    entry.timestamp_ms,
                    entry.session_id,
                    entry.method,
                    entry.params_hash,
                    params_str,
                    entry.client_name,
                    entry.client_version,
                    entry.response_summary,
                    entry.transport,
                    entry.remote_addr,
                    entry.user_agent,
                    client_meta_str,
                ],
            )
            .context("inserting event row")?;
        }

        let mut jsonl = self.inner.jsonl.lock().await;
        if let Some(f) = jsonl.as_mut() {
            let mut line = serde_json::to_vec(entry).context("serializing jsonl entry")?;
            line.push(b'\n');
            f.write_all(&line).await.context("appending to jsonl")?;
            f.flush().await.ok();
        }
        Ok(())
    }

    pub async fn count_events(&self) -> Result<i64> {
        let db = self.inner.db.lock().await;
        let n: i64 = db.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(n)
    }
}

fn add_column_if_missing(db: &Connection, table: &str, column: &str, col_type: &str) -> Result<()> {
    let existing: Vec<String> = db
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |r| r.get::<_, String>(1))?
        .filter_map(|r| r.ok())
        .collect();
    if existing.iter().any(|c| c == column) {
        return Ok(());
    }
    db.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {col_type}"),
        [],
    )
    .with_context(|| format!("adding column {column} to {table}"))?;
    Ok(())
}

pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn records_events_to_sqlite_and_jsonl() {
        let dir = tempdir().unwrap();
        let db = dir.path().join("hive.db");
        let jsonl = dir.path().join("hive.jsonl");
        let logger = Logger::open(&db, Some(&jsonl)).await.unwrap();

        let entry = LogEntry {
            timestamp_ms: now_ms(),
            method: "tools/call".into(),
            params_hash: hash_params(&Some(serde_json::json!({"name": "query"}))),
            params: Some(serde_json::json!({"name": "query"})),
            client_name: Some("attacker".into()),
            client_version: Some("1.0".into()),
            session_id: "sess-1".into(),
            response_summary: "rows=0".into(),
            transport: Some("http".into()),
            remote_addr: Some("203.0.113.7:54321".into()),
            user_agent: Some("curl/8.0".into()),
            client_meta: Some(serde_json::json!({"x_forwarded_for": "198.51.100.9"})),
        };
        logger.record(&entry).await.unwrap();

        assert_eq!(logger.count_events().await.unwrap(), 1);
        let body = tokio::fs::read_to_string(&jsonl).await.unwrap();
        assert!(body.contains("\"method\":\"tools/call\""));
        assert!(body.contains("\"client_name\":\"attacker\""));
        assert!(body.contains("\"transport\":\"http\""));
        assert!(body.contains("\"remote_addr\":\"203.0.113.7:54321\""));
    }

    #[tokio::test]
    async fn migrates_existing_db_in_place() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("legacy.db");

        // Simulate an existing Day-1 schema that lacks the new columns.
        {
            let c = Connection::open(&db_path).unwrap();
            c.execute_batch(
                r#"
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_ms INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    params_hash TEXT NOT NULL,
                    params TEXT,
                    client_name TEXT,
                    client_version TEXT,
                    response_summary TEXT NOT NULL
                );
                INSERT INTO events
                    (timestamp_ms, session_id, method, params_hash, response_summary)
                VALUES (1, 'old', 'initialize', 'h', 'ok');
                "#,
            )
            .unwrap();
        }

        // Opening via Logger must add the new columns without losing the old row.
        let logger = Logger::open(&db_path, None).await.unwrap();
        assert_eq!(logger.count_events().await.unwrap(), 1);

        let entry = LogEntry {
            timestamp_ms: 2,
            method: "tools/list".into(),
            params_hash: "h2".into(),
            params: None,
            client_name: None,
            client_version: None,
            session_id: "new".into(),
            response_summary: "ok".into(),
            transport: Some("http".into()),
            remote_addr: Some("127.0.0.1:1".into()),
            user_agent: None,
            client_meta: None,
        };
        logger.record(&entry).await.unwrap();
        assert_eq!(logger.count_events().await.unwrap(), 2);
    }

    #[test]
    fn hash_is_stable_for_identical_params() {
        let a = Some(serde_json::json!({"k": 1}));
        assert_eq!(hash_params(&a), hash_params(&a));
        assert_ne!(hash_params(&a), hash_params(&None));
    }
}
