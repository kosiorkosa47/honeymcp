//! Postgres backend for the event store (feature-gated: `--features postgres`).
//!
//! Scaffolding only. The concrete `PostgresLogger` that mirrors the SqliteLogger
//! API lands in a follow-up commit; this module exists so the feature flag
//! compiles cleanly, CI stays green, and the migrations SQL has a home that
//! does not bit-rot independently of the Rust side.
//!
//! Expected future shape:
//!
//! ```ignore
//! pub struct PostgresLogger {
//!     pool: sqlx::PgPool,
//! }
//!
//! impl PostgresLogger {
//!     pub async fn connect(database_url: &str) -> Result<Self> { ... }
//!     pub async fn record(&self, entry: &LogEntry) -> Result<i64> { ... }
//!     pub async fn record_detections(&self, event_id: i64, dets: &[Detection]) -> Result<()> { ... }
//!     // plus the query methods Logger exposes today (count_events, top_tools, ...)
//! }
//! ```
//!
//! CLI routing: `main.rs` decides between `Logger::open(path)` (SQLite) and
//! `PostgresLogger::connect(url)` based on whether `--db` starts with
//! `postgres://` or is a filesystem path.

use anyhow::Result;

/// Placeholder connector. Returns Err until the real backend lands so nothing
/// silently accepts a `postgres://` URL and writes into /dev/null.
pub async fn connect(_database_url: &str) -> Result<()> {
    anyhow::bail!(
        "postgres backend is not implemented yet; \
         build with default features (SQLite) or wait for the follow-up commit"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_returns_not_implemented_until_backend_lands() {
        let err = connect("postgres://example/db").await.unwrap_err();
        assert!(
            err.to_string().contains("not implemented"),
            "expected explicit not-implemented marker, got: {err}"
        );
    }
}
