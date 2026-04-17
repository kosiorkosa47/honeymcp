//! Aggregate statistics served over `GET /stats`.
//!
//! A thin read-only projection over the logger — the transport layer calls
//! [`StatsProvider::stats`] to build a JSON snapshot without needing to know the
//! SQLite schema. Kept as its own module so adding new dimensions doesn't thread
//! through Dispatcher.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use std::time::Instant;

use crate::logger::Logger;

#[derive(Debug, Serialize)]
pub struct ServerIdentity {
    pub name: String,
    pub version: String,
    pub protocol_version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct StatsSnapshot {
    pub uptime_seconds: u64,
    pub server: ServerIdentity,
    pub total_events: i64,
    pub total_detections: i64,
    pub events_by_method: Vec<(String, i64)>,
    pub detections_by_category: Vec<(String, i64)>,
    pub unique_remote_addrs_24h: i64,
    pub top_tools: Vec<(String, i64)>,
}

#[async_trait]
pub trait StatsProvider: Send + Sync {
    async fn stats(&self) -> Result<StatsSnapshot>;
}

pub struct LoggerStatsProvider {
    logger: Logger,
    server: ServerIdentity,
    started: Instant,
}

impl LoggerStatsProvider {
    pub fn new(logger: Logger, persona_name: String, persona_version: String) -> Self {
        Self {
            logger,
            server: ServerIdentity {
                name: persona_name,
                version: persona_version,
                protocol_version: crate::protocol::PROTOCOL_VERSION,
            },
            started: Instant::now(),
        }
    }

    pub fn into_arc(self) -> Arc<dyn StatsProvider> {
        Arc::new(self)
    }
}

#[async_trait]
impl StatsProvider for LoggerStatsProvider {
    async fn stats(&self) -> Result<StatsSnapshot> {
        let now_ms = crate::logger::now_ms();
        let day_ago_ms = now_ms - 24 * 60 * 60 * 1000;

        Ok(StatsSnapshot {
            uptime_seconds: self.started.elapsed().as_secs(),
            server: ServerIdentity {
                name: self.server.name.clone(),
                version: self.server.version.clone(),
                protocol_version: self.server.protocol_version,
            },
            total_events: self.logger.count_events().await?,
            total_detections: self.logger.count_detections().await?,
            events_by_method: self.logger.events_by_method().await?,
            detections_by_category: self.logger.detections_by_category().await?,
            unique_remote_addrs_24h: self.logger.unique_remote_addrs_since(day_ago_ms).await?,
            top_tools: self.logger.top_tools(10).await?,
        })
    }
}
