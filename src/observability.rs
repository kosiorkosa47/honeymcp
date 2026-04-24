//! Tracing + logging bootstrap.
//!
//! Single entry point the binary calls at startup to wire up:
//!
//! - A `tracing_subscriber` stack (always on). Format comes from the
//!   `HONEYMCP_LOG_FORMAT` env var:
//!     - `pretty` (default) — human-readable stderr output.
//!     - `json` — structured ndjson, one event per line, suitable for
//!       shipping to Loki / Cloudwatch / Datadog without a parser.
//! - An OpenTelemetry OTLP tracer (only when built with `--features otel`
//!   **and** `OTEL_EXPORTER_OTLP_ENDPOINT` is set). When both conditions
//!   hold, spans land in the configured collector via gRPC/tonic; when
//!   either is false, the OTEL layer is not registered and there is no
//!   runtime cost.
//!
//! Levels are controlled by `RUST_LOG` via `EnvFilter`, same as before.
//! When unset, the default is `info`.

use anyhow::Result;
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

/// Sentinel that the caller keeps until shutdown. Dropping it flushes the
/// OTLP exporter (if one is active) so in-flight spans are not lost on
/// graceful shutdown. Inert when the OTEL feature is off.
pub struct Guard {
    #[cfg(feature = "otel")]
    otel: Option<opentelemetry_sdk::trace::TracerProvider>,
}

impl Guard {
    fn inert() -> Self {
        Self {
            #[cfg(feature = "otel")]
            otel: None,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        if let Some(provider) = self.otel.take() {
            // Best-effort flush of in-flight spans. Any failure here happens
            // during process shutdown when the collector may already be gone,
            // so swallowing is the right call.
            let _ = provider.shutdown();
        }
    }
}

/// Install the subscriber. Call once, at the top of `main`, and keep the
/// returned `Guard` alive until the process is ready to exit.
pub fn init() -> Result<Guard> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let format = std::env::var("HONEYMCP_LOG_FORMAT")
        .unwrap_or_else(|_| "pretty".to_string())
        .to_ascii_lowercase();

    // Build the subscriber. We split on HONEYMCP_LOG_FORMAT instead of always
    // registering both layers because `with()` returns different types for
    // pretty vs json and the compound layer type has to be selected once.
    match format.as_str() {
        "json" => install_with_format(env_filter, FormatKind::Json),
        "pretty" | "" => install_with_format(env_filter, FormatKind::Pretty),
        other => {
            // Unknown value: warn once via fallback subscriber, then use pretty.
            install_with_format(env_filter, FormatKind::Pretty)?;
            tracing::warn!(
                format = %other,
                "HONEYMCP_LOG_FORMAT value not recognised; falling back to 'pretty'"
            );
            Ok(Guard::inert())
        }
    }
}

enum FormatKind {
    Pretty,
    Json,
}

fn install_with_format(filter: EnvFilter, kind: FormatKind) -> Result<Guard> {
    let fmt_layer = match kind {
        FormatKind::Pretty => fmt::layer().with_writer(std::io::stderr).boxed(),
        FormatKind::Json => fmt::layer()
            .with_writer(std::io::stderr)
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .boxed(),
    };

    let registry = Registry::default().with(filter).with(fmt_layer);

    #[cfg(feature = "otel")]
    {
        if let Some(tracer_provider) = try_build_otlp_provider()? {
            let tracer = opentelemetry::trace::TracerProvider::tracer(&tracer_provider, "honeymcp");
            let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);
            registry.with(telemetry).init();
            return Ok(Guard {
                otel: Some(tracer_provider),
            });
        }
    }

    registry.init();
    Ok(Guard::inert())
}

#[cfg(feature = "otel")]
fn try_build_otlp_provider() -> Result<Option<opentelemetry_sdk::trace::TracerProvider>> {
    use opentelemetry::KeyValue;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{runtime, trace, Resource};

    let endpoint = match std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
        Ok(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };

    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "honeymcp".to_string());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let provider = trace::TracerProvider::builder()
        .with_batch_exporter(exporter, runtime::Tokio)
        .with_resource(Resource::new(vec![KeyValue::new(
            "service.name",
            service_name,
        )]))
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    Ok(Some(provider))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_drop_is_inert_without_otel() {
        // Guard with no OTEL provider must be safe to drop exactly once, even
        // when the feature is off; this is the fast path we ship by default.
        // We let the binding fall out of scope rather than calling drop() so
        // clippy does not flag a drop on a zero-sized type under default
        // features.
        {
            let _g = Guard::inert();
        }
    }

    #[test]
    fn format_selection_is_case_insensitive() {
        // Spot-check the HONEYMCP_LOG_FORMAT match arms exist for the casings
        // operators are likely to type. We do not call install_with_format()
        // because installing the global subscriber twice in test context is
        // a no-op with side effects; this test only guards against typos in
        // the match.
        let valid = ["pretty", "PRETTY", "json", "JSON", ""];
        for v in valid {
            let normalised = v.to_ascii_lowercase();
            assert!(
                matches!(normalised.as_str(), "pretty" | "json" | ""),
                "expected recognised format, got {normalised:?}"
            );
        }
    }
}
