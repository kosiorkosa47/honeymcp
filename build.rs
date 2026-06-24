use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let supplied_sha = std::env::var("HONEYMCP_GIT_SHA")
        .ok()
        .map(|s| short_sha(&s))
        .filter(|s| !s.is_empty() && s != "unknown");

    let (sha, dirty) = match supplied_sha {
        Some(sha) => (sha, false),
        None => {
            let sha = Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let dirty = Command::new("git")
                .args(["status", "--porcelain"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| !o.stdout.is_empty())
                .unwrap_or(false);

            (sha, dirty)
        }
    };

    let sha = if dirty { format!("{sha}-dirty") } else { sha };

    let unix_ts = std::env::var("HONEYMCP_BUILD_UNIX_TS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });

    println!("cargo:rustc-env=HONEYMCP_GIT_SHA={sha}");
    println!("cargo:rustc-env=HONEYMCP_BUILD_UNIX_TS={unix_ts}");

    // Re-run if HEAD changes; the index check is cheap and avoids stale stamps.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-env-changed=HONEYMCP_GIT_SHA");
    println!("cargo:rerun-if-env-changed=HONEYMCP_BUILD_UNIX_TS");
}

fn short_sha(raw: &str) -> String {
    let s = raw.trim();
    if s.len() > 12 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        s.chars().take(12).collect()
    } else {
        s.to_string()
    }
}
