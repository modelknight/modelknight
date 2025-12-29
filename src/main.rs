mod api;
mod compile;
mod pii_regex;
mod policy;
mod store;
//mod evaluator; // if you extracted stage1 evaluator into its own module

use api::{router, AppState};
use pii_regex::PiiRegexDetector;
use std::path::PathBuf;
use store::RuleStore;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let bind = std::env::var("ENGINE_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let policy_path =
        std::env::var("POLICY_PATH").unwrap_or_else(|_| "./configs/policy.yaml".to_string());

    // Load policy/rules from YAML
    let store = RuleStore::load(PathBuf::from(policy_path)).await?;

    // Stage 2a detector (full masking)
    let pii_regex = PiiRegexDetector::new()?;

    // Build HTTP router with shared state
    let app = router(AppState { store, pii_regex });

    info!("engine listening on {}", bind);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
