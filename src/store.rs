use crate::compile::{compile_rule, CompiledRule};
use crate::policy::{PiiConfig, PolicyFile, Rule, SemanticConfig};
use crate::semantic::{compile_semantic, CompiledSemantic};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct RuleStore {
    inner: Arc<RwLock<Inner>>,
}

struct Inner {
    policy_path: PathBuf,
    rules: Vec<Rule>,
    compiled: Vec<CompiledRule>,
    pii: PiiConfig,
    semantic_cfg: SemanticConfig,
    semantic: CompiledSemantic,
}

impl RuleStore {
    pub async fn load(policy_path: PathBuf) -> anyhow::Result<Self> {
        let raw = tokio::fs::read_to_string(&policy_path)
            .await
            .unwrap_or_else(|_| "rules: []\n".to_string());

        let policy: PolicyFile = serde_yaml::from_str(&raw)?;

        let compiled = compile_all(&policy.rules)?;
        let semantic_cfg = policy.semantic.clone();
        let semantic = compile_semantic(&semantic_cfg);

        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                policy_path,
                rules: policy.rules,
                compiled,
                pii: policy.pii,
                semantic_cfg,
                semantic,
            })),
        })
    }

    // -------------------------
    // Policy-level operations
    // -------------------------

    /// Returns the currently active full policy (rules + pii + semantic).
    pub async fn get_policy(&self) -> PolicyFile {
        let r = self.inner.read().await;
        PolicyFile {
            rules: r.rules.clone(),
            pii: r.pii.clone(),
            semantic: r.semantic_cfg.clone(),
        }
    }

    /// Applies a full policy atomically:
    /// - compile/validate first
    /// - swap state
    /// - persist full policy.yaml
    pub async fn apply_policy(&self, policy: PolicyFile) -> anyhow::Result<()> {
        // Compile first — if it fails (bad regex), we don’t mutate state or persist.
        let compiled = compile_all(&policy.rules)?;
        let semantic_cfg = policy.semantic.clone();
        let semantic = compile_semantic(&semantic_cfg);

        let mut w = self.inner.write().await;
        w.rules = policy.rules;
        w.pii = policy.pii;
        w.compiled = compiled;
        w.semantic_cfg = semantic_cfg;
        w.semantic = semantic;

        persist_locked(&w).await
    }

    // -------------------------
    // Snapshots for fast eval
    // -------------------------

    pub async fn compiled_snapshot(&self) -> Vec<CompiledRule> {
        self.inner.read().await.compiled.clone()
    }

    pub async fn pii_config(&self) -> PiiConfig {
        self.inner.read().await.pii.clone()
    }

    pub async fn semantic_snapshot(&self) -> CompiledSemantic {
        self.inner.read().await.semantic.clone()
    }
}

fn compile_all(rules: &[Rule]) -> anyhow::Result<Vec<CompiledRule>> {
    let mut compiled = Vec::with_capacity(rules.len());
    for r in rules {
        compiled.push(compile_rule(r)?);
    }

    // priority ascending; then id for deterministic tie-breaker
    compiled.sort_by(|a, b| a.priority.cmp(&b.priority).then(a.id.cmp(&b.id)));
    Ok(compiled)
}

async fn persist_locked(w: &Inner) -> anyhow::Result<()> {
    // Persist rules + pii + semantic (policy.yaml is source of truth)
    let policy = PolicyFile {
        rules: w.rules.clone(),
        pii: w.pii.clone(),
        semantic: w.semantic_cfg.clone(),
    };
    let yaml = serde_yaml::to_string(&policy)?;

    tokio::fs::create_dir_all(w.policy_path.parent().unwrap_or(std::path::Path::new("./"))).await?;
    tokio::fs::write(&w.policy_path, yaml).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, AppliesTo, Field, MatchExpr, When, PiiDetectors, PiiMode, Rule, SemanticConfig};
    use tempfile::TempDir;

    async fn create_test_policy() -> PolicyFile {
        PolicyFile {
            rules: vec![Rule {
                id: "test-rule".to_string(),
                description: Some("Test".to_string()),
                applies_to: AppliesTo::Prompt,
                action: Action::Block,
                priority: 10,
                when: When {
                    any: vec![MatchExpr::Exact {
                        field: Field::Text,
                        value: "test".to_string(),
                    }],
                },
            }],
            pii: PiiConfig {
                enabled: true,
                applies_to: AppliesTo::Response,
                mode: PiiMode::Redact,
                redaction_token: "REDACTED".to_string(),
                detectors: PiiDetectors::default(),
                max_bytes: 10000,
                include_findings: false,
            },
            semantic: SemanticConfig::default(),
        }
    }

    #[tokio::test]
    async fn load_and_get_policy() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("policy.yaml");
        
        let policy = create_test_policy().await;
        let yaml = serde_yaml::to_string(&policy).unwrap();
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let store = RuleStore::load(policy_path).await.unwrap();
        let retrieved = store.get_policy().await;
        
        assert_eq!(retrieved.rules.len(), 1);
        assert_eq!(retrieved.rules[0].id, "test-rule");
        assert!(retrieved.pii.enabled);
    }

    #[tokio::test]
    async fn apply_policy_updates_state() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("policy.yaml");
        
        let initial_policy = create_test_policy().await;
        let yaml = serde_yaml::to_string(&initial_policy).unwrap();
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let store = RuleStore::load(policy_path.clone()).await.unwrap();
        
        // Apply new policy
        let mut new_policy = create_test_policy().await;
        new_policy.rules[0].id = "updated-rule".to_string();
        new_policy.pii.enabled = false;
        
        store.apply_policy(new_policy).await.unwrap();
        
        // Verify updated
        let retrieved = store.get_policy().await;
        assert_eq!(retrieved.rules[0].id, "updated-rule");
        assert!(!retrieved.pii.enabled);
        
        // Verify persisted
        let file_content = tokio::fs::read_to_string(&policy_path).await.unwrap();
        let persisted: PolicyFile = serde_yaml::from_str(&file_content).unwrap();
        assert_eq!(persisted.rules[0].id, "updated-rule");
    }

    #[tokio::test]
    async fn compiled_snapshot_returns_sorted_rules() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("policy.yaml");
        
        let mut policy = create_test_policy().await;
        policy.rules.push(Rule {
            id: "high-priority".to_string(),
            description: None,
            applies_to: AppliesTo::Prompt,
            action: Action::Block,
            priority: 5, // Lower than first rule (10)
            when: When {
                any: vec![MatchExpr::Exact {
                    field: Field::Text,
                    value: "urgent".to_string(),
                }],
            },
        });
        
        let yaml = serde_yaml::to_string(&policy).unwrap();
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let store = RuleStore::load(policy_path).await.unwrap();
        let compiled = store.compiled_snapshot().await;
        
        assert_eq!(compiled.len(), 2);
        assert_eq!(compiled[0].id, "high-priority"); // Priority 5 comes first
        assert_eq!(compiled[1].id, "test-rule");     // Priority 10 comes second
    }

    #[tokio::test]
    async fn pii_config_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("policy.yaml");
        
        let policy = create_test_policy().await;
        let yaml = serde_yaml::to_string(&policy).unwrap();
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let store = RuleStore::load(policy_path).await.unwrap();
        let pii = store.pii_config().await;
        
        assert!(pii.enabled);
        assert_eq!(pii.redaction_token, "REDACTED");
    }

    #[tokio::test]
    async fn semantic_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("policy.yaml");
        
        let policy = create_test_policy().await;
        let yaml = serde_yaml::to_string(&policy).unwrap();
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let store = RuleStore::load(policy_path).await.unwrap();
        let semantic = store.semantic_snapshot().await;
        
        assert!(!semantic.enabled); // Default is disabled
    }
}
