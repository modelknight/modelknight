use crate::compile::{compile_rule, CompiledRule};
use crate::policy::{PiiConfig, PolicyFile, Rule};
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
}

impl RuleStore {
    pub async fn load(policy_path: PathBuf) -> anyhow::Result<Self> {
        let raw = tokio::fs::read_to_string(&policy_path)
            .await
            .unwrap_or_else(|_| "rules: []\n".to_string());

        // PolicyFile has #[serde(default)] on pii, so older YAML without pii works.
        let policy: PolicyFile = serde_yaml::from_str(&raw)?;
        let compiled = compile_all(&policy.rules)?;

        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                policy_path,
                rules: policy.rules,
                compiled,
                pii: policy.pii,
            })),
        })
    }

    // -------------------------
    // Policy-level operations
    // -------------------------

    /// Returns the currently active full policy (rules + pii).
    pub async fn get_policy(&self) -> PolicyFile {
        let r = self.inner.read().await;
        PolicyFile {
            rules: r.rules.clone(),
            pii: r.pii.clone(),
        }
    }

    /// Applies a full policy atomically:
    /// - validate + compile rules first (fail fast)
    /// - swap state (rules + compiled + pii)
    /// - persist to disk
    pub async fn apply_policy(&self, policy: PolicyFile) -> anyhow::Result<()> {
        // Compile first — if it fails (bad regex), we don’t mutate state or persist.
        let compiled = compile_all(&policy.rules)?;

        let mut w = self.inner.write().await;
        w.rules = policy.rules;
        w.pii = policy.pii;
        w.compiled = compiled;

        persist_locked(&w).await
    }

    /// Convenience setter for Stage 2 config (optional).
    /// Internally persists the full policy.
    pub async fn set_pii_config(&self, pii: PiiConfig) -> anyhow::Result<()> {
        let mut policy = self.get_policy().await;
        policy.pii = pii;
        self.apply_policy(policy).await
    }

    // -------------------------
    // Rule CRUD (Stage 1)
    // -------------------------

    pub async fn list_rules(&self) -> Vec<Rule> {
        self.inner.read().await.rules.clone()
    }

    pub async fn get_rule(&self, id: &str) -> Option<Rule> {
        self.inner
            .read()
            .await
            .rules
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    pub async fn create_rule(&self, rule: Rule) -> anyhow::Result<()> {
        let mut w = self.inner.write().await;
        if w.rules.iter().any(|r| r.id == rule.id) {
            anyhow::bail!("rule id already exists");
        }
        w.rules.push(rule);
        rebuild_and_persist(&mut w).await
    }

    pub async fn update_rule(&self, id: &str, rule: Rule) -> anyhow::Result<()> {
        let mut w = self.inner.write().await;
        let idx = w
            .rules
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| anyhow::anyhow!("not found"))?;

        let mut updated = rule;
        updated.id = id.to_string(); // path param is canonical
        w.rules[idx] = updated;

        rebuild_and_persist(&mut w).await
    }

    pub async fn delete_rule(&self, id: &str) -> anyhow::Result<()> {
        let mut w = self.inner.write().await;
        let before = w.rules.len();
        w.rules.retain(|r| r.id != id);
        if w.rules.len() == before {
            anyhow::bail!("not found");
        }
        rebuild_and_persist(&mut w).await
    }

    pub async fn compiled_snapshot(&self) -> Vec<CompiledRule> {
        self.inner.read().await.compiled.clone()
    }

    pub async fn pii_config(&self) -> PiiConfig {
        self.inner.read().await.pii.clone()
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

async fn rebuild_and_persist(w: &mut Inner) -> anyhow::Result<()> {
    // Compile first — if it fails (bad regex), we don’t persist a broken policy
    w.compiled = compile_all(&w.rules)?;
    persist_locked(w).await
}

async fn persist_locked(w: &Inner) -> anyhow::Result<()> {
    // Persist rules + pii
    let policy = PolicyFile {
        rules: w.rules.clone(),
        pii: w.pii.clone(),
    };
    let yaml = serde_yaml::to_string(&policy)?;

    tokio::fs::create_dir_all(w.policy_path.parent().unwrap_or(std::path::Path::new("./"))).await?;
    tokio::fs::write(&w.policy_path, yaml).await?;
    Ok(())
}
