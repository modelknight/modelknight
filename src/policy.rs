use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PolicyFile {
    pub rules: Vec<Rule>,

    /// Stage 2a: regex-based PII redaction (OSS)
    #[serde(default)]
    pub pii: PiiConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id: String,
    pub description: Option<String>,
    pub applies_to: AppliesTo, // prompt|response|both
    pub action: Action,        // allow|block
    pub priority: u32,         // lower = higher priority
    pub when: When,            // OR list
}

/// Stage 2a config
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PiiConfig {
    pub enabled: bool,
    pub applies_to: AppliesTo, // prompt|response|both
    pub mode: PiiMode,         // redact|off (future: block/report)
    pub redaction_token: String,
    pub detectors: PiiDetectors,
    pub max_bytes: usize,
    pub include_findings: bool,
}

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            applies_to: AppliesTo::Both,
            mode: PiiMode::Redact,
            redaction_token: "REDACTED".to_string(),
            detectors: PiiDetectors::default(),
            max_bytes: 32 * 1024,
            include_findings: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PiiMode {
    Redact,
    Off,
}

impl Default for PiiMode {
    fn default() -> Self {
        PiiMode::Redact
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PiiDetectors {
    pub email: bool,
    pub ip: bool,
    pub credit_card: bool,
    pub phone: bool,
}

impl Default for PiiDetectors {
    fn default() -> Self {
        Self {
            email: false,
            ip: false,
            credit_card: false,
            phone: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PiiEntity {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f32,

    // ⚠️ Consider removing this in default mode to avoid leaking raw PII back.
    // We'll keep it in the struct, but control whether it's populated via include_findings.
    pub text: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvalResponse {
    pub request_id: Uuid,
    pub action: Action,
    pub matched_rule: Option<String>,
    pub reason: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_text: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii: Option<Vec<PiiEntity>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct When {
    pub any: Vec<MatchExpr>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AppliesTo {
    Prompt,
    Response,
    Both,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Text,
    Tenant,
    Model,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MatchExpr {
    Exact { field: Field, value: String },
    Regex { field: Field, pattern: String },
    Keywords { field: Field, values: Vec<String> },
}

/// What apps call to evaluate a prompt/response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvalRequest {
    pub request_id: Option<Uuid>,
    pub kind: Kind, // prompt|response
    pub text: String,
    pub tenant: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Prompt,
    Response,
}
