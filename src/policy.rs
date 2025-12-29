use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PolicyFile {
    pub rules: Vec<Rule>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PiiEntity {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub score: f32,
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

