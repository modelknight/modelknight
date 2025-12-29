use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use uuid::Uuid;

use crate::compile::{CompiledMatch, CompiledRule};
use crate::{
    pii_regex::PiiRegexDetector,
    policy::{Action, AppliesTo, EvalRequest, EvalResponse, Kind, Rule},
    store::RuleStore,
};

#[derive(Clone)]
pub struct AppState {
    pub store: RuleStore,
    pub pii_regex: PiiRegexDetector,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // CRUD
        .route("/v1/rules", get(list_rules).post(create_rule))
        .route(
            "/v1/rules/:id",
            get(get_rule).put(update_rule).delete(delete_rule),
        )
        // Evaluate
        .route("/v1/eval", post(eval))
        .with_state(state)
        .layer(tower_http::trace::TraceLayer::new_for_http())
}

async fn list_rules(State(st): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, Json(st.store.list_rules().await))
}

async fn get_rule(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match st.store.get_rule(&id).await {
        Some(rule) => (StatusCode::OK, Json(rule)).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn create_rule(State(st): State<AppState>, Json(rule): Json<Rule>) -> impl IntoResponse {
    match st.store.create_rule(rule).await {
        Ok(_) => (StatusCode::CREATED, "created").into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn update_rule(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Json(rule): Json<Rule>,
) -> impl IntoResponse {
    match st.store.update_rule(&id, rule).await {
        Ok(_) => (StatusCode::OK, "updated").into_response(),
        Err(e) if e.to_string().contains("not found") => {
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn delete_rule(State(st): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match st.store.delete_rule(&id).await {
        Ok(_) => (StatusCode::NO_CONTENT, "").into_response(),
        Err(e) if e.to_string().contains("not found") => {
            (StatusCode::NOT_FOUND, "not found").into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn eval(State(st): State<AppState>, Json(mut req): Json<EvalRequest>) -> impl IntoResponse {
    let request_id = req.request_id.unwrap_or_else(Uuid::new_v4);
    req.request_id = Some(request_id);

    // Stage 1: rules
    let compiled = st.store.compiled_snapshot().await;
    let (action, matched_rule, reason) = evaluate_stage1(&compiled, &req);

    // If Stage 1 blocks, short-circuit (don’t bother masking)
    if matches!(action, Action::Block) {
        let resp = EvalResponse {
            request_id,
            action,
            matched_rule,
            reason,
            output_text: None,
            pii: None,
        };
        return (StatusCode::OK, Json(resp)).into_response();
    }

    // Stage 2a: full masking (OSS)
    let (masked, findings) = st.pii_regex.full_mask(&req.text);

    let (output_text, pii) = if findings.is_empty() {
        (None, None)
    } else {
        let pii_entities = findings
            .into_iter()
            .map(|f| crate::policy::PiiEntity {
                entity_type: format!("{:?}", f.pii_type),
                start: f.start,
                end: f.end,
                score: 1.0,
                text: f.text,
            })
            .collect::<Vec<_>>();

        (Some(masked), Some(pii_entities))
    };

    let resp = EvalResponse {
        request_id,
        action: Action::Allow,
        matched_rule,
        reason,
        output_text,
        pii,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

fn evaluate_stage1(
    rules: &[CompiledRule],
    req: &EvalRequest,
) -> (Action, Option<String>, Option<String>) {
    for r in rules {
        if !applies(&r.applies_to, &req.kind) {
            continue;
        }
        if r.when_any.iter().any(|m| match_one(m, req)) {
            let reason = r
                .description
                .clone()
                .or_else(|| Some("matched".to_string()));
            return (r.action.clone(), Some(r.id.clone()), reason);
        }
    }
    (Action::Allow, None, None)
}

fn applies(applies_to: &AppliesTo, kind: &Kind) -> bool {
    match (applies_to, kind) {
        (AppliesTo::Both, _) => true,
        (AppliesTo::Prompt, Kind::Prompt) => true,
        (AppliesTo::Response, Kind::Response) => true,
        _ => false,
    }
}

fn field_value<'a>(field: &crate::policy::Field, req: &'a EvalRequest) -> &'a str {
    match field {
        crate::policy::Field::Text => req.text.as_str(),
        crate::policy::Field::Tenant => req.tenant.as_deref().unwrap_or(""),
        crate::policy::Field::Model => req.model.as_deref().unwrap_or(""),
    }
}

fn match_one(m: &CompiledMatch, req: &EvalRequest) -> bool {
    match m {
        CompiledMatch::Exact { field, value } => field_value(field, req) == value,
        CompiledMatch::Regex { field, re, .. } => re.is_match(field_value(field, req)),
        CompiledMatch::Keywords { field, ac, .. } => ac.is_match(field_value(field, req)),
    }
}
