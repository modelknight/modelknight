use crate::policy::{Action, AppliesTo, Field, MatchExpr, Rule};
use aho_corasick::AhoCorasick;
use regex::Regex;

#[derive(Clone)]
pub struct CompiledRule {
    pub id: String,
    pub description: Option<String>,
    pub applies_to: AppliesTo,
    pub action: Action,
    pub priority: u32,
    pub when_any: Vec<CompiledMatch>, // OR list
}

#[derive(Clone)]
pub enum CompiledMatch {
    Exact {
        field: Field,
        value: String,
    },
    Regex {
        field: Field,
        re: Regex,
        raw: String,
    },
    Keywords {
        field: Field,
        ac: AhoCorasick,
        raw: Vec<String>,
    },
}

pub fn compile_rule(rule: &Rule) -> anyhow::Result<CompiledRule> {
    let mut compiled = Vec::with_capacity(rule.when.any.len());

    for expr in &rule.when.any {
        let c = match expr {
            MatchExpr::Exact { field, value } => CompiledMatch::Exact {
                field: field.clone(),
                value: value.clone(),
            },
            MatchExpr::Regex { field, pattern } => {
                let re = Regex::new(pattern)?;
                CompiledMatch::Regex {
                    field: field.clone(),
                    re,
                    raw: pattern.clone(),
                }
            }
            MatchExpr::Keywords { field, values } => {
                let ac = AhoCorasick::new(values)?;
                CompiledMatch::Keywords {
                    field: field.clone(),
                    ac,
                    raw: values.clone(),
                }
            }
        };
        compiled.push(c);
    }

    Ok(CompiledRule {
        id: rule.id.clone(),
        description: rule.description.clone(),
        applies_to: rule.applies_to.clone(),
        action: rule.action.clone(),
        priority: rule.priority,
        when_any: compiled,
    })
}
