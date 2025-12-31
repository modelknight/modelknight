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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Action, AppliesTo, Field, MatchExpr, When, Rule};

    #[test]
    fn compile_exact_match_rule() {
        let rule = Rule {
            id: "test-exact".to_string(),
            description: Some("Test exact match".to_string()),
            applies_to: AppliesTo::Prompt,
            action: Action::Block,
            priority: 10,
            when: When {
                any: vec![MatchExpr::Exact {
                    field: Field::Text,
                    value: "dangerous".to_string(),
                }],
            },
        };

        let compiled = compile_rule(&rule).unwrap();
        assert_eq!(compiled.id, "test-exact");
        assert_eq!(compiled.when_any.len(), 1);
        
        match &compiled.when_any[0] {
            CompiledMatch::Exact { field, value } => {
                assert!(matches!(field, Field::Text));
                assert_eq!(value, "dangerous");
            }
            _ => panic!("Expected Exact match"),
        }
    }

    #[test]
    fn compile_regex_match_rule() {
        let rule = Rule {
            id: "test-regex".to_string(),
            description: None,
            applies_to: AppliesTo::Both,
            action: Action::Block,
            priority: 5,
            when: When {
                any: vec![MatchExpr::Regex {
                    field: Field::Text,
                    pattern: r"\b(hack|exploit)\b".to_string(),
                }],
            },
        };

        let compiled = compile_rule(&rule).unwrap();
        assert_eq!(compiled.when_any.len(), 1);
        
        match &compiled.when_any[0] {
            CompiledMatch::Regex { field, re, .. } => {
                assert!(matches!(field, Field::Text));
                assert!(re.is_match("try to hack this"));
                assert!(!re.is_match("hacking around"));
            }
            _ => panic!("Expected Regex match"),
        }
    }

    #[test]
    fn compile_keywords_match_rule() {
        let rule = Rule {
            id: "test-keywords".to_string(),
            description: None,
            applies_to: AppliesTo::Response,
            action: Action::Block,
            priority: 15,
            when: When {
                any: vec![MatchExpr::Keywords {
                    field: Field::Text,
                    values: vec!["password".to_string(), "secret".to_string()],
                }],
            },
        };

        let compiled = compile_rule(&rule).unwrap();
        assert_eq!(compiled.when_any.len(), 1);
        
        match &compiled.when_any[0] {
            CompiledMatch::Keywords { field, ac, .. } => {
                assert!(matches!(field, Field::Text));
                let text = "enter your password";
                let matches: Vec<_> = ac.find_iter(text).collect();
                assert_eq!(matches.len(), 1);
            }
            _ => panic!("Expected Keywords match"),
        }
    }

    #[test]
    fn compile_invalid_regex_fails() {
        let rule = Rule {
            id: "bad-regex".to_string(),
            description: None,
            applies_to: AppliesTo::Prompt,
            action: Action::Block,
            priority: 1,
            when: When {
                any: vec![MatchExpr::Regex {
                    field: Field::Text,
                    pattern: "[invalid(".to_string(), // Invalid regex
                }],
            },
        };

        assert!(compile_rule(&rule).is_err());
    }

    #[test]
    fn compile_multiple_matchers() {
        let rule = Rule {
            id: "multi".to_string(),
            description: None,
            applies_to: AppliesTo::Both,
            action: Action::Block,
            priority: 20,
            when: When {
                any: vec![
                    MatchExpr::Exact {
                        field: Field::Text,
                        value: "exact".to_string(),
                    },
                    MatchExpr::Regex {
                        field: Field::Text,
                        pattern: r"regex\d+".to_string(),
                    },
                    MatchExpr::Keywords {
                        field: Field::Text,
                        values: vec!["key1".to_string(), "key2".to_string()],
                    },
                ],
            },
        };

        let compiled = compile_rule(&rule).unwrap();
        assert_eq!(compiled.when_any.len(), 3);
    }
}
