use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiiType {
    Email,
    Ip,
    CreditCard,
    Phone,
}

impl PiiType {
    pub fn token(&self) -> &'static str {
        match self {
            PiiType::Email => "[EMAIL]",
            PiiType::Ip => "[IP]",
            PiiType::CreditCard => "[CREDIT_CARD]",
            PiiType::Phone => "[PHONE]",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
    pub text: String,
}

#[derive(Clone)]
pub struct PiiRegexDetector {
    re_email: Regex,
    re_ipv4: Regex,
    re_cc_digits: Regex,
    re_phone: Regex,
}

impl PiiRegexDetector {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            // simple + effective email
            re_email: Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")?,
            // IPv4 candidate, validate range after match
            re_ipv4: Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}\b")?,
            // 13-19 digits, optional spaces or dashes
            // We'll normalize and Luhn-check
            re_cc_digits: Regex::new(r"\b(?:\d[ -]?){13,19}\b")?,
            // very rough phone (improve later). you can add country-specific later.
            re_phone: Regex::new(r"\b(?:\+?\d[\d -]{7,}\d)\b")?,
        })
    }

    pub fn detect(&self, text: &str) -> Vec<Finding> {
        let mut out = Vec::new();

        // EMAIL
        for m in self.re_email.find_iter(text) {
            out.push(Finding {
                pii_type: PiiType::Email,
                start: m.start(),
                end: m.end(),
                text: text[m.start()..m.end()].to_string(),
            });
        }

        // IP v4
        for m in self.re_ipv4.find_iter(text) {
            let s = &text[m.start()..m.end()];
            if is_valid_ipv4(s) {
                out.push(Finding {
                    pii_type: PiiType::Ip,
                    start: m.start(),
                    end: m.end(),
                    text: s.to_string(),
                });
            }
        }

        // CREDIT CARD (Luhn)
        for m in self.re_cc_digits.find_iter(text) {
            let s = &text[m.start()..m.end()];
            let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 13 && digits.len() <= 19 && luhn_valid(&digits) {
                out.push(Finding {
                    pii_type: PiiType::CreditCard,
                    start: m.start(),
                    end: m.end(),
                    text: s.to_string(),
                });
            }
        }

        // PHONE (heuristic: avoid re-masking CC already found; we’ll dedupe later anyway)
        for m in self.re_phone.find_iter(text) {
            let s = &text[m.start()..m.end()];
            let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
            // conservative: phone typically 8-15 digits
            if digits.len() >= 8 && digits.len() <= 15 {
                out.push(Finding {
                    pii_type: PiiType::Phone,
                    start: m.start(),
                    end: m.end(),
                    text: s.to_string(),
                });
            }
        }

        // sort + merge overlaps (prefer longer match, then stable)
        out.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        merge_overlaps(out)
    }

    pub fn full_mask(&self, text: &str) -> (String, Vec<Finding>) {
        let findings = self.detect(text);
        let masked = apply_replacements(text, &findings);
        (masked, findings)
    }
}

/// Apply replacements right-to-left to preserve offsets.
fn apply_replacements(input: &str, findings: &[Finding]) -> String {
    let mut s = input.to_string();
    for f in findings.iter().rev() {
        s.replace_range(f.start..f.end, f.pii_type.token());
    }
    s
}

/// Remove overlaps so we don’t corrupt offsets.
/// Rule: keep the first match, discard any later match that overlaps it.
fn merge_overlaps(sorted: Vec<Finding>) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    let mut last_end: usize = 0;

    for f in sorted {
        if out.is_empty() {
            last_end = f.end;
            out.push(f);
            continue;
        }
        // if overlaps previous kept range, skip
        if f.start < last_end {
            continue;
        }
        last_end = f.end;
        out.push(f);
    }
    out
}

fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    for p in parts {
        if p.is_empty() || p.len() > 3 {
            return false;
        }
        if let Ok(n) = p.parse::<u16>() {
            if n > 255 {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;

    for ch in digits.chars().rev() {
        let mut d = (ch as u8 - b'0') as u32;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_email_fully() {
        let det = PiiRegexDetector::new().unwrap();
        let (out, findings) = det.full_mask("contact me at eugene@example.com please");
        assert!(out.contains("[EMAIL]"));
        assert!(!out.contains("eugene@example.com"));
        assert!(findings.iter().any(|f| f.pii_type == PiiType::Email));
    }

    #[test]
    fn masks_ipv4_fully() {
        let det = PiiRegexDetector::new().unwrap();
        let (out, findings) = det.full_mask("ip is 192.168.45.23 ok");
        assert!(out.contains("[IP]"));
        assert!(!out.contains("192.168.45.23"));
        assert!(findings.iter().any(|f| f.pii_type == PiiType::Ip));
    }

    #[test]
    fn masks_credit_card_only_if_luhn_valid() {
        let det = PiiRegexDetector::new().unwrap();

        let (out1, f1) = det.full_mask("card 4111111111111111");
        assert!(out1.contains("[CREDIT_CARD]"));
        assert!(f1.iter().any(|f| f.pii_type == PiiType::CreditCard));

        // invalid luhn -> should not mask as credit card
        let (out2, f2) = det.full_mask("card 4111111111111112");
        assert!(!out2.contains("[CREDIT_CARD]"));
        assert!(f2.iter().all(|f| f.pii_type != PiiType::CreditCard));
    }

    #[test]
    fn masks_multiple_types_and_preserves_text() {
        let det = PiiRegexDetector::new().unwrap();
        let input = "Email e@example.com IP 8.8.8.8 CC 4111-1111-1111-1111";
        let (out, _) = det.full_mask(input);

        assert!(out.contains("[EMAIL]"));
        assert!(out.contains("[IP]"));
        assert!(out.contains("[CREDIT_CARD]"));
    }
}
