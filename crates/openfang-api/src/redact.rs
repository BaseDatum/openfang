//! Defense-in-depth redaction of sensitive fields from tool result strings.
//!
//! Applied at the API boundary (session GET, WS tool_result events) to
//! ensure secrets never leak to clients even if kernel-level redaction
//! was bypassed or the session contains pre-existing leaked data.

/// JSON field names whose values must be scrubbed from tool results.
const SENSITIVE_JSON_FIELDS: &[&str] = &[
    "access_token",
    "refresh_token",
    "token",
    "api_key",
    "api_secret",
    "secret_key",
    "client_secret",
    "private_key",
    "signing_secret",
    "password",
    "secret",
];

/// Minimum length for a field value to be redacted (avoids false positives
/// on short values like `"token": "true"` or `"secret": "no"`).
const MIN_REDACT_LEN: usize = 8;

/// Scrub known sensitive field values from a tool result string.
///
/// Strategy: try to parse the tool result as JSON. If it's valid JSON,
/// recursively walk the structure and replace values of sensitive fields.
/// Then re-serialize.  If the result isn't valid JSON, return as-is
/// (the kernel-level redaction is the primary defence; this is a safety net).
pub fn redact_sensitive_tool_result(text: &str) -> String {
    // Fast path: try JSON parse.
    if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(text) {
        if redact_json_value(&mut val) {
            return serde_json::to_string(&val).unwrap_or_else(|_| text.to_string());
        }
        // No changes needed — return original to avoid reformatting.
        return text.to_string();
    }

    // Not valid JSON — return as-is.  The kernel-level SecretRegistry
    // redaction (which runs on raw stdout) is the primary defence for
    // non-JSON output.
    text.to_string()
}

/// Recursively walk a JSON value and replace sensitive field values with `"[REDACTED]"`.
/// Returns `true` if any modification was made.
fn redact_json_value(val: &mut serde_json::Value) -> bool {
    let mut changed = false;
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let key_lower = k.to_lowercase();
                if SENSITIVE_JSON_FIELDS.iter().any(|f| *f == key_lower) {
                    if let Some(s) = v.as_str() {
                        if s.len() >= MIN_REDACT_LEN {
                            *v = serde_json::Value::String("[REDACTED]".to_string());
                            changed = true;
                            continue;
                        }
                    }
                }
                if redact_json_value(v) {
                    changed = true;
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                if redact_json_value(item) {
                    changed = true;
                }
            }
        }
        serde_json::Value::String(s) => {
            // Try to parse embedded JSON strings (double-encoded).
            if s.starts_with('{') || s.starts_with('[') {
                if let Ok(mut inner) = serde_json::from_str::<serde_json::Value>(s) {
                    if redact_json_value(&mut inner) {
                        *s = serde_json::to_string(&inner).unwrap_or_else(|_| s.clone());
                        changed = true;
                    }
                }
            }
        }
        _ => {}
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_json_with_access_token() {
        let input = r#"{"cloud_id":"abc","access_token":"eyJraWQiOiJhdXRo.long-token"}"#;
        let output = redact_sensitive_tool_result(input);
        assert!(output.contains("[REDACTED]"), "output: {output}");
        assert!(!output.contains("eyJraWQi"), "output: {output}");
    }

    #[test]
    fn test_redact_nested_array() {
        let input =
            r#"[{"site":"x","access_token":"sk-1234567890abcdef"},{"site":"y","token":"short"}]"#;
        let output = redact_sensitive_tool_result(input);
        assert!(output.contains("[REDACTED]"), "output: {output}");
        assert!(!output.contains("sk-1234567890abcdef"), "output: {output}");
        // "short" is < MIN_REDACT_LEN, should NOT be redacted
        assert!(output.contains("short"), "output: {output}");
    }

    #[test]
    fn test_redact_double_encoded_json() {
        let inner = r#"{"access_token":"eyJraWQiOiJhdXRo.long-token"}"#;
        let outer = serde_json::json!({"result": inner});
        let input = serde_json::to_string(&outer).unwrap();
        let output = redact_sensitive_tool_result(&input);
        assert!(!output.contains("eyJraWQi"), "output: {output}");
    }

    #[test]
    fn test_no_sensitive_fields_unchanged() {
        let input = r#"{"name":"test","value":"hello world"}"#;
        let output = redact_sensitive_tool_result(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_non_json_passthrough() {
        let input = "Just a plain text tool result";
        let output = redact_sensitive_tool_result(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_short_token_not_redacted() {
        let input = r#"{"token":"abc"}"#;
        let output = redact_sensitive_tool_result(input);
        // "abc" is only 3 chars, below MIN_REDACT_LEN
        assert!(output.contains("abc"), "output: {output}");
    }
}
