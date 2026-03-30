//! Per-turn secret registry for PTC stdout/stderr redaction.
//!
//! When the agent calls `get_secret_value` via PTC IPC, the kernel
//! intercepts the tool result and records the secret name→value mapping.
//! After the Python subprocess completes, all known secret values are
//! scrubbed from stdout/stderr before the output enters the LLM context.
//!
//! This is the **real security boundary** — the `SecretValue` Python class
//! with masked `__str__` is an ergonomic convenience, but the LLM can
//! override it.  The kernel-level redaction cannot be bypassed because it
//! runs outside the Python sandbox.
//!
//! All secret values are stored as `Zeroizing<String>` and are scrubbed
//! from memory when the registry is dropped (end of the PTC turn).

use std::collections::HashMap;
use std::collections::HashSet;
use zeroize::Zeroizing;

/// Bare tool name that returns secret plaintext via PTC IPC.
pub const SECRET_TOOL_NAME: &str = "get_secret_value";

/// Check whether `tool_name` is a secret-fetching tool.
///
/// MCP tools are namespaced as `mcp_{server}_{tool}` so the actual IPC
/// tool name for our secrets-mcp server is `mcp_secrets_get_secret_value`.
/// This function handles both the bare name and any MCP-namespaced variant.
pub fn is_secret_tool(tool_name: &str) -> bool {
    tool_name == SECRET_TOOL_NAME
        || (tool_name.starts_with("mcp_") && tool_name.ends_with("_get_secret_value"))
}

/// In-memory registry of secrets fetched during a single PTC turn.
///
/// Created at the start of an `execute_code` invocation, populated as
/// `get_secret_value` IPC calls are dispatched, consumed for redaction
/// when the Python subprocess exits, and dropped (zeroized) afterward.
#[derive(Default)]
pub struct SecretRegistry {
    /// name → plaintext value (zeroized on drop).
    secrets: HashMap<String, Zeroizing<String>>,
}

impl SecretRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a secret fetched via `get_secret_value`.
    ///
    /// Called by the IPC dispatch loop when it intercepts a
    /// `get_secret_value` tool result.
    pub fn insert(&mut self, name: String, value: String) {
        self.secrets.insert(name, Zeroizing::new(value));
    }

    /// Returns true if the registry has recorded any secrets.
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// JSON field names whose values are considered sensitive.
    ///
    /// When a secret's value is valid JSON (object or array), the redactor
    /// walks the structure and collects string values under these keys.
    /// Those sub-values are then individually redacted from the output,
    /// catching cases where Python extracts and prints a nested field
    /// rather than the full blob.
    const SENSITIVE_FIELDS: &[&str] = &[
        "access_token",
        "refresh_token",
        "token",
        "api_key",
        "api_secret",
        "secret",
        "secret_key",
        "password",
        "client_secret",
        "private_key",
        "signing_secret",
    ];

    /// Minimum length for a sub-value to be worth redacting.
    /// Very short strings (e.g. "true", "1") would cause false positives.
    const MIN_SENSITIVE_LEN: usize = 8;

    /// Redact all known secret values from `text`.
    ///
    /// Two passes:
    ///
    /// 1. **Full-value replacement** — every occurrence of the complete
    ///    secret plaintext is replaced with `[SECRET:<name>]`.
    ///
    /// 2. **Deep JSON extraction** — if the secret value is valid JSON,
    ///    any string values under [`SENSITIVE_FIELDS`] are also redacted
    ///    individually.  This catches the case where Python code parses
    ///    the secret JSON and prints only a sub-field (e.g., an embedded
    ///    `access_token`).
    ///
    /// Operates on raw strings — no regex, just exact substring
    /// replacement.  Returns the redacted string.
    pub fn redact(&self, text: &str) -> String {
        if self.secrets.is_empty() {
            return text.to_string();
        }

        let mut result = text.to_string();

        // Collect all redaction targets: (needle, placeholder).
        // Use a Vec so longer needles are replaced first (avoids partial
        // matches when a sub-value is a prefix of the full value).
        let mut targets: Vec<(String, String)> = Vec::new();

        for (name, value) in &self.secrets {
            if value.is_empty() {
                continue;
            }

            // Full-value match.
            targets.push((value.as_str().to_string(), format!("[SECRET:{}]", name)));

            // Deep extraction: walk JSON structure for sensitive leaves.
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value.as_str()) {
                let mut seen = HashSet::new();
                Self::collect_sensitive_values(&parsed, &mut seen);
                for sv in seen {
                    if sv.len() >= Self::MIN_SENSITIVE_LEN && sv != value.as_str() {
                        targets.push((sv, format!("[SECRET:{}]", name)));
                    }
                }
            }
        }

        // Sort by descending needle length so longer matches take priority.
        targets.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        for (needle, placeholder) in &targets {
            result = result.replace(needle.as_str(), placeholder);
        }

        result
    }

    /// Recursively collect string values from JSON fields whose names
    /// appear in [`SENSITIVE_FIELDS`].
    fn collect_sensitive_values(val: &serde_json::Value, out: &mut HashSet<String>) {
        match val {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let key_lower = k.to_lowercase();
                    if Self::SENSITIVE_FIELDS.iter().any(|f| *f == key_lower) {
                        if let Some(s) = v.as_str() {
                            out.insert(s.to_string());
                        }
                    }
                    // Recurse into nested structures regardless.
                    Self::collect_sensitive_values(v, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    Self::collect_sensitive_values(item, out);
                }
            }
            _ => {}
        }
    }

    /// Try to extract a secret name and value from a `get_secret_value`
    /// tool result JSON.
    ///
    /// Expected format: `{"name": "MY_KEY", "value": "the-secret"}`
    ///
    /// Returns `Some((name, value))` on success, `None` if the result
    /// doesn't match (e.g., error responses).
    pub fn parse_secret_from_tool_result(content: &str) -> Option<(String, String)> {
        let parsed: serde_json::Value = serde_json::from_str(content).ok()?;
        let name = parsed.get("name")?.as_str()?.to_string();
        let value = parsed.get("value")?.as_str()?.to_string();
        if name.is_empty() || value.is_empty() {
            return None;
        }
        Some((name, value))
    }
}

impl Drop for SecretRegistry {
    fn drop(&mut self) {
        // Zeroizing<String> values are automatically scrubbed on drop.
        // Explicit clear ensures the HashMap entries are removed.
        self.secrets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_replaces_secret_values() {
        let mut reg = SecretRegistry::new();
        reg.insert("API_KEY".to_string(), "sk-abc123".to_string());
        reg.insert("DB_PASS".to_string(), "hunter2".to_string());

        let input = "Using key sk-abc123 and password hunter2 to connect";
        let output = reg.redact(input);
        assert_eq!(
            output,
            "Using key [SECRET:API_KEY] and password [SECRET:DB_PASS] to connect"
        );
    }

    #[test]
    fn test_redact_no_secrets_returns_original() {
        let reg = SecretRegistry::new();
        let input = "No secrets here";
        assert_eq!(reg.redact(input), input);
    }

    #[test]
    fn test_redact_no_match_returns_original() {
        let mut reg = SecretRegistry::new();
        reg.insert("KEY".to_string(), "secret-value".to_string());
        let input = "This text has no matching values";
        assert_eq!(reg.redact(input), input);
    }

    #[test]
    fn test_parse_secret_from_tool_result() {
        let json = r#"{"name": "MY_KEY", "value": "the-secret"}"#;
        let (name, value) = SecretRegistry::parse_secret_from_tool_result(json).unwrap();
        assert_eq!(name, "MY_KEY");
        assert_eq!(value, "the-secret");
    }

    #[test]
    fn test_parse_secret_error_response() {
        let json = r#"{"error": "Secret 'X' not found"}"#;
        assert!(SecretRegistry::parse_secret_from_tool_result(json).is_none());
    }

    #[test]
    fn test_multiple_occurrences_redacted() {
        let mut reg = SecretRegistry::new();
        reg.insert("TOKEN".to_string(), "abc123".to_string());
        let input = "First: abc123, second: abc123";
        let output = reg.redact(input);
        assert_eq!(output, "First: [SECRET:TOKEN], second: [SECRET:TOKEN]");
    }

    #[test]
    fn test_is_secret_tool_bare_name() {
        assert!(is_secret_tool("get_secret_value"));
    }

    #[test]
    fn test_is_secret_tool_mcp_namespaced() {
        assert!(is_secret_tool("mcp_secrets_get_secret_value"));
    }

    #[test]
    fn test_is_secret_tool_other_server() {
        // Any MCP server with a get_secret_value tool should match
        assert!(is_secret_tool("mcp_custom_server_get_secret_value"));
    }

    #[test]
    fn test_is_secret_tool_non_matching() {
        assert!(!is_secret_tool("list_secrets"));
        assert!(!is_secret_tool("mcp_secrets_list_secrets"));
        assert!(!is_secret_tool("get_secret_valuex")); // suffix mismatch
    }

    #[test]
    fn test_deep_json_redaction_nested_access_token() {
        let mut reg = SecretRegistry::new();
        // Secret value is a JSON array with embedded access_token
        let secret_value =
            r#"[{"cloud_id":"abc","access_token":"eyJraWQiOiJhdXRo.long-jwt-token"}]"#;
        reg.insert("ATLASSIAN_SITES".to_string(), secret_value.to_string());

        // Python extracts and prints just the access_token
        let stdout = "Using token: eyJraWQiOiJhdXRo.long-jwt-token to authenticate";
        let output = reg.redact(stdout);
        assert!(
            !output.contains("eyJraWQi"),
            "access_token should be redacted, got: {output}"
        );
        assert!(
            output.contains("[SECRET:ATLASSIAN_SITES]"),
            "should contain placeholder, got: {output}"
        );
    }

    #[test]
    fn test_deep_json_redaction_full_value_still_works() {
        let mut reg = SecretRegistry::new();
        let secret_value = r#"{"key":"sk-1234567890abcdef"}"#;
        reg.insert("API_KEY".to_string(), secret_value.to_string());

        // Full value appears in stdout
        let stdout = format!("Result: {}", secret_value);
        let output = reg.redact(&stdout);
        assert!(
            !output.contains("sk-1234567890abcdef"),
            "full value should be redacted, got: {output}"
        );
    }

    #[test]
    fn test_deep_json_short_values_not_redacted() {
        let mut reg = SecretRegistry::new();
        // "token" value is too short to redact (< MIN_SENSITIVE_LEN)
        let secret_value = r#"{"token":"abc"}"#;
        reg.insert("MY_SECRET".to_string(), secret_value.to_string());

        // The full value should still be redacted (full-value match)
        let stdout = format!("Got: {}", secret_value);
        let output = reg.redact(&stdout);
        assert!(
            !output.contains(r#"{"token":"abc"}"#),
            "full value should be redacted, got: {output}"
        );
        // But "abc" alone should NOT be redacted (too short for deep extraction)
        let stdout2 = "Short value: abc is fine";
        let output2 = reg.redact(stdout2);
        assert_eq!(output2, stdout2);
    }

    #[test]
    fn test_deep_json_multiple_sensitive_fields() {
        let mut reg = SecretRegistry::new();
        let secret_value = r#"{"access_token":"eyJhbGciOiJSUzI1NiIsInR5","refresh_token":"dGhpc2lzYXJlZnJlc2h0b2tlbg"}"#;
        reg.insert("OAUTH".to_string(), secret_value.to_string());

        // Python prints both tokens separately
        let stdout = "Access: eyJhbGciOiJSUzI1NiIsInR5\nRefresh: dGhpc2lzYXJlZnJlc2h0b2tlbg";
        let output = reg.redact(stdout);
        assert!(
            !output.contains("eyJhbGci"),
            "access_token leaked: {output}"
        );
        assert!(
            !output.contains("dGhpc2lz"),
            "refresh_token leaked: {output}"
        );
    }
}
