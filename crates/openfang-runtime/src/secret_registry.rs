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
use zeroize::Zeroizing;

/// MCP tool name that returns secret plaintext via PTC IPC.
pub const SECRET_TOOL_NAME: &str = "get_secret_value";

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

    /// Redact all known secret values from `text`.
    ///
    /// Replaces every occurrence of each secret's plaintext with
    /// `[SECRET:<name>]`.  Operates on the raw string — no regex,
    /// just exact substring replacement.
    ///
    /// Returns the redacted string.  If no secrets are registered or
    /// no matches are found, the original string is returned unmodified.
    pub fn redact(&self, text: &str) -> String {
        if self.secrets.is_empty() {
            return text.to_string();
        }

        let mut result = text.to_string();
        for (name, value) in &self.secrets {
            if !value.is_empty() {
                // Replace the full value.
                let placeholder = format!("[SECRET:{}]", name);
                result = result.replace(value.as_str(), &placeholder);
            }
        }
        result
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
}
