//! Request/response types for the OpenFang API.

use serde::{Deserialize, Serialize};

/// Request to spawn an agent from a TOML manifest string or a template name.
#[derive(Debug, Deserialize)]
pub struct SpawnRequest {
    /// Agent manifest as TOML string (optional if `template` is provided).
    #[serde(default)]
    pub manifest_toml: String,
    /// Template name from `~/.openfang/agents/{template}/agent.toml`.
    /// When provided and `manifest_toml` is empty, the template is loaded automatically.
    #[serde(default)]
    pub template: Option<String>,
    /// Optional Ed25519 signed manifest envelope (JSON).
    /// When present, the signature is verified before spawning.
    #[serde(default)]
    pub signed_manifest: Option<String>,
}

/// Response after spawning an agent.
#[derive(Debug, Serialize)]
pub struct SpawnResponse {
    pub agent_id: String,
    pub name: String,
}

/// A file attachment reference (from a prior upload).
#[derive(Debug, Clone, Deserialize)]
pub struct AttachmentRef {
    pub file_id: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub content_type: String,
}

/// Request to send a message to an agent.
#[derive(Debug, Deserialize)]
pub struct MessageRequest {
    pub message: String,
    /// Optional file attachments (uploaded via /upload endpoint).
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
    /// Sender identity (e.g. WhatsApp phone number, Telegram user ID).
    #[serde(default)]
    pub sender_id: Option<String>,
    /// Sender display name.
    #[serde(default)]
    pub sender_name: Option<String>,
}

/// Response from sending a message.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub response: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub iterations: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

/// Request to install a skill from the marketplace.
#[derive(Debug, Deserialize)]
pub struct SkillInstallRequest {
    pub name: String,
}

/// Request to uninstall a skill.
#[derive(Debug, Deserialize)]
pub struct SkillUninstallRequest {
    pub name: String,
}

/// Request to install a skill from raw content (pushed by api-server).
#[derive(Debug, Deserialize)]
pub struct SkillInstallContentRequest {
    pub name: String,
    pub content: String,
    #[serde(default = "default_skill_type")]
    pub skill_type: String,
    #[serde(default)]
    pub source: Option<serde_json::Value>,
}

fn default_skill_type() -> String {
    "prompt_only".to_string()
}

/// Request to install a skill from a remote source (URL/git/clawhub).
#[derive(Debug, Deserialize)]
pub struct SkillInstallRemoteRequest {
    pub name: String,
    pub source_type: String, // "url", "git", "clawhub"
    pub source_ref: String,
}

/// Request to update an agent's manifest.
#[derive(Debug, Deserialize)]
pub struct AgentUpdateRequest {
    pub manifest_toml: String,
}

/// Request to change an agent's operational mode.
#[derive(Debug, Deserialize)]
pub struct SetModeRequest {
    pub mode: openfang_types::agent::AgentMode,
}

/// Request to run a migration.
#[derive(Debug, Deserialize)]
pub struct MigrateRequest {
    pub source: String,
    pub source_dir: String,
    pub target_dir: String,
    #[serde(default)]
    pub dry_run: bool,
}

/// Request to scan a directory for migration.
#[derive(Debug, Deserialize)]
pub struct MigrateScanRequest {
    pub path: String,
}

/// Request to install a skill from ClawHub.
#[derive(Debug, Deserialize)]
pub struct ClawHubInstallRequest {
    /// ClawHub skill slug (e.g., "github-helper").
    pub slug: String,
}

/// Query parameters for cross-agent context search.
#[derive(Debug, Deserialize)]
pub struct ContextSearchQuery {
    /// Search query string.
    pub query: String,
    /// Agent ID, name, or "all" for broadcast search.
    #[serde(default = "default_agent_all")]
    pub agent_id: String,
    /// Maximum results (default: 5, max: 50).
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    /// Time window in minutes (optional, max: 1440).
    pub time_window_minutes: Option<u64>,
}

fn default_agent_all() -> String {
    "all".to_string()
}

fn default_max_results() -> usize {
    5
}

/// Query parameters for agent context retrieval.
#[derive(Debug, Deserialize)]
pub struct ContextGetQuery {
    /// Maximum messages to return (default: 10, max: 100).
    #[serde(default = "default_max_messages")]
    pub max_messages: usize,
    /// Time window in minutes (optional, max: 1440).
    pub time_window_minutes: Option<u64>,
}

fn default_max_messages() -> usize {
    10
}

// ---------------------------------------------------------------------------
// Dynamic MCP server management types
// ---------------------------------------------------------------------------

/// A single MCP server configuration for the connect API.
///
/// Mirrors `McpServerConfigEntry` but uses the runtime transport representation
/// so callers (e.g. ASM) can pass complete server configs without knowledge
/// of openfang's config.toml schema.
#[derive(Debug, Clone, Deserialize)]
pub struct McpConnectServerEntry {
    /// Display name for this server (used in tool namespacing).
    pub name: String,
    /// Transport configuration.
    pub transport: McpConnectTransport,
    /// Request timeout in seconds (default: 60).
    #[serde(default = "default_mcp_connect_timeout")]
    pub timeout_secs: u64,
    /// Environment variables to pass through to subprocesses.
    #[serde(default)]
    pub env: Vec<String>,
    /// Extra HTTP headers (e.g. `"Authorization: Bearer <token>"`).
    #[serde(default)]
    pub headers: Vec<String>,
}

fn default_mcp_connect_timeout() -> u64 {
    60
}

/// Transport type for the connect API.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpConnectTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
    Sse {
        url: String,
    },
    Http {
        url: String,
    },
}

/// POST /api/mcp/connect request body.
#[derive(Debug, Deserialize)]
pub struct McpConnectRequest {
    /// MCP server configurations to connect.
    pub servers: Vec<McpConnectServerEntry>,
}

/// Result for a single server connection attempt.
#[derive(Debug, Serialize)]
pub struct McpConnectServerResult {
    pub name: String,
    pub connected: bool,
    pub tools_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST /api/mcp/connect response body.
#[derive(Debug, Serialize)]
pub struct McpConnectResponse {
    pub results: Vec<McpConnectServerResult>,
    pub total_connected: usize,
    pub total_failed: usize,
}

/// GET /api/mcp/status response — per-server connection info.
#[derive(Debug, Serialize)]
pub struct McpServerStatus {
    pub name: String,
    pub connected: bool,
    pub tools_count: usize,
    pub tools: Vec<McpToolInfo>,
}

/// Tool info within an MCP server status.
#[derive(Debug, Serialize)]
pub struct McpToolInfo {
    pub name: String,
    pub description: String,
}

/// GET /api/mcp/status response body.
#[derive(Debug, Serialize)]
pub struct McpStatusResponse {
    pub servers: Vec<McpServerStatus>,
    pub total_servers: usize,
    pub total_tools: usize,
}
