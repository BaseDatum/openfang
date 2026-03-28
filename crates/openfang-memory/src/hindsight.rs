//! Hindsight semantic memory backend.
//!
//! Routes semantic memory operations (remember, recall, forget) and
//! knowledge-graph operations (add_entity, add_relation, query_graph)
//! to a remote Hindsight server via its HTTP API.
//!
//! Each openfang user gets a dedicated Hindsight memory bank (one bank
//! per tenant schema). The bank ID defaults to `"default"` — tenant
//! isolation is handled server-side by Hindsight's `DialogueTenantExtension`,
//! which maps the `Authorization: Bearer {user_id}` header to a
//! PostgreSQL schema.
//!
//! Knowledge graph operations (add_entity, add_relation, query_graph)
//! are mapped to rich natural-language facts stored via retain.
//! Hindsight's LLM pipeline automatically extracts entities and builds
//! a knowledge graph during retain, so we write descriptive facts that
//! carry enough context for semantic recall and entity extraction.
//!
//! Structured operations (KV, sessions, tasks) remain on the local
//! SQLite database — this module only handles semantic/graph ops.

use std::collections::HashMap;

use chrono::Utc;
use tracing::{debug, warn};
use uuid::Uuid;

use hindsight_client::types;
use hindsight_client::Client;

use openfang_types::agent::AgentId;
use openfang_types::error::{OpenFangError, OpenFangResult};
use openfang_types::memory::{
    ConsolidationReport, Entity, EntityType, GraphMatch, GraphPattern, MemoryFilter, MemoryFragment,
    MemoryId, MemorySource, Relation, RelationType,
};

/// Default bank ID within a tenant schema.
/// Each tenant schema is already user-isolated, so a single bank suffices.
const DEFAULT_BANK_ID: &str = "default";

/// Hindsight semantic memory backend.
///
/// Created once at kernel startup when `memory.backend = "hindsight"`.
/// Thread-safe (`Client` uses `reqwest::Client` which is `Clone + Send + Sync`).
pub struct HindsightBackend {
    client: Client,
    bank_id: String,
}

impl HindsightBackend {
    /// Create a new Hindsight backend.
    ///
    /// - `base_url`: Hindsight server URL (e.g., `http://hindsight:8888`).
    /// - `auth_token`: Bearer token (the user_id) sent on every request.
    pub fn new(base_url: &str, auth_token: &str) -> Self {
        // Build a reqwest client with the auth header baked in.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .default_headers({
                let mut h = reqwest::header::HeaderMap::new();
                h.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {auth_token}"))
                        .expect("Invalid auth token for header"),
                );
                h
            })
            .build()
            .expect("Failed to build reqwest client for Hindsight");

        let client = Client::new_with_client(base_url, http);

        Self {
            client,
            bank_id: DEFAULT_BANK_ID.to_string(),
        }
    }

    // -----------------------------------------------------------------
    // Semantic operations (Memory trait methods)
    // -----------------------------------------------------------------

    /// Store a memory in Hindsight via the retain API.
    pub async fn remember(
        &self,
        agent_id: AgentId,
        content: &str,
        source: MemorySource,
        scope: &str,
        metadata: HashMap<String, serde_json::Value>,
    ) -> OpenFangResult<MemoryId> {
        let tags = vec![
            format!("agent:{}", agent_id.0),
            format!("scope:{scope}"),
            format!("source:{source:?}"),
        ];

        let mut meta_map = HashMap::new();
        for (k, v) in &metadata {
            meta_map.insert(k.clone(), v.to_string());
        }
        meta_map.insert("agent_id".to_string(), agent_id.0.to_string());
        meta_map.insert("source".to_string(), format!("{source:?}"));
        meta_map.insert("scope".to_string(), scope.to_string());

        let item = types::MemoryItem {
            content: content.to_string(),
            context: Some(format!("Agent {}, scope: {scope}", agent_id.0)),
            tags: Some(tags),
            metadata: Some(meta_map),
            timestamp: None,
            document_id: None,
            entities: None,
            observation_scopes: None,
            strategy: None,
        };

        let request = types::RetainRequest {
            items: vec![item],
            async_: true,
            document_tags: None,
        };

        self.client
            .retain_memories(&self.bank_id, None, &request)
            .await
            .map_err(|e| OpenFangError::Memory(format!("Hindsight retain failed: {e}")))?;

        // Hindsight doesn't return per-item IDs from retain, so we generate
        // a synthetic MemoryId. The real ID lives in Hindsight's database.
        let id = MemoryId(Uuid::new_v4());
        debug!(memory_id = %id, "Retained memory in Hindsight (async)");
        Ok(id)
    }

    /// Recall memories from Hindsight.
    pub async fn recall(
        &self,
        query: &str,
        limit: usize,
        filter: Option<MemoryFilter>,
    ) -> OpenFangResult<Vec<MemoryFragment>> {
        let mut tags = Vec::new();
        let mut tags_match = types::TagsMatch::Any;

        if let Some(ref f) = filter {
            if let Some(agent_id) = f.agent_id {
                tags.push(format!("agent:{}", agent_id.0));
                tags_match = types::TagsMatch::AnyStrict;
            }
            if let Some(ref scope) = f.scope {
                tags.push(format!("scope:{scope}"));
                tags_match = types::TagsMatch::AnyStrict;
            }
        }

        // Convert count-based limit to an approximate max_tokens.
        // ~50 words per memory × ~4 chars/word × ~1.3 tokens/char ≈ 260 tokens/memory.
        let max_tokens = (limit as i64) * 260;

        let request = types::RecallRequest {
            query: query.to_string(),
            max_tokens: max_tokens.max(1024),
            trace: false,
            budget: None,
            include: None,
            query_timestamp: None,
            types: None,
            tags: if tags.is_empty() { None } else { Some(tags) },
            tags_match,
            tag_groups: None,
        };

        let response = self
            .client
            .recall_memories(&self.bank_id, None, &request)
            .await
            .map_err(|e| OpenFangError::Memory(format!("Hindsight recall failed: {e}")))?;

        let result = response.into_inner();
        let mut fragments = Vec::new();

        for r in &result.results {
            let meta_ref = r.metadata.as_ref();

            let agent_id = meta_ref
                .and_then(|m| m.get("agent_id"))
                .and_then(|s| Uuid::parse_str(s).ok())
                .map(AgentId)
                .unwrap_or_else(|| AgentId(Uuid::nil()));

            let source = meta_ref
                .and_then(|m| m.get("source"))
                .map(|s| match s.as_str() {
                    "Conversation" => MemorySource::Conversation,
                    "Document" => MemorySource::Document,
                    "Observation" => MemorySource::Observation,
                    "Inference" => MemorySource::Inference,
                    "UserProvided" => MemorySource::UserProvided,
                    "System" => MemorySource::System,
                    _ => MemorySource::Observation,
                })
                .unwrap_or(MemorySource::Observation);

            let scope = meta_ref
                .and_then(|m| m.get("scope"))
                .map(|s| s.to_string())
                .unwrap_or_else(|| "episodic".to_string());

            // Convert HashMap<String, String> → HashMap<String, serde_json::Value>
            let meta: HashMap<String, serde_json::Value> = meta_ref
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                        .collect()
                })
                .unwrap_or_default();

            fragments.push(MemoryFragment {
                id: MemoryId(Uuid::new_v4()), // Synthetic — Hindsight manages real IDs
                agent_id,
                content: r.text.clone(),
                embedding: None,
                metadata: meta,
                source,
                confidence: 0.8, // Hindsight doesn't expose per-result scores in the typed client
                created_at: Utc::now(),
                accessed_at: Utc::now(),
                access_count: 0,
                scope,
            });
        }

        debug!(count = fragments.len(), "Recalled memories from Hindsight");
        Ok(fragments)
    }

    /// Forget a specific memory.
    ///
    /// Hindsight doesn't expose a direct delete-by-openfang-ID since we use
    /// synthetic IDs. For now this is a no-op with a warning. Full delete
    /// support would require storing the Hindsight memory_unit_id mapping.
    pub async fn forget(&self, id: MemoryId) -> OpenFangResult<()> {
        warn!(
            memory_id = %id,
            "Hindsight backend: forget() is a no-op — Hindsight manages memory lifecycle internally"
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // Explicit tool operations (memory_retain, memory_reflect)
    // -----------------------------------------------------------------

    /// Explicitly retain a fact via the `memory_retain` tool.
    ///
    /// Unlike `remember()` (called automatically after each conversation turn),
    /// this is invoked when the LLM explicitly decides something is worth storing.
    /// Uses async retain — Hindsight workers handle fact extraction in background.
    pub async fn retain_explicit(
        &self,
        agent_id: AgentId,
        content: &str,
        context: &str,
        tags: Option<Vec<String>>,
        metadata: Option<HashMap<String, String>>,
        timestamp: Option<&str>,
    ) -> OpenFangResult<String> {
        let mut all_tags = vec![format!("agent:{}", agent_id.0)];
        if let Some(user_tags) = tags {
            all_tags.extend(user_tags);
        }

        let mut meta_map = metadata.unwrap_or_default();
        meta_map.insert("agent_id".to_string(), agent_id.0.to_string());
        meta_map.insert("source".to_string(), "explicit_retain".to_string());

        let ts = timestamp.map(|t| types::MemoryItemTimestamp {
            subtype_0: None,
            subtype_1: Some(t.to_string()),
        });

        let item = types::MemoryItem {
            content: content.to_string(),
            context: Some(context.to_string()),
            tags: Some(all_tags),
            metadata: Some(meta_map),
            timestamp: ts,
            document_id: None,
            entities: None,
            observation_scopes: None,
            strategy: None,
        };

        let request = types::RetainRequest {
            items: vec![item],
            async_: true,
            document_tags: None,
        };

        let response = self
            .client
            .retain_memories(&self.bank_id, None, &request)
            .await
            .map_err(|e| OpenFangError::Memory(format!("Hindsight retain_explicit failed: {e}")))?;

        let result = response.into_inner();
        let op_id = result
            .operation_id
            .unwrap_or_else(|| "accepted".to_string());
        debug!(operation_id = %op_id, "Explicit retain submitted to Hindsight");
        Ok(format!("Memory accepted for processing (operation: {op_id})"))
    }

    /// Reflect — synthesized reasoning across stored memories.
    ///
    /// Calls Hindsight's reflect endpoint which runs an agentic LLM workflow:
    /// retrieves relevant memories, mental models, and observations, then
    /// synthesizes a reasoned answer. Much more powerful than raw recall.
    pub async fn reflect(
        &self,
        agent_id: AgentId,
        query: &str,
        budget: Option<&str>,
    ) -> OpenFangResult<String> {
        let budget_enum = match budget.unwrap_or("low") {
            "mid" => types::Budget::Mid,
            "high" => types::Budget::High,
            _ => types::Budget::Low,
        };

        let request = types::ReflectRequest {
            query: query.to_string(),
            budget: Some(budget_enum),
            context: None,
            max_tokens: 4096,
            tags: Some(vec![format!("agent:{}", agent_id.0)]),
            tags_match: types::TagsMatch::AnyStrict,
            tag_groups: None,
            include: None,
            response_schema: None,
            exclude_mental_models: false,
            exclude_mental_model_ids: None,
            fact_types: None,
        };

        let response = self
            .client
            .reflect(&self.bank_id, None, &request)
            .await
            .map_err(|e| OpenFangError::Memory(format!("Hindsight reflect failed: {e}")))?;

        let result = response.into_inner();
        debug!(text_len = result.text.len(), "Reflect completed from Hindsight");
        Ok(result.text)
    }

    // -----------------------------------------------------------------
    // Knowledge graph operations
    //
    // Hindsight automatically extracts entities and builds a knowledge
    // graph during retain. We store rich natural-language facts that
    // carry enough context for Hindsight's entity resolver, and use
    // recall to query them back.
    // -----------------------------------------------------------------

    /// Add an entity by retaining a rich descriptive fact.
    ///
    /// The fact is written in natural language so Hindsight's LLM
    /// pipeline can extract the entity and its properties during retain.
    pub async fn add_entity(&self, entity: Entity) -> OpenFangResult<String> {
        let entity_type = format_entity_type(&entity.entity_type);

        // Build a rich description including all properties.
        let mut parts = vec![format!(
            "{} is a {entity_type}",
            entity.name,
        )];

        for (key, value) in &entity.properties {
            let val_str = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
                    .join(", "),
                other => other.to_string(),
            };
            if !val_str.is_empty() {
                // Convert snake_case keys to readable form
                let readable_key = key.replace('_', " ");
                parts.push(format!("{readable_key}: {val_str}"));
            }
        }

        let content = parts.join(". ") + ".";

        let mut meta_map = HashMap::new();
        meta_map.insert("kg_type".to_string(), "entity".to_string());
        meta_map.insert("entity_id".to_string(), entity.id.clone());
        meta_map.insert("entity_name".to_string(), entity.name.clone());
        meta_map.insert("entity_type".to_string(), entity_type);

        let item = types::MemoryItem {
            content,
            context: Some(format!("Knowledge graph entity: {}", entity.name)),
            tags: Some(vec![
                "knowledge_graph".to_string(),
                "entity".to_string(),
                format!("entity_name:{}", entity.name),
                format!("entity_type:{}", format_entity_type(&entity.entity_type)),
            ]),
            metadata: Some(meta_map),
            timestamp: None,
            document_id: None,
            entities: None,
            observation_scopes: None,
            strategy: None,
        };

        let request = types::RetainRequest {
            items: vec![item],
            async_: false,
            document_tags: None,
        };

        self.client
            .retain_memories(&self.bank_id, None, &request)
            .await
            .map_err(|e| OpenFangError::Memory(format!("Hindsight add_entity failed: {e}")))?;

        debug!(entity_id = %entity.id, name = %entity.name, "Retained entity in Hindsight");
        Ok(entity.id)
    }

    /// Add a relation by retaining a descriptive fact.
    ///
    /// Stored as a natural language statement so Hindsight can extract
    /// both entities and the relationship between them.
    pub async fn add_relation(&self, relation: Relation) -> OpenFangResult<String> {
        let relation_type = format_relation_type(&relation.relation);

        let content = format!(
            "{} {} {}",
            relation.source, relation_type, relation.target
        );

        let mut meta_map = HashMap::new();
        meta_map.insert("kg_type".to_string(), "relation".to_string());
        meta_map.insert("source_entity".to_string(), relation.source.clone());
        meta_map.insert("target_entity".to_string(), relation.target.clone());
        meta_map.insert("relation_type".to_string(), relation_type.clone());

        let item = types::MemoryItem {
            content,
            context: Some(format!(
                "Knowledge graph relation: {} {} {}",
                relation.source, relation_type, relation.target
            )),
            tags: Some(vec![
                "knowledge_graph".to_string(),
                "relation".to_string(),
                format!("entity_name:{}", relation.source),
                format!("entity_name:{}", relation.target),
                format!("relation_type:{relation_type}"),
            ]),
            metadata: Some(meta_map),
            timestamp: None,
            document_id: None,
            entities: None,
            observation_scopes: None,
            strategy: None,
        };

        let request = types::RetainRequest {
            items: vec![item],
            async_: false,
            document_tags: None,
        };

        self.client
            .retain_memories(&self.bank_id, None, &request)
            .await
            .map_err(|e| OpenFangError::Memory(format!("Hindsight add_relation failed: {e}")))?;

        let id = Uuid::new_v4().to_string();
        debug!(relation_id = %id, "Retained relation in Hindsight");
        Ok(id)
    }

    /// Query the knowledge graph via Hindsight recall.
    ///
    /// Searches for knowledge graph entries (entities and relations)
    /// matching the pattern. Returns results as `GraphMatch` structs
    /// synthesized from the recalled text.
    pub async fn query_graph(&self, pattern: GraphPattern) -> OpenFangResult<Vec<GraphMatch>> {
        // Build a natural language query from the pattern.
        let query = match (&pattern.source, &pattern.target) {
            (Some(src), Some(tgt)) => format!("{src} and {tgt}"),
            (Some(src), None) => src.clone(),
            (None, Some(tgt)) => tgt.clone(),
            (None, None) => return Ok(Vec::new()),
        };

        let request = types::RecallRequest {
            query,
            max_tokens: 4096,
            trace: false,
            budget: None,
            include: None,
            query_timestamp: None,
            types: None,
            tags: Some(vec!["knowledge_graph".to_string()]),
            tags_match: types::TagsMatch::AnyStrict,
            tag_groups: None,
        };

        let response = self
            .client
            .recall_memories(&self.bank_id, None, &request)
            .await
            .map_err(|e| OpenFangError::Memory(format!("Hindsight query_graph failed: {e}")))?;

        let result = response.into_inner();
        let mut matches = Vec::new();

        for r in &result.results {
            let meta = r.metadata.as_ref();

            let kg_type = meta
                .and_then(|m| m.get("kg_type"))
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            match kg_type {
                "relation" => {
                    let source_name = meta
                        .and_then(|m| m.get("source_entity"))
                        .cloned()
                        .unwrap_or_default();
                    let target_name = meta
                        .and_then(|m| m.get("target_entity"))
                        .cloned()
                        .unwrap_or_default();
                    let rel_type = meta
                        .and_then(|m| m.get("relation_type"))
                        .cloned()
                        .unwrap_or_default();

                    if source_name.is_empty() || target_name.is_empty() {
                        continue;
                    }

                    matches.push(GraphMatch {
                        source: Entity {
                            id: source_name.clone(),
                            entity_type: EntityType::Custom("unknown".to_string()),
                            name: source_name,
                            properties: HashMap::new(),
                            created_at: Utc::now(),
                            updated_at: Utc::now(),
                        },
                        relation: Relation {
                            source: meta
                                .and_then(|m| m.get("source_entity"))
                                .cloned()
                                .unwrap_or_default(),
                            relation: RelationType::Custom(rel_type),
                            target: meta
                                .and_then(|m| m.get("target_entity"))
                                .cloned()
                                .unwrap_or_default(),
                            properties: HashMap::new(),
                            confidence: 0.8,
                            created_at: Utc::now(),
                        },
                        target: Entity {
                            id: target_name.clone(),
                            entity_type: EntityType::Custom("unknown".to_string()),
                            name: target_name,
                            properties: HashMap::new(),
                            created_at: Utc::now(),
                            updated_at: Utc::now(),
                        },
                    });
                }
                "entity" => {
                    // For entity results, synthesize a self-referential match
                    // so the agent can see the entity and its properties.
                    let name = meta
                        .and_then(|m| m.get("entity_name"))
                        .cloned()
                        .unwrap_or_default();
                    let etype = meta
                        .and_then(|m| m.get("entity_type"))
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());

                    if name.is_empty() {
                        continue;
                    }

                    let entity = Entity {
                        id: name.clone(),
                        entity_type: parse_entity_type(&etype),
                        name: name.clone(),
                        properties: HashMap::new(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    };

                    matches.push(GraphMatch {
                        source: entity.clone(),
                        relation: Relation {
                            source: name.clone(),
                            relation: RelationType::Custom("is_a".to_string()),
                            target: etype,
                            properties: HashMap::new(),
                            confidence: 1.0,
                            created_at: Utc::now(),
                        },
                        target: entity,
                    });
                }
                _ => {
                    // Unknown kg_type — skip.
                    debug!(kg_type, "Skipping unknown knowledge graph result type");
                }
            }
        }

        debug!(count = matches.len(), "query_graph returned results from Hindsight");
        Ok(matches)
    }

    /// Consolidation is handled automatically by Hindsight workers.
    pub async fn consolidate(&self) -> OpenFangResult<ConsolidationReport> {
        debug!("Hindsight backend: consolidate() is a no-op — handled by Hindsight workers");
        Ok(ConsolidationReport {
            memories_merged: 0,
            memories_decayed: 0,
            duration_ms: 0,
        })
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_entity_type(et: &EntityType) -> String {
    match et {
        EntityType::Person => "person".to_string(),
        EntityType::Organization => "organization".to_string(),
        EntityType::Project => "project".to_string(),
        EntityType::Concept => "concept".to_string(),
        EntityType::Event => "event".to_string(),
        EntityType::Location => "location".to_string(),
        EntityType::Document => "document".to_string(),
        EntityType::Tool => "tool".to_string(),
        EntityType::Custom(s) => s.clone(),
    }
}

fn format_relation_type(rt: &RelationType) -> String {
    match rt {
        RelationType::WorksAt => "works at".to_string(),
        RelationType::KnowsAbout => "knows about".to_string(),
        RelationType::RelatedTo => "is related to".to_string(),
        RelationType::DependsOn => "depends on".to_string(),
        RelationType::OwnedBy => "is owned by".to_string(),
        RelationType::CreatedBy => "was created by".to_string(),
        RelationType::LocatedIn => "is located in".to_string(),
        RelationType::PartOf => "is part of".to_string(),
        RelationType::Uses => "uses".to_string(),
        RelationType::Produces => "produces".to_string(),
        RelationType::Custom(s) => s.clone(),
    }
}

fn parse_entity_type(s: &str) -> EntityType {
    match s.to_lowercase().as_str() {
        "person" => EntityType::Person,
        "organization" => EntityType::Organization,
        "project" => EntityType::Project,
        "concept" => EntityType::Concept,
        "event" => EntityType::Event,
        "location" => EntityType::Location,
        "document" => EntityType::Document,
        "tool" => EntityType::Tool,
        other => EntityType::Custom(other.to_string()),
    }
}
