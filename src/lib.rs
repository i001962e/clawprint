//! Clawprint - Flight recorder for OpenClaw agent runs
//!
//! A tamper-evident audit and replay system for agent actions.
//! Tagline: "Show the Clawprint" / "Receipts for agent actions"

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod daemon;
pub mod gateway;
pub mod ledger;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod proof;
pub mod record;
pub mod redact;
pub mod replay;
pub mod security;
pub mod storage;
pub mod viewer;

/// Unique identifier for a recorded run
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RunId(pub String);

impl RunId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for an event within a run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub u64);

/// Core event types for the ledger
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    /// Run started
    RunStart,
    /// Run ended
    RunEnd,
    /// Raw agent event from gateway stream
    AgentEvent,
    /// Tool was called
    ToolCall,
    /// Tool returned result
    ToolResult,
    /// Chunk of streamed output
    OutputChunk,
    /// Presence heartbeat
    Presence,
    /// Tick/event loop tick
    Tick,
    /// Gateway shutdown
    Shutdown,
    /// Custom/unknown
    Custom,
}

/// Core event structure - stored in ledger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Which run this event belongs to
    pub run_id: RunId,
    /// Sequential event ID within run
    pub event_id: EventId,
    /// Timestamp when event was recorded
    pub ts: DateTime<Utc>,
    /// Event type classification
    pub kind: EventKind,
    /// Span/trace ID for grouping related operations
    pub span_id: Option<String>,
    /// Parent span ID for nested operations
    pub parent_span_id: Option<String>,
    /// Actor identity (agent/client) if available
    pub actor: Option<String>,
    /// Structured payload - event-specific data
    pub payload: serde_json::Value,
    /// References to external artifacts (hashes)
    pub artifact_refs: Vec<String>,
    /// Hash of previous event in chain (empty for first)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_prev: Option<String>,
    /// Hash of this event (computed from canonical form)
    pub hash_self: String,
    /// Optional external proof metadata for this event hash
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cryptowerk: Option<CryptowerkProof>,
}

impl Event {
    /// Create a new event with computed hash
    pub fn new(
        run_id: RunId,
        event_id: EventId,
        kind: EventKind,
        payload: serde_json::Value,
        prev_hash: Option<String>,
    ) -> Self {
        let ts = Utc::now();
        let mut event = Self {
            run_id,
            event_id,
            ts,
            kind,
            span_id: None,
            parent_span_id: None,
            actor: None,
            payload,
            artifact_refs: Vec::new(),
            hash_prev: prev_hash,
            hash_self: String::new(), // computed below
            cryptowerk: None,
        };
        event.hash_self = event.compute_hash();
        event
    }

    /// Compute SHA256 hash of canonical event representation.
    ///
    /// Panics if the canonical form cannot be serialized to JSON,
    /// since silent fallback would produce identical hashes for
    /// different events and break chain integrity.
    pub fn compute_hash(&self) -> String {
        // Create canonical representation without hash fields
        let canonical = CanonicalEvent {
            run_id: self.run_id.clone(),
            event_id: self.event_id,
            ts: self.ts,
            kind: self.kind,
            span_id: self.span_id.clone(),
            parent_span_id: self.parent_span_id.clone(),
            actor: self.actor.clone(),
            payload: self.payload.clone(),
            artifact_refs: self.artifact_refs.clone(),
            hash_prev: self.hash_prev.clone(),
        };

        // Serialize to canonical JSON - must not silently default
        let json =
            serde_json::to_string(&canonical).expect("canonical event must be JSON-serializable");

        // Compute hash
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify event hash integrity
    pub fn verify(&self) -> bool {
        self.hash_self == self.compute_hash()
    }
}

/// Canonical event form for hashing (excludes hash_self)
#[derive(Debug, Clone, Serialize)]
struct CanonicalEvent {
    run_id: RunId,
    event_id: EventId,
    ts: DateTime<Utc>,
    kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    payload: serde_json::Value,
    artifact_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_prev: Option<String>,
}

/// Run metadata stored in meta.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    pub run_id: RunId,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub event_count: u64,
    pub root_hash: String,
    pub gateway_url: String,
    pub version: String,
    #[serde(default)]
    pub cryptowerk: Option<CryptowerkProof>,
}

impl RunMeta {
    pub fn new(run_id: RunId, gateway_url: String) -> Self {
        Self {
            run_id,
            started_at: Utc::now(),
            ended_at: None,
            event_count: 0,
            root_hash: String::new(),
            gateway_url,
            version: env!("CARGO_PKG_VERSION").to_string(),
            cryptowerk: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CryptowerkProof {
    pub retrieval_id: Option<String>,
    pub proof_url: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub error_text: Option<String>,
}

/// Configuration for Clawprint
#[derive(Debug, Clone)]
pub struct Config {
    /// Output directory for runs
    pub output_dir: std::path::PathBuf,
    /// Whether to redact secrets
    pub redact_secrets: bool,
    /// Gateway WebSocket URL
    pub gateway_url: String,
    /// Gateway auth token
    pub auth_token: Option<String>,
    /// Batch size for SQLite commits
    pub batch_size: usize,
    /// Flush interval in milliseconds
    pub flush_interval_ms: u64,
    /// Optional post-seal external anchoring configuration
    pub cryptowerk: Option<proof::CryptowerkConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output_dir: std::path::PathBuf::from("./clawprints"),
            redact_secrets: true,
            gateway_url: "ws://127.0.0.1:18789".to_string(),
            auth_token: None,
            batch_size: 100,
            flush_interval_ms: 200,
            cryptowerk: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_hash_chain() {
        let run_id = RunId::new();

        let event1 = Event::new(
            run_id.clone(),
            EventId(1),
            EventKind::RunStart,
            serde_json::json!({"message": "start"}),
            None,
        );
        assert!(event1.verify());
        assert!(event1.hash_prev.is_none());

        let event2 = Event::new(
            run_id.clone(),
            EventId(2),
            EventKind::ToolCall,
            serde_json::json!({"tool": "test"}),
            Some(event1.hash_self.clone()),
        );
        assert!(event2.verify());
        assert_eq!(event2.hash_prev, Some(event1.hash_self));
    }

    /// Hash must be deterministic: same inputs -> same hash
    #[test]
    fn test_hash_determinism() {
        let run_id = RunId("fixed-id".to_string());
        let event = Event::new(
            run_id.clone(),
            EventId(1),
            EventKind::RunStart,
            serde_json::json!({"key": "value"}),
            None,
        );

        let hash1 = event.compute_hash();
        let hash2 = event.compute_hash();
        assert_eq!(hash1, hash2);
    }

    /// Different payloads must produce different hashes
    #[test]
    fn test_different_payloads_different_hashes() {
        let run_id = RunId("fixed-id".to_string());
        let ts = chrono::Utc::now();

        let mut e1 = Event {
            run_id: run_id.clone(),
            event_id: EventId(1),
            ts,
            kind: EventKind::ToolCall,
            span_id: None,
            parent_span_id: None,
            actor: None,
            payload: serde_json::json!({"data": "aaa"}),
            artifact_refs: vec![],
            hash_prev: None,
            hash_self: String::new(),
            cryptowerk: None,
        };
        e1.hash_self = e1.compute_hash();

        let mut e2 = Event {
            run_id: run_id.clone(),
            event_id: EventId(1),
            ts,
            kind: EventKind::ToolCall,
            span_id: None,
            parent_span_id: None,
            actor: None,
            payload: serde_json::json!({"data": "bbb"}),
            artifact_refs: vec![],
            hash_prev: None,
            hash_self: String::new(),
            cryptowerk: None,
        };
        e2.hash_self = e2.compute_hash();

        assert_ne!(e1.hash_self, e2.hash_self);
    }

    /// Verify detects modification
    #[test]
    fn test_verify_detects_tamper() {
        let run_id = RunId::new();
        let mut event = Event::new(
            run_id,
            EventId(1),
            EventKind::RunStart,
            serde_json::json!({"ok": true}),
            None,
        );
        assert!(event.verify());

        // Tamper with payload
        event.payload = serde_json::json!({"ok": false});
        assert!(!event.verify(), "Tampered event should fail verification");
    }

    /// Hash output is always 64 hex characters (SHA-256)
    #[test]
    fn test_hash_format() {
        let event = Event::new(
            RunId::new(),
            EventId(1),
            EventKind::RunStart,
            serde_json::json!(null),
            None,
        );
        assert_eq!(event.hash_self.len(), 64);
        assert!(event.hash_self.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// EventKind serde round-trip
    #[test]
    fn test_event_kind_serde() {
        let kinds = vec![
            (EventKind::RunStart, "\"RUN_START\""),
            (EventKind::RunEnd, "\"RUN_END\""),
            (EventKind::ToolCall, "\"TOOL_CALL\""),
            (EventKind::ToolResult, "\"TOOL_RESULT\""),
            (EventKind::OutputChunk, "\"OUTPUT_CHUNK\""),
            (EventKind::Presence, "\"PRESENCE\""),
            (EventKind::Tick, "\"TICK\""),
            (EventKind::Shutdown, "\"SHUTDOWN\""),
            (EventKind::Custom, "\"CUSTOM\""),
        ];

        for (kind, expected_json) in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, expected_json, "Serialization of {:?}", kind);

            let deserialized: EventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, kind, "Deserialization of {}", json);
        }
    }
}
