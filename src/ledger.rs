//! Continuous ledger for 24/7 recording
//!
//! Unlike RunStorage (one SQLite DB per recording session), the Ledger
//! is a single append-only database that grows forever. Agent runs are
//! detected automatically from gateway event payloads.

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::{Event, EventId, EventKind, RunId};

/// Summary of a single agent conversation run
#[derive(Debug, Clone)]
pub struct AgentRunSummary {
    pub agent_run_id: String,
    pub first_event: DateTime<Utc>,
    pub last_event: DateTime<Utc>,
    pub event_count: u64,
    pub tool_call_count: u64,
    pub kinds: HashMap<String, u64>,
}

/// A recorded tool call extracted from events
#[derive(Debug, Clone)]
pub struct ToolCallRecord {
    pub tool: String,
    pub args: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub agent_run: Option<String>,
}

/// Single continuous append-only ledger.
///
/// All events are written to one SQLite database with a hash chain.
/// Agent runs are extracted automatically from event payloads.
pub struct Ledger {
    db: Connection,
    db_path: PathBuf,
    last_hash: Option<String>,
    event_count: u64,
    batch_buffer: Vec<Event>,
    batch_size: usize,
}

impl Ledger {
    /// Open or create a ledger at the given directory.
    /// The database file will be `{path}/ledger.sqlite`.
    pub fn open(path: &Path, batch_size: usize) -> Result<Self> {
        std::fs::create_dir_all(path)?;

        let db_path = path.join("ledger.sqlite");
        let db = Connection::open(&db_path)?;

        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;

        db.execute(
            "CREATE TABLE IF NOT EXISTS events (
                event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id      TEXT NOT NULL DEFAULT 'ledger',
                ts          TEXT NOT NULL,
                kind        TEXT NOT NULL,
                agent_run   TEXT,
                span_id     TEXT,
                parent_span_id TEXT,
                actor       TEXT,
                payload     TEXT NOT NULL,
                artifact_refs TEXT,
                hash_prev   TEXT,
                hash_self   TEXT NOT NULL
            )",
            [],
        )?;

        db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)", [])?;
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind)",
            [],
        )?;
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_agent_run ON events(agent_run)",
            [],
        )?;

        db.execute(
            "CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;

        // Restore state from existing data
        let last_hash: Option<String> = db
            .query_row(
                "SELECT hash_self FROM events ORDER BY event_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let event_count: u64 = db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;

        if event_count > 0 {
            info!("Opened ledger at {:?} ({} events)", db_path, event_count);
        } else {
            info!("Created new ledger at {:?}", db_path);
        }

        Ok(Self {
            db,
            db_path,
            last_hash,
            event_count,
            batch_buffer: Vec::with_capacity(batch_size),
            batch_size,
        })
    }

    /// Open a ledger in read-only mode (for MCP server / queries).
    pub fn open_readonly(path: &Path) -> Result<Self> {
        let db_path = path.join("ledger.sqlite");
        if !db_path.exists() {
            return Err(anyhow!("Ledger not found at {:?}", db_path));
        }

        let db = Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        let last_hash: Option<String> = db
            .query_row(
                "SELECT hash_self FROM events ORDER BY event_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let event_count: u64 = db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;

        Ok(Self {
            db,
            db_path,
            last_hash,
            event_count,
            batch_buffer: Vec::new(),
            batch_size: 0, // read-only, no batching
        })
    }

    /// Extract agent_run ID from event payload.
    /// Looks for `payload.data.runId` (OpenClaw gateway format).
    fn extract_agent_run(event: &Event) -> Option<String> {
        event
            .payload
            .pointer("/data/runId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Append an event to the ledger with hash chain linking.
    /// The event_id is assigned by the ledger (sequential) to match
    /// the AUTOINCREMENT primary key in SQLite.
    pub fn append_event(&mut self, mut event: Event) -> Result<()> {
        // Assign sequential event_id matching what AUTOINCREMENT will produce
        self.event_count += 1;
        event.event_id = EventId(self.event_count);

        let prev_hash = self
            .batch_buffer
            .last()
            .map(|e| e.hash_self.clone())
            .or_else(|| self.last_hash.clone());

        event.hash_prev = prev_hash;
        event.hash_self = event.compute_hash();

        self.batch_buffer.push(event);

        if self.batch_buffer.len() >= self.batch_size {
            self.flush()?;
        }

        Ok(())
    }

    /// Flush buffered events to SQLite.
    pub fn flush(&mut self) -> Result<()> {
        if self.batch_buffer.is_empty() {
            return Ok(());
        }

        let tx = self.db.transaction()?;

        for event in &self.batch_buffer {
            let kind_str = serde_json::to_string(&event.kind)
                .unwrap_or_default()
                .trim_matches('"')
                .to_owned();

            let agent_run = Self::extract_agent_run(event);

            // Use explicit event_id (assigned in append_event) instead of AUTOINCREMENT
            tx.execute(
                "INSERT INTO events
                 (event_id, run_id, ts, kind, agent_run, span_id, parent_span_id, actor,
                  payload, artifact_refs, hash_prev, hash_self)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    event.event_id.0 as i64,
                    event.run_id.0,
                    event.ts.to_rfc3339(),
                    kind_str,
                    agent_run,
                    event.span_id,
                    event.parent_span_id,
                    event.actor,
                    serde_json::to_string(&event.payload)?,
                    serde_json::to_string(&event.artifact_refs)?,
                    event.hash_prev,
                    event.hash_self,
                ],
            )?;
            self.last_hash = Some(event.hash_self.clone());
        }

        let flushed = self.batch_buffer.len();
        tx.commit()?;
        self.batch_buffer.clear();

        debug!(
            "Flushed {} events to ledger (total: {})",
            flushed, self.event_count
        );

        Ok(())
    }

    /// Total number of events in the ledger.
    pub fn total_events(&self) -> u64 {
        self.event_count
    }

    /// Timestamp of the last event, or None if ledger is empty.
    /// Checks the in-memory batch buffer first, then falls back to the DB.
    pub fn last_event_time(&self) -> Result<Option<DateTime<Utc>>> {
        // Check unflushed buffer first
        if let Some(last) = self.batch_buffer.last() {
            return Ok(Some(last.ts));
        }

        let ts: Option<String> = self
            .db
            .query_row(
                "SELECT ts FROM events ORDER BY event_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        match ts {
            Some(s) => {
                let dt = DateTime::parse_from_rfc3339(&s)?;
                Ok(Some(dt.with_timezone(&Utc)))
            }
            None => Ok(None),
        }
    }

    /// Root hash (hash of the last event in the chain).
    pub fn root_hash(&self) -> Option<String> {
        self.last_hash.clone()
    }

    /// Size of the ledger database file in bytes.
    pub fn storage_size_bytes(&self) -> Result<u64> {
        let meta = std::fs::metadata(&self.db_path)?;
        Ok(meta.len())
    }

    /// List agent conversation runs, optionally filtered by time range.
    pub fn list_agent_runs(
        &self,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<AgentRunSummary>> {
        let mut where_clauses = vec!["agent_run IS NOT NULL".to_string()];
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = since {
            where_clauses.push("ts >= ?".to_string());
            param_values.push(Box::new(s.to_rfc3339()));
        }
        if let Some(u) = until {
            where_clauses.push("ts <= ?".to_string());
            param_values.push(Box::new(u.to_rfc3339()));
        }

        let where_sql = format!("WHERE {}", where_clauses.join(" AND "));

        let sql = format!(
            "SELECT agent_run, MIN(ts), MAX(ts), COUNT(*),
                    SUM(CASE WHEN kind = 'AGENT_EVENT'
                         AND json_extract(payload, '$.data.type') = 'tool_use' THEN 1 ELSE 0 END)
             FROM events {}
             GROUP BY agent_run
             ORDER BY MIN(ts) DESC
             LIMIT ?",
            where_sql
        );
        param_values.push(Box::new(limit as i64));

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            let agent_run_id: String = row.get(0)?;
            let first_ts: String = row.get(1)?;
            let last_ts: String = row.get(2)?;
            let event_count: u64 = row.get(3)?;
            let tool_call_count: u64 = row.get(4)?;
            Ok((
                agent_run_id,
                first_ts,
                last_ts,
                event_count,
                tool_call_count,
            ))
        })?;

        let mut runs = Vec::new();
        for row in rows {
            let (agent_run_id, first_ts, last_ts, event_count, tool_call_count) = row?;
            let first_event = DateTime::parse_from_rfc3339(&first_ts)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let last_event = DateTime::parse_from_rfc3339(&last_ts)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            // Get kind breakdown for this run
            let kinds = self.event_count_by_kind_for_run(&agent_run_id)?;

            runs.push(AgentRunSummary {
                agent_run_id,
                first_event,
                last_event,
                event_count,
                tool_call_count,
                kinds,
            });
        }

        Ok(runs)
    }

    /// Get all events for a specific agent run.
    pub fn get_agent_run_events(&self, agent_run: &str) -> Result<Vec<Event>> {
        let mut stmt = self.db.prepare(
            "SELECT event_id, run_id, ts, kind, agent_run, span_id, parent_span_id, actor,
                    payload, artifact_refs, hash_prev, hash_self
             FROM events WHERE agent_run = ? ORDER BY event_id",
        )?;

        let events = stmt
            .query_map(params![agent_run], row_to_event)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Get the most recent agent run ID.
    pub fn latest_agent_run(&self) -> Result<Option<String>> {
        self.db
            .query_row(
                "SELECT agent_run FROM events
                 WHERE agent_run IS NOT NULL
                 ORDER BY event_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Search events by text query on payload, with optional kind and time filters.
    pub fn search_events(
        &self,
        query: &str,
        kind: Option<&str>,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<Event>> {
        let mut where_clauses = vec!["payload LIKE ?".to_string()];
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        param_values.push(Box::new(format!("%{}%", query)));

        if let Some(k) = kind {
            where_clauses.push("kind = ?".to_string());
            param_values.push(Box::new(k.to_string()));
        }
        if let Some(s) = since {
            where_clauses.push("ts >= ?".to_string());
            param_values.push(Box::new(s.to_rfc3339()));
        }
        if let Some(u) = until {
            where_clauses.push("ts <= ?".to_string());
            param_values.push(Box::new(u.to_rfc3339()));
        }

        let where_sql = format!("WHERE {}", where_clauses.join(" AND "));
        let sql = format!(
            "SELECT event_id, run_id, ts, kind, agent_run, span_id, parent_span_id, actor,
                    payload, artifact_refs, hash_prev, hash_self
             FROM events {} ORDER BY event_id DESC LIMIT ?",
            where_sql
        );
        param_values.push(Box::new(limit as i64));

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self.db.prepare(&sql)?;
        let events = stmt
            .query_map(params_ref.as_slice(), row_to_event)?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Event count grouped by kind.
    pub fn event_count_by_kind(&self) -> Result<HashMap<String, u64>> {
        let mut stmt = self
            .db
            .prepare("SELECT kind, COUNT(*) FROM events GROUP BY kind ORDER BY COUNT(*) DESC")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (kind, count) = row?;
            map.insert(kind, count);
        }
        Ok(map)
    }

    /// Event count by kind for a specific agent run.
    fn event_count_by_kind_for_run(&self, agent_run: &str) -> Result<HashMap<String, u64>> {
        let mut stmt = self
            .db
            .prepare("SELECT kind, COUNT(*) FROM events WHERE agent_run = ? GROUP BY kind")?;
        let rows = stmt.query_map(params![agent_run], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (kind, count) = row?;
            map.insert(kind, count);
        }
        Ok(map)
    }

    /// Events per minute timeline, optionally filtered by since.
    pub fn events_timeline(&self, since: Option<DateTime<Utc>>) -> Result<Vec<(String, u64)>> {
        let (sql, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match since {
            Some(s) => (
                "SELECT substr(ts, 12, 5) as minute, COUNT(*)
                 FROM events WHERE ts >= ? GROUP BY minute ORDER BY minute"
                    .to_string(),
                vec![Box::new(s.to_rfc3339()) as Box<dyn rusqlite::types::ToSql>],
            ),
            None => (
                "SELECT substr(ts, 12, 5) as minute, COUNT(*)
                 FROM events GROUP BY minute ORDER BY minute"
                    .to_string(),
                vec![],
            ),
        };

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// List tool calls, optionally filtered by agent run, time, or tool name.
    pub fn tool_calls(
        &self,
        agent_run: Option<&str>,
        since: Option<DateTime<Utc>>,
        tool_name: Option<&str>,
    ) -> Result<Vec<ToolCallRecord>> {
        let mut where_clauses = vec![
            "kind = 'AGENT_EVENT'".to_string(),
            "json_extract(payload, '$.data.type') = 'tool_use'".to_string(),
        ];
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ar) = agent_run {
            where_clauses.push("agent_run = ?".to_string());
            param_values.push(Box::new(ar.to_string()));
        }
        if let Some(s) = since {
            where_clauses.push("ts >= ?".to_string());
            param_values.push(Box::new(s.to_rfc3339()));
        }
        if let Some(tn) = tool_name {
            where_clauses.push("json_extract(payload, '$.data.tool') = ?".to_string());
            param_values.push(Box::new(tn.to_string()));
        }

        let where_sql = format!("WHERE {}", where_clauses.join(" AND "));
        let sql = format!(
            "SELECT ts, agent_run,
                    json_extract(payload, '$.data.tool') as tool,
                    json_extract(payload, '$.data.args') as args
             FROM events {} ORDER BY event_id",
            where_sql
        );

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            let ts_str: String = row.get(0)?;
            let agent_run: Option<String> = row.get(1)?;
            let tool: Option<String> = row.get(2)?;
            let args_str: Option<String> = row.get(3)?;
            Ok((ts_str, agent_run, tool, args_str))
        })?;

        let mut calls = Vec::new();
        for row in rows {
            let (ts_str, agent_run, tool, args_str) = row?;
            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let args = args_str
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null);

            calls.push(ToolCallRecord {
                tool: tool.unwrap_or_else(|| "unknown".to_string()),
                args,
                timestamp,
                agent_run,
            });
        }

        Ok(calls)
    }

    /// Verify hash chain integrity.
    /// Returns (is_valid, event_count_checked).
    /// Streams events one at a time to avoid loading entire ledger into memory.
    pub fn verify_chain(&self) -> Result<(bool, u64)> {
        let mut stmt = self.db.prepare(
            "SELECT event_id, run_id, ts, kind, agent_run, span_id, parent_span_id, actor,
                    payload, artifact_refs, hash_prev, hash_self
             FROM events ORDER BY event_id",
        )?;

        let mut rows = stmt.query([])?;
        let mut count: u64 = 0;
        let mut prev_hash: Option<String> = None;

        while let Some(row) = rows.next()? {
            let event = row_to_event(row)?;
            count += 1;

            if !event.verify() {
                warn!("Ledger event {} failed hash verification", event.event_id.0);
                return Ok((false, count));
            }

            if let Some(ref expected_prev) = prev_hash
                && event.hash_prev.as_ref() != Some(expected_prev)
            {
                warn!("Ledger event {} has broken chain link", event.event_id.0);
                return Ok((false, count));
            }

            prev_hash = Some(event.hash_self);
        }

        if count > 0 {
            info!("Ledger hash chain verified for {} events", count);
        }
        Ok((true, count))
    }

    /// Set a metadata key-value pair.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Get a metadata value by key.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        self.db
            .query_row(
                "SELECT value FROM meta WHERE key = ?",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }
}

/// Parse a row from the ledger events table into an Event.
/// The ledger uses AUTOINCREMENT so event_id comes from the DB.
fn row_to_event(row: &rusqlite::Row) -> rusqlite::Result<Event> {
    let event_id: i64 = row.get(0)?;
    let run_id_str: String = row.get(1)?;
    let ts_str: String = row.get(2)?;
    let kind_str: String = row.get(3)?;
    // column 4 is agent_run (not part of Event struct)
    let span_id: Option<String> = row.get(5)?;
    let parent_span_id: Option<String> = row.get(6)?;
    let actor: Option<String> = row.get(7)?;
    let payload_str: String = row.get(8)?;
    let artifact_refs_str: String = row.get(9)?;
    let hash_prev: Option<String> = row.get(10)?;
    let hash_self: String = row.get(11)?;

    let ts = DateTime::parse_from_rfc3339(&ts_str)
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Text, Box::new(e))
        })?
        .with_timezone(&Utc);

    let kind = match kind_str.as_str() {
        "RUN_START" => EventKind::RunStart,
        "RUN_END" => EventKind::RunEnd,
        "AGENT_EVENT" => EventKind::AgentEvent,
        "TOOL_CALL" => EventKind::ToolCall,
        "TOOL_RESULT" => EventKind::ToolResult,
        "OUTPUT_CHUNK" => EventKind::OutputChunk,
        "PRESENCE" => EventKind::Presence,
        "TICK" => EventKind::Tick,
        "SHUTDOWN" => EventKind::Shutdown,
        _ => EventKind::Custom,
    };

    let payload: serde_json::Value = serde_json::from_str(&payload_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(e))
    })?;
    let artifact_refs: Vec<String> = serde_json::from_str(&artifact_refs_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(9, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(Event {
        run_id: RunId(run_id_str),
        event_id: EventId(event_id as u64),
        ts,
        kind,
        span_id,
        parent_span_id,
        actor,
        payload,
        artifact_refs,
        hash_prev,
        hash_self,
        cryptowerk: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_event(id: u64, kind: EventKind, payload: serde_json::Value) -> Event {
        Event::new(RunId("test".to_string()), EventId(id), kind, payload, None)
    }

    #[test]
    fn test_ledger_create_and_reopen() {
        let temp = TempDir::new().unwrap();
        {
            let mut ledger = Ledger::open(temp.path(), 10).unwrap();
            let event = make_event(1, EventKind::Tick, serde_json::json!({"ts": 1}));
            ledger.append_event(event).unwrap();
            ledger.flush().unwrap();
            assert_eq!(ledger.total_events(), 1);
        }
        // Reopen and verify state is preserved
        {
            let ledger = Ledger::open(temp.path(), 10).unwrap();
            assert_eq!(ledger.total_events(), 1);
            assert!(ledger.root_hash().is_some());
        }
    }

    #[test]
    fn test_ledger_hash_chain() {
        let temp = TempDir::new().unwrap();
        let mut ledger = Ledger::open(temp.path(), 100).unwrap();

        for i in 1..=10 {
            let event = make_event(i, EventKind::AgentEvent, serde_json::json!({"n": i}));
            ledger.append_event(event).unwrap();
        }
        ledger.flush().unwrap();

        let (valid, count) = ledger.verify_chain().unwrap();
        assert!(valid);
        assert_eq!(count, 10);
    }

    #[test]
    fn test_ledger_hash_chain_across_flushes() {
        let temp = TempDir::new().unwrap();
        let mut ledger = Ledger::open(temp.path(), 3).unwrap(); // flush every 3

        for i in 1..=10 {
            let event = make_event(i, EventKind::AgentEvent, serde_json::json!({"n": i}));
            ledger.append_event(event).unwrap();
        }
        ledger.flush().unwrap();

        let (valid, count) = ledger.verify_chain().unwrap();
        assert!(valid);
        assert_eq!(count, 10);
    }

    #[test]
    fn test_ledger_tamper_detection() {
        let temp = TempDir::new().unwrap();
        let mut ledger = Ledger::open(temp.path(), 100).unwrap();

        for i in 1..=5 {
            let event = make_event(i, EventKind::ToolCall, serde_json::json!({"step": i}));
            ledger.append_event(event).unwrap();
        }
        ledger.flush().unwrap();

        // Tamper with an event
        ledger
            .db
            .execute(
                "UPDATE events SET payload = '{\"step\":999}' WHERE event_id = 3",
                [],
            )
            .unwrap();

        let (valid, _) = ledger.verify_chain().unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_ledger_agent_run_extraction() {
        let temp = TempDir::new().unwrap();
        let mut ledger = Ledger::open(temp.path(), 100).unwrap();

        // Events with agent run IDs
        let event1 = make_event(
            1,
            EventKind::AgentEvent,
            serde_json::json!({
                "data": {"runId": "run-abc", "type": "tool_use", "tool": "read_file", "args": {}}
            }),
        );
        let event2 = make_event(
            2,
            EventKind::AgentEvent,
            serde_json::json!({
                "data": {"runId": "run-abc", "type": "tool_use", "tool": "write_file", "args": {}}
            }),
        );
        let event3 = make_event(
            3,
            EventKind::AgentEvent,
            serde_json::json!({
                "data": {"runId": "run-def", "type": "tool_use", "tool": "bash", "args": {}}
            }),
        );
        // Event without agent run
        let event4 = make_event(4, EventKind::Tick, serde_json::json!({"ts": 1}));

        ledger.append_event(event1).unwrap();
        ledger.append_event(event2).unwrap();
        ledger.append_event(event3).unwrap();
        ledger.append_event(event4).unwrap();
        ledger.flush().unwrap();

        let runs = ledger.list_agent_runs(None, None, 100).unwrap();
        assert_eq!(runs.len(), 2);

        // Most recent first
        let run_ids: Vec<&str> = runs.iter().map(|r| r.agent_run_id.as_str()).collect();
        assert!(run_ids.contains(&"run-abc"));
        assert!(run_ids.contains(&"run-def"));

        let abc = runs.iter().find(|r| r.agent_run_id == "run-abc").unwrap();
        assert_eq!(abc.event_count, 2);
        assert_eq!(abc.tool_call_count, 2);
    }

    #[test]
    fn test_ledger_search_events() {
        let temp = TempDir::new().unwrap();
        let mut ledger = Ledger::open(temp.path(), 100).unwrap();

        let event1 = make_event(
            1,
            EventKind::AgentEvent,
            serde_json::json!({
                "data": {"tool": "read_file", "path": "/etc/passwd"}
            }),
        );
        let event2 = make_event(
            2,
            EventKind::AgentEvent,
            serde_json::json!({
                "data": {"tool": "write_file", "path": "/tmp/output.txt"}
            }),
        );
        let event3 = make_event(3, EventKind::Tick, serde_json::json!({"ts": 1}));

        ledger.append_event(event1).unwrap();
        ledger.append_event(event2).unwrap();
        ledger.append_event(event3).unwrap();
        ledger.flush().unwrap();

        let results = ledger
            .search_events("passwd", None, None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 1);

        let results = ledger.search_events("file", None, None, None, 100).unwrap();
        assert_eq!(results.len(), 2);

        let results = ledger
            .search_events("file", Some("AGENT_EVENT"), None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 2);

        let results = ledger
            .search_events("file", Some("TICK"), None, None, 100)
            .unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_ledger_tool_calls() {
        let temp = TempDir::new().unwrap();
        let mut ledger = Ledger::open(temp.path(), 100).unwrap();

        let event1 = make_event(
            1,
            EventKind::AgentEvent,
            serde_json::json!({
                "data": {"runId": "run-1", "type": "tool_use", "tool": "read_file", "args": {"path": "/etc/hosts"}}
            }),
        );
        let event2 = make_event(
            2,
            EventKind::AgentEvent,
            serde_json::json!({
                "data": {"runId": "run-1", "type": "tool_result", "tool": "read_file"}
            }),
        );
        let event3 = make_event(
            3,
            EventKind::AgentEvent,
            serde_json::json!({
                "data": {"runId": "run-1", "type": "tool_use", "tool": "bash", "args": {"command": "ls"}}
            }),
        );

        ledger.append_event(event1).unwrap();
        ledger.append_event(event2).unwrap();
        ledger.append_event(event3).unwrap();
        ledger.flush().unwrap();

        // All tool calls
        let calls = ledger.tool_calls(None, None, None).unwrap();
        assert_eq!(calls.len(), 2); // tool_result excluded

        // Filter by tool name
        let calls = ledger.tool_calls(None, None, Some("bash")).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].tool, "bash");
    }

    #[test]
    fn test_ledger_event_count_by_kind() {
        let temp = TempDir::new().unwrap();
        let mut ledger = Ledger::open(temp.path(), 100).unwrap();

        ledger
            .append_event(make_event(1, EventKind::Tick, serde_json::json!({})))
            .unwrap();
        ledger
            .append_event(make_event(2, EventKind::Tick, serde_json::json!({})))
            .unwrap();
        ledger
            .append_event(make_event(3, EventKind::AgentEvent, serde_json::json!({})))
            .unwrap();
        ledger.flush().unwrap();

        let counts = ledger.event_count_by_kind().unwrap();
        assert_eq!(counts.get("TICK"), Some(&2));
        assert_eq!(counts.get("AGENT_EVENT"), Some(&1));
    }

    #[test]
    fn test_ledger_meta() {
        let temp = TempDir::new().unwrap();
        let ledger = Ledger::open(temp.path(), 100).unwrap();

        ledger
            .set_meta("started_at", "2026-01-31T12:00:00Z")
            .unwrap();
        let val = ledger.get_meta("started_at").unwrap();
        assert_eq!(val, Some("2026-01-31T12:00:00Z".to_string()));

        let none = ledger.get_meta("nonexistent").unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn test_ledger_readonly() {
        let temp = TempDir::new().unwrap();
        {
            let mut ledger = Ledger::open(temp.path(), 100).unwrap();
            ledger
                .append_event(make_event(1, EventKind::Tick, serde_json::json!({})))
                .unwrap();
            ledger.flush().unwrap();
        }
        {
            let ledger = Ledger::open_readonly(temp.path()).unwrap();
            assert_eq!(ledger.total_events(), 1);
            let (valid, _) = ledger.verify_chain().unwrap();
            assert!(valid);
        }
    }
}
