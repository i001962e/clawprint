//! Storage layer for Clawprint
//!
//! Uses SQLite for events + filesystem for compressed artifacts.
//! Implements hash chain verification.

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::{CryptowerkProof, Event, EventId, EventKind, RunId, RunMeta};

/// Storage manager for a single run
pub struct RunStorage {
    run_id: RunId,
    base_path: PathBuf,
    db: Connection,
    last_hash: Option<String>,
    event_count: u64,
    batch_buffer: Vec<Event>,
    batch_size: usize,
}

impl RunStorage {
    /// Create new storage for a run
    pub fn new(run_id: RunId, base_path: &Path, batch_size: usize) -> Result<Self> {
        let run_path = base_path.join("runs").join(&run_id.0);
        fs::create_dir_all(&run_path)?;
        fs::create_dir_all(run_path.join("artifacts"))?;

        let db_path = run_path.join("ledger.sqlite");
        let db = Connection::open(&db_path)?;

        // Enable WAL mode for better concurrent performance
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;

        // Create tables
        db.execute(
            "CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                kind TEXT NOT NULL,
                span_id TEXT,
                parent_span_id TEXT,
                actor TEXT,
                payload TEXT NOT NULL,
                artifact_refs TEXT,
                hash_prev TEXT,
                hash_self TEXT NOT NULL
            )",
            [],
        )?;

        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind)",
            [],
        )?;
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)", [])?;
        ensure_event_cryptowerk_column(&db)?;

        info!("Created storage for run {} at {:?}", run_id.0, run_path);

        Ok(Self {
            run_id,
            base_path: run_path,
            db,
            last_hash: None,
            event_count: 0,
            batch_buffer: Vec::with_capacity(batch_size),
            batch_size,
        })
    }

    /// Open existing run storage
    pub fn open(run_id: RunId, base_path: &Path) -> Result<Self> {
        let run_path = base_path.join("runs").join(&run_id.0);
        let db_path = run_path.join("ledger.sqlite");

        if !db_path.exists() {
            return Err(anyhow!("Run {} not found at {:?}", run_id.0, run_path));
        }

        let db = Connection::open(&db_path)?;
        ensure_event_cryptowerk_column(&db)?;

        // Get last hash for chain continuation
        let last_hash: Option<String> = db
            .query_row(
                "SELECT hash_self FROM events ORDER BY event_id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        let event_count: u64 = db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;

        info!(
            "Opened storage for run {} ({} events)",
            run_id.0, event_count
        );

        Ok(Self {
            run_id,
            base_path: run_path,
            db,
            last_hash,
            event_count,
            batch_buffer: Vec::with_capacity(100),
            batch_size: 100,
        })
    }

    /// Write event to storage, chaining it to the previous event's hash
    pub fn write_event(&mut self, event: Event) -> Result<()> {
        let _ = self.write_event_and_return(event)?;
        Ok(())
    }

    /// Write an event and return the finalized chained form with hash_prev/hash_self set.
    pub fn write_event_and_return(&mut self, mut event: Event) -> Result<Event> {
        // Determine the previous hash: from the last buffered event, or from storage
        let prev_hash = self
            .batch_buffer
            .last()
            .map(|e| e.hash_self.clone())
            .or_else(|| self.last_hash.clone());

        // Set the chain link and recompute hash
        event.hash_prev = prev_hash;
        event.hash_self = event.compute_hash();

        self.batch_buffer.push(event.clone());

        if self.batch_buffer.len() >= self.batch_size {
            self.flush()?;
        }

        Ok(event)
    }

    /// Flush batch to database
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
            tx.execute(
                "INSERT INTO events
                 (event_id, ts, kind, span_id, parent_span_id, actor, payload, artifact_refs, hash_prev, hash_self, cryptowerk_proof)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    event.event_id.0 as i64,
                    event.ts.to_rfc3339(),
                    kind_str,
                    event.span_id,
                    event.parent_span_id,
                    event.actor,
                    serde_json::to_string(&event.payload)?,
                    serde_json::to_string(&event.artifact_refs)?,
                    event.hash_prev,
                    event.hash_self,
                    event
                        .cryptowerk
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?,
                ],
            )?;
            self.last_hash = Some(event.hash_self.clone());
            self.event_count += 1;
        }

        let flushed = self.batch_buffer.len();
        tx.commit()?;
        self.batch_buffer.clear();

        debug!(
            "Flushed {} events to storage (total: {})",
            flushed, self.event_count
        );

        Ok(())
    }

    /// Store artifact (compressed with zstd, content-addressed by SHA-256)
    pub fn store_artifact(&self, data: &[u8]) -> Result<String> {
        if data.is_empty() {
            return Err(anyhow!("Cannot store empty artifact"));
        }

        // Compute hash
        use sha2::{Digest, Sha256};
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        };

        // Check if already exists (hash is always 64 hex chars)
        let prefix = &hash[..2];
        let artifact_dir = self.base_path.join("artifacts").join(prefix);
        let artifact_path = artifact_dir.join(format!("{}.zst", &hash));

        if artifact_path.exists() {
            debug!("Artifact {} already exists", hash);
            return Ok(hash);
        }

        // Compress and store
        fs::create_dir_all(&artifact_dir)?;
        let compressed = zstd::encode_all(data, 3)?;
        let mut file = fs::File::create(&artifact_path)?;
        file.write_all(&compressed)?;

        debug!(
            "Stored artifact {} ({} bytes -> {} bytes)",
            hash,
            data.len(),
            compressed.len()
        );

        Ok(hash)
    }

    /// Retrieve artifact and verify its hash
    pub fn get_artifact(&self, hash: &str) -> Result<Vec<u8>> {
        if hash.len() < 2 {
            return Err(anyhow!("Invalid artifact hash: too short"));
        }

        let prefix = &hash[..2];
        let artifact_path = self
            .base_path
            .join("artifacts")
            .join(prefix)
            .join(format!("{}.zst", hash));

        if !artifact_path.exists() {
            return Err(anyhow!("Artifact {} not found", hash));
        }

        let compressed = fs::read(&artifact_path)?;
        let data = zstd::decode_all(&compressed[..])?;

        // Verify integrity: recompute hash and compare
        use sha2::{Digest, Sha256};
        let actual_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        };
        if actual_hash != hash {
            return Err(anyhow!(
                "Artifact integrity check failed: expected {} got {}",
                hash,
                actual_hash
            ));
        }

        Ok(data)
    }

    /// Load events from storage
    pub fn load_events(&self, limit: Option<usize>) -> Result<Vec<Event>> {
        let mut stmt = self.db.prepare(
            "SELECT event_id, ts, kind, span_id, parent_span_id, actor,
                    payload, artifact_refs, hash_prev, hash_self, cryptowerk_proof
             FROM events ORDER BY event_id",
        )?;

        let limit = limit.unwrap_or(usize::MAX);
        let run_id = self.run_id.clone();
        let events = stmt
            .query_map([], |row| Self::row_to_event(row, &run_id))?
            .take(limit)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(events)
    }

    /// Verify hash chain integrity
    pub fn verify_chain(&self) -> Result<bool> {
        let events = self.load_events(None)?;
        verify_event_chain(&events)
    }

    /// Get root hash (hash of last event)
    pub fn root_hash(&self) -> Option<String> {
        self.last_hash.clone()
    }

    /// Get event count
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Finalize run and write meta.json
    pub fn finalize(&mut self, meta: &RunMeta) -> Result<()> {
        self.flush()?;

        self.write_meta(meta)?;

        info!(
            "Finalized run {} at {:?}",
            self.run_id.0,
            self.base_path.join("meta.json")
        );

        Ok(())
    }

    pub fn write_meta(&self, meta: &RunMeta) -> Result<()> {
        let meta_path = self.base_path.join("meta.json");
        let meta_json = serde_json::to_string_pretty(meta)?;
        fs::write(&meta_path, meta_json)?;
        Ok(())
    }

    pub fn load_meta(&self) -> Result<RunMeta> {
        let meta_path = self.base_path.join("meta.json");
        let meta_json = fs::read_to_string(meta_path)?;
        Ok(serde_json::from_str(&meta_json)?)
    }

    pub fn write_event_cryptowerk_proof(
        &self,
        event_id: EventId,
        proof: &CryptowerkProof,
    ) -> Result<()> {
        let proof_json = serde_json::to_string(proof)?;
        self.db.execute(
            "UPDATE events SET cryptowerk_proof = ?1 WHERE event_id = ?2",
            params![proof_json, event_id.0 as i64],
        )?;
        Ok(())
    }

    pub fn run_path(&self) -> &Path {
        &self.base_path
    }

    /// Get event count grouped by kind
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

    /// Load events with optional kind filter, text search, and pagination.
    /// Returns (events, total_matching_count).
    pub fn load_events_filtered(
        &self,
        kind_filter: Option<&[&str]>,
        search: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<Event>, u64)> {
        let mut where_clauses = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(kinds) = kind_filter
            && !kinds.is_empty()
        {
            let placeholders: Vec<&str> = kinds.iter().map(|_| "?").collect();
            where_clauses.push(format!("kind IN ({})", placeholders.join(",")));
            for k in kinds {
                param_values.push(Box::new(k.to_string()));
            }
        }

        if let Some(term) = search
            && !term.is_empty()
        {
            where_clauses.push("payload LIKE ?".to_string());
            param_values.push(Box::new(format!("%{}%", term)));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // Get total count
        let count_sql = format!("SELECT COUNT(*) FROM events {}", where_sql);
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let total: u64 = self
            .db
            .query_row(&count_sql, params_ref.as_slice(), |row| row.get(0))?;

        // Get paginated events
        let select_sql = format!(
            "SELECT event_id, ts, kind, span_id, parent_span_id, actor,
                    payload, artifact_refs, hash_prev, hash_self, cryptowerk_proof
             FROM events {} ORDER BY event_id LIMIT ? OFFSET ?",
            where_sql
        );
        let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        // Re-add filter params
        if let Some(kinds) = kind_filter {
            for k in kinds {
                all_params.push(Box::new(k.to_string()));
            }
        }
        if let Some(term) = search
            && !term.is_empty()
        {
            all_params.push(Box::new(format!("%{}%", term)));
        }
        all_params.push(Box::new(limit as i64));
        all_params.push(Box::new(offset as i64));

        let all_ref: Vec<&dyn rusqlite::types::ToSql> =
            all_params.iter().map(|p| p.as_ref()).collect();
        let run_id = self.run_id.clone();

        let mut stmt = self.db.prepare(&select_sql)?;
        let events = stmt
            .query_map(all_ref.as_slice(), |row| Self::row_to_event(row, &run_id))?
            .collect::<Result<Vec<_>, _>>()?;

        Ok((events, total))
    }

    /// Get events-per-minute timeline
    pub fn events_timeline(&self) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.db.prepare(
            "SELECT substr(ts, 12, 5) as minute, COUNT(*)
             FROM events GROUP BY minute ORDER BY minute",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get distinct agent run IDs from payload
    pub fn agent_run_ids(&self) -> Result<Vec<String>> {
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT json_extract(payload, '$.data.runId')
             FROM events
             WHERE json_extract(payload, '$.data.runId') IS NOT NULL",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Get total storage size (ledger + artifacts) in bytes
    pub fn storage_size_bytes(&self) -> Result<u64> {
        let mut total: u64 = 0;
        for entry in walkdir::WalkDir::new(&self.base_path).into_iter().flatten() {
            if entry.file_type().is_file() {
                total += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
        Ok(total)
    }

    /// Parse a single row into an Event (shared by load_events and load_events_filtered)
    fn row_to_event(row: &rusqlite::Row, run_id: &RunId) -> rusqlite::Result<Event> {
        let event_id: i64 = row.get(0)?;
        let ts_str: String = row.get(1)?;
        let kind_str: String = row.get(2)?;
        let span_id: Option<String> = row.get(3)?;
        let parent_span_id: Option<String> = row.get(4)?;
        let actor: Option<String> = row.get(5)?;
        let payload_str: String = row.get(6)?;
        let artifact_refs_str: String = row.get(7)?;
        let hash_prev: Option<String> = row.get(8)?;
        let hash_self: String = row.get(9)?;
        let cryptowerk_proof_str: Option<String> = row.get(10)?;

        let ts = DateTime::parse_from_rfc3339(&ts_str)
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
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
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let artifact_refs: Vec<String> = serde_json::from_str(&artifact_refs_str).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(e))
        })?;
        let cryptowerk = cryptowerk_proof_str
            .map(|proof| {
                serde_json::from_str::<CryptowerkProof>(&proof).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        10,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })
            })
            .transpose()?;

        Ok(Event {
            run_id: run_id.clone(),
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
            cryptowerk,
        })
    }
}

fn ensure_event_cryptowerk_column(db: &Connection) -> Result<()> {
    let mut stmt = db.prepare("PRAGMA table_info(events)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_cryptowerk_column = false;
    for column in columns {
        if column? == "cryptowerk_proof" {
            has_cryptowerk_column = true;
            break;
        }
    }

    if !has_cryptowerk_column {
        db.execute("ALTER TABLE events ADD COLUMN cryptowerk_proof TEXT", [])?;
    }

    Ok(())
}

/// List all recorded runs in a directory
pub fn list_runs(base_path: &Path) -> Result<Vec<(RunId, RunMeta)>> {
    let runs_dir = base_path.join("runs");
    if !runs_dir.exists() {
        return Ok(vec![]);
    }

    let mut runs = Vec::new();

    for entry in fs::read_dir(&runs_dir)? {
        let entry = entry?;
        let meta_path = entry.path().join("meta.json");

        if meta_path.exists() {
            let meta_json = fs::read_to_string(&meta_path)?;
            if let Ok(meta) = serde_json::from_str::<RunMeta>(&meta_json) {
                runs.push((meta.run_id.clone(), meta));
            }
        }
    }

    // Sort by start time descending
    runs.sort_by(|a, b| b.1.started_at.cmp(&a.1.started_at));

    Ok(runs)
}

/// List all recorded runs with storage size
/// Resolve a (possibly short) run ID prefix to a full run ID.
/// Scans the `runs/` directory for directories starting with the given prefix.
/// Returns an error if zero or multiple matches are found.
pub fn resolve_run_id(prefix: &str, base_path: &Path) -> Result<RunId> {
    let runs_dir = base_path.join("runs");
    if !runs_dir.exists() {
        return Err(anyhow!("No runs directory at {:?}", runs_dir));
    }

    let mut matches = Vec::new();
    for entry in fs::read_dir(&runs_dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && name.starts_with(prefix)
        {
            matches.push(name.to_string());
        }
    }

    match matches.len() {
        0 => Err(anyhow!("No run found matching prefix '{}'", prefix)),
        1 => Ok(RunId(matches.into_iter().next().unwrap())),
        n => {
            let previews: Vec<String> = matches
                .iter()
                .map(|m| m[..8.min(m.len())].to_string())
                .collect();
            Err(anyhow!(
                "Prefix '{}' is ambiguous — matches {} runs: {}",
                prefix,
                n,
                previews.join(", ")
            ))
        }
    }
}

pub fn list_runs_with_stats(base_path: &Path) -> Result<Vec<(RunId, RunMeta, u64)>> {
    let runs_dir = base_path.join("runs");
    if !runs_dir.exists() {
        return Ok(vec![]);
    }

    let mut runs = Vec::new();

    for entry in fs::read_dir(&runs_dir)? {
        let entry = entry?;
        let run_path = entry.path();
        let meta_path = run_path.join("meta.json");

        if meta_path.exists() {
            let meta_json = fs::read_to_string(&meta_path)?;
            if let Ok(meta) = serde_json::from_str::<RunMeta>(&meta_json) {
                let mut size: u64 = 0;
                for f in walkdir::WalkDir::new(&run_path).into_iter().flatten() {
                    if f.file_type().is_file() {
                        size += f.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                }
                runs.push((meta.run_id.clone(), meta, size));
            }
        }
    }

    runs.sort_by(|a, b| b.1.started_at.cmp(&a.1.started_at));
    Ok(runs)
}

/// Verify hash chain integrity on a slice of events.
/// Returns Ok(true) if valid, Ok(false) if tampered.
pub fn verify_event_chain(events: &[crate::Event]) -> Result<bool> {
    if events.is_empty() {
        return Ok(true);
    }

    for (i, event) in events.iter().enumerate() {
        if !event.verify() {
            warn!("Event {} failed hash verification", event.event_id.0);
            return Ok(false);
        }

        if i > 0 {
            let prev_hash = &events[i - 1].hash_self;
            if event.hash_prev.as_ref() != Some(prev_hash) {
                warn!("Event {} has broken chain link", event.event_id.0);
                return Ok(false);
            }
        }
    }

    info!("Hash chain verified for {} events", events.len());
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventKind;
    use tempfile::TempDir;

    #[test]
    fn test_storage_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let run_id = RunId::new();

        let mut storage = RunStorage::new(run_id.clone(), temp_dir.path(), 10).unwrap();

        let data = b"test artifact data";
        let hash = storage.store_artifact(data).unwrap();
        assert!(!hash.is_empty());

        let retrieved = storage.get_artifact(&hash).unwrap();
        assert_eq!(retrieved, data);

        let meta = RunMeta::new(run_id.clone(), "ws://test".to_string());
        storage.finalize(&meta).unwrap();

        let storage2 = RunStorage::open(run_id, temp_dir.path()).unwrap();
        assert_eq!(storage2.event_count(), 0);
    }

    /// Verify EventKind survives a DB round-trip (was broken: stored "RunStart", loaded "RUN_START")
    #[test]
    fn test_event_kind_round_trip() {
        let temp_dir = TempDir::new().unwrap();
        let run_id = RunId::new();
        let mut storage = RunStorage::new(run_id.clone(), temp_dir.path(), 100).unwrap();

        let kinds = [
            EventKind::RunStart,
            EventKind::ToolCall,
            EventKind::ToolResult,
            EventKind::OutputChunk,
            EventKind::Presence,
            EventKind::Tick,
            EventKind::Shutdown,
            EventKind::RunEnd,
        ];

        for (i, kind) in kinds.iter().enumerate() {
            let event = crate::Event::new(
                run_id.clone(),
                crate::EventId((i + 1) as u64),
                *kind,
                serde_json::json!({"test": true}),
                None,
            );
            storage.write_event(event).unwrap();
        }
        storage.flush().unwrap();

        let loaded = storage.load_events(None).unwrap();
        assert_eq!(loaded.len(), kinds.len());

        for (loaded_event, expected_kind) in loaded.iter().zip(kinds.iter()) {
            assert_eq!(
                loaded_event.kind, *expected_kind,
                "Kind mismatch for event {}: got {:?}, expected {:?}",
                loaded_event.event_id.0, loaded_event.kind, expected_kind
            );
        }
    }

    /// Verify that write_event chains hashes correctly and verify_chain passes
    #[test]
    fn test_hash_chain_through_storage() {
        let temp_dir = TempDir::new().unwrap();
        let run_id = RunId::new();
        let mut storage = RunStorage::new(run_id.clone(), temp_dir.path(), 100).unwrap();

        // Write 5 events
        for i in 1..=5 {
            let event = crate::Event::new(
                run_id.clone(),
                crate::EventId(i),
                EventKind::ToolCall,
                serde_json::json!({"step": i}),
                None, // storage will set hash_prev
            );
            storage.write_event(event).unwrap();
        }
        storage.flush().unwrap();

        // Load and verify chain structure
        let events = storage.load_events(None).unwrap();
        assert_eq!(events.len(), 5);

        // First event has no previous hash
        assert!(events[0].hash_prev.is_none());

        // Each subsequent event links to the previous
        for i in 1..events.len() {
            assert_eq!(
                events[i].hash_prev.as_ref(),
                Some(&events[i - 1].hash_self),
                "Event {} should link to event {}",
                i + 1,
                i
            );
        }

        // verify_chain should pass
        assert!(storage.verify_chain().unwrap());
    }

    /// Verify that tampering is detected
    #[test]
    fn test_tamper_detection() {
        let temp_dir = TempDir::new().unwrap();
        let run_id = RunId::new();
        let mut storage = RunStorage::new(run_id.clone(), temp_dir.path(), 100).unwrap();

        for i in 1..=3 {
            let event = crate::Event::new(
                run_id.clone(),
                crate::EventId(i),
                EventKind::ToolCall,
                serde_json::json!({"step": i}),
                None,
            );
            storage.write_event(event).unwrap();
        }
        storage.flush().unwrap();

        // Tamper with event 2's payload directly in the DB
        storage
            .db
            .execute(
                "UPDATE events SET payload = '{\"step\":999}' WHERE event_id = 2",
                [],
            )
            .unwrap();

        // verify_chain should now fail
        assert!(!storage.verify_chain().unwrap());
    }

    /// Verify that hash chain works across flush boundaries
    #[test]
    fn test_hash_chain_across_flushes() {
        let temp_dir = TempDir::new().unwrap();
        let run_id = RunId::new();
        // batch_size=2 so we flush after every 2 events
        let mut storage = RunStorage::new(run_id.clone(), temp_dir.path(), 2).unwrap();

        for i in 1..=5 {
            let event = crate::Event::new(
                run_id.clone(),
                crate::EventId(i),
                EventKind::AgentEvent,
                serde_json::json!({"n": i}),
                None,
            );
            storage.write_event(event).unwrap();
        }
        storage.flush().unwrap();

        let events = storage.load_events(None).unwrap();
        assert_eq!(events.len(), 5);

        // Chain must be unbroken across flush boundaries
        for i in 1..events.len() {
            assert_eq!(
                events[i].hash_prev.as_ref(),
                Some(&events[i - 1].hash_self),
                "Chain broken at event {} (across flush boundary)",
                i + 1
            );
        }
        assert!(storage.verify_chain().unwrap());
    }

    /// Verify artifact integrity check catches corruption
    #[test]
    fn test_artifact_integrity_check() {
        let temp_dir = TempDir::new().unwrap();
        let run_id = RunId::new();
        let storage = RunStorage::new(run_id.clone(), temp_dir.path(), 10).unwrap();

        let data = b"important audit data";
        let hash = storage.store_artifact(data).unwrap();

        // Retrieval should work
        let retrieved = storage.get_artifact(&hash).unwrap();
        assert_eq!(retrieved, data);

        // Corrupt the artifact file
        let prefix = &hash[..2];
        let artifact_path = storage
            .run_path()
            .join("artifacts")
            .join(prefix)
            .join(format!("{}.zst", hash));
        let corrupted = zstd::encode_all(b"tampered data" as &[u8], 3).unwrap();
        fs::write(&artifact_path, corrupted).unwrap();

        // Retrieval should now fail integrity check
        let result = storage.get_artifact(&hash);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("integrity check failed"),
            "Should report integrity failure"
        );
    }

    /// Verify empty artifact is rejected
    #[test]
    fn test_empty_artifact_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let run_id = RunId::new();
        let storage = RunStorage::new(run_id.clone(), temp_dir.path(), 10).unwrap();

        let result = storage.store_artifact(b"");
        assert!(result.is_err());
    }

    /// Verify artifact deduplication
    #[test]
    fn test_artifact_deduplication() {
        let temp_dir = TempDir::new().unwrap();
        let run_id = RunId::new();
        let storage = RunStorage::new(run_id.clone(), temp_dir.path(), 10).unwrap();

        let data = b"same content";
        let hash1 = storage.store_artifact(data).unwrap();
        let hash2 = storage.store_artifact(data).unwrap();
        assert_eq!(hash1, hash2);
    }
}
