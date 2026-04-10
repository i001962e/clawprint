//! MCP (Model Context Protocol) server for Clawprint.
//!
//! Exposes the continuous ledger as MCP tools so Claude Desktop
//! (or any MCP client) can query agent activity via natural language.
//!
//! Run with: `clawprint mcp --out ./clawprints`
//! All output goes to stderr; stdout is reserved for the MCP JSON-RPC protocol.

use std::path::PathBuf;

use rmcp::{
    ErrorData as McpError, ServerHandler, handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters, model::*, schemars, tool, tool_handler, tool_router,
};

use crate::ledger::Ledger;

/// Parameter types for MCP tools.
/// Each derives Deserialize + JsonSchema so rmcp can generate schemas.

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListRunsParams {
    /// ISO 8601 datetime — only show runs after this time (e.g. "2026-01-31T00:00:00Z" or "today")
    #[serde(default)]
    pub since: Option<String>,
    /// ISO 8601 datetime — only show runs before this time
    #[serde(default)]
    pub until: Option<String>,
    /// Maximum number of runs to return (default 20)
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetRunParams {
    /// Agent run ID, or "latest" for the most recent conversation
    pub run_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    /// Text to search for in event payloads
    pub query: String,
    /// Filter by event kind (e.g. "AGENT_EVENT", "OUTPUT_CHUNK")
    #[serde(default)]
    pub kind: Option<String>,
    /// ISO 8601 datetime — only search events after this time
    #[serde(default)]
    pub since: Option<String>,
    /// ISO 8601 datetime — only search events before this time
    #[serde(default)]
    pub until: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ToolCallsParams {
    /// Filter by agent run ID
    #[serde(default)]
    pub run_id: Option<String>,
    /// ISO 8601 datetime — only show tool calls after this time
    #[serde(default)]
    pub since: Option<String>,
    /// Filter by tool name (e.g. "bash", "read_file")
    #[serde(default)]
    pub tool_name: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SecurityCheckParams {
    /// ISO 8601 datetime — only scan events after this time
    #[serde(default)]
    pub since: Option<String>,
    /// Scan only a specific agent run
    #[serde(default)]
    pub run_id: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct StatsParams {
    /// ISO 8601 datetime — only include events after this time
    #[serde(default)]
    pub since: Option<String>,
}

#[cfg(feature = "cryptowerk")]
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CryptowerkProofsParams {
    /// ISO 8601 datetime — only include events after this time
    #[serde(default)]
    pub since: Option<String>,
    /// ISO 8601 datetime — only include events before this time
    #[serde(default)]
    pub until: Option<String>,
    /// Only show proof rows that do not yet have a retrieval ID
    #[serde(default)]
    pub missing_only: Option<bool>,
    /// Maximum number of rows to return (default 50)
    #[serde(default)]
    pub limit: Option<u32>,
}

/// The Clawprint MCP server.
#[derive(Clone)]
pub struct ClawprintMcp {
    ledger_path: PathBuf,
    tool_router: ToolRouter<ClawprintMcp>,
}

impl ClawprintMcp {
    pub fn new(ledger_path: PathBuf) -> Self {
        Self {
            ledger_path,
            tool_router: Self::tool_router(),
        }
    }

    /// Open a read-only ledger connection.
    fn open_ledger(&self) -> Result<Ledger, McpError> {
        Ledger::open_readonly(&self.ledger_path)
            .map_err(|e| McpError::internal_error(format!("Failed to open ledger: {}", e), None))
    }

    /// Parse a datetime string like "2026-01-31T12:00:00Z" or relative like "today".
    fn parse_datetime(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        use chrono::{NaiveDate, TimeZone, Utc};

        let s = s.trim();

        // Handle relative time keywords
        let now = Utc::now();
        match s.to_lowercase().as_str() {
            "today" => {
                let today = now.date_naive();
                return today
                    .and_hms_opt(0, 0, 0)
                    .map(|dt| Utc.from_utc_datetime(&dt));
            }
            "yesterday" => {
                let yesterday = now.date_naive() - chrono::Duration::days(1);
                return yesterday
                    .and_hms_opt(0, 0, 0)
                    .map(|dt| Utc.from_utc_datetime(&dt));
            }
            _ => {}
        }

        // Handle "N hours ago", "N days ago" etc.
        if s.ends_with(" ago") {
            let parts: Vec<&str> = s.trim_end_matches(" ago").split_whitespace().collect();
            if parts.len() == 2
                && let Ok(n) = parts[0].parse::<i64>()
            {
                let duration = match parts[1] {
                    "hour" | "hours" | "h" => Some(chrono::Duration::hours(n)),
                    "day" | "days" | "d" => Some(chrono::Duration::days(n)),
                    "minute" | "minutes" | "min" | "m" => Some(chrono::Duration::minutes(n)),
                    _ => None,
                };
                if let Some(d) = duration {
                    return Some(now - d);
                }
            }
        }

        // Try ISO 8601 / RFC 3339
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
            return Some(dt.with_timezone(&Utc));
        }

        // Try date only (YYYY-MM-DD)
        if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            return date
                .and_hms_opt(0, 0, 0)
                .map(|dt| Utc.from_utc_datetime(&dt));
        }

        None
    }
}

fn text_result(text: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::success(vec![Content::text(text)]))
}

fn err_result(msg: String) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::error(vec![Content::text(msg)]))
}

#[tool_router]
impl ClawprintMcp {
    #[tool(
        description = "Get Clawprint recording status: total events, last event time, ledger size, and daemon info"
    )]
    async fn clawprint_status(&self) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        let total = ledger.total_events();
        let last_time = ledger
            .last_event_time()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let size = ledger
            .storage_size_bytes()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let daemon_started = ledger
            .get_meta("daemon_started_at")
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let gateway_url = ledger
            .get_meta("gateway_url")
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut out = "Clawprint Ledger Status\n".to_string();
        out.push_str(&format!("  Total events: {}\n", total));
        if let Some(lt) = last_time {
            out.push_str(&format!(
                "  Last event:   {}\n",
                lt.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
        out.push_str(&format!("  Ledger size:  {}\n", format_bytes(size)));
        if let Some(gw) = gateway_url {
            out.push_str(&format!("  Gateway:      {}\n", gw));
        }
        if let Some(started) = daemon_started {
            out.push_str(&format!("  Daemon started: {}\n", started));
        }

        // Hash chain status
        let (valid, checked) = ledger
            .verify_chain()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        out.push_str(&format!(
            "  Integrity:    {} ({} events checked)\n",
            if valid { "VALID" } else { "TAMPERED" },
            checked
        ));

        text_result(out)
    }

    #[tool(
        description = "List agent conversation runs. Returns run IDs with duration, event count, and tool call count. Use 'since' for time filtering (e.g. 'today', '3 hours ago', '2026-01-31')"
    )]
    async fn clawprint_list_runs(
        &self,
        Parameters(params): Parameters<ListRunsParams>,
    ) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        let since = params.since.as_deref().and_then(Self::parse_datetime);
        let until = params.until.as_deref().and_then(Self::parse_datetime);
        let limit = params.limit.unwrap_or(20) as usize;

        let runs = ledger
            .list_agent_runs(since, until, limit)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if runs.is_empty() {
            return text_result("No agent runs found in the specified time range.".to_string());
        }

        let mut out = format!("Agent Conversation Runs ({} found)\n\n", runs.len());

        for run in &runs {
            let duration = run.last_event.signed_duration_since(run.first_event);
            let dur_str = format_duration(duration.num_seconds());

            out.push_str(&format!("Run: {}\n", run.agent_run_id));
            out.push_str(&format!(
                "  Time:       {} to {}\n",
                run.first_event.format("%Y-%m-%d %H:%M:%S"),
                run.last_event.format("%H:%M:%S")
            ));
            out.push_str(&format!("  Duration:   {}\n", dur_str));
            out.push_str(&format!("  Events:     {}\n", run.event_count));
            out.push_str(&format!("  Tool calls: {}\n", run.tool_call_count));
            out.push('\n');
        }

        text_result(out)
    }

    #[tool(
        description = "Get full transcript of an agent conversation run. Use run_id='latest' for the most recent conversation"
    )]
    async fn clawprint_get_run(
        &self,
        Parameters(params): Parameters<GetRunParams>,
    ) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        let run_id = if params.run_id == "latest" {
            ledger
                .latest_agent_run()
                .map_err(|e| McpError::internal_error(e.to_string(), None))?
                .ok_or_else(|| McpError::internal_error("No agent runs found".to_string(), None))?
        } else {
            params.run_id
        };

        let events = ledger
            .get_agent_run_events(&run_id)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if events.is_empty() {
            return err_result(format!("No events found for agent run '{}'", run_id));
        }

        let mut out = format!("Agent Run: {}\n", run_id);
        out.push_str(&format!("Events: {}\n\n", events.len()));

        // Extract tool calls and chat output
        let mut tool_calls = Vec::new();
        let mut chat_output = String::new();

        for event in &events {
            match event.kind {
                crate::EventKind::AgentEvent => {
                    let is_tool_use = event
                        .payload
                        .pointer("/data/type")
                        .and_then(|v| v.as_str())
                        .map(|t| t == "tool_use")
                        .unwrap_or(false);

                    if is_tool_use {
                        let tool = event
                            .payload
                            .pointer("/data/tool")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let args = event
                            .payload
                            .pointer("/data/args")
                            .map(|v| serde_json::to_string_pretty(v).unwrap_or_default())
                            .unwrap_or_default();
                        tool_calls.push(format!(
                            "[{}] {} {}\n  {}\n",
                            event.ts.format("%H:%M:%S"),
                            tool,
                            "",
                            truncate(&args, 500)
                        ));
                    }
                }
                crate::EventKind::OutputChunk => {
                    // Check for final state chunk
                    let is_final = event
                        .payload
                        .pointer("/data/state")
                        .and_then(|v| v.as_str())
                        .map(|s| s == "final")
                        .unwrap_or(false);

                    if is_final
                        && let Some(text) = event
                            .payload
                            .pointer("/data/text")
                            .or_else(|| event.payload.pointer("/data/content"))
                            .and_then(|v| v.as_str())
                    {
                        chat_output = text.to_string();
                    }
                }
                _ => {}
            }
        }

        if !tool_calls.is_empty() {
            out.push_str(&format!("Tool Calls ({}):\n", tool_calls.len()));
            for tc in &tool_calls {
                out.push_str(tc);
            }
            out.push('\n');
        }

        if !chat_output.is_empty() {
            out.push_str("Assistant Output:\n");
            out.push_str(&truncate(&chat_output, 3000));
            out.push('\n');
        }

        text_result(out)
    }

    #[tool(
        description = "Search events by text query across all recorded history. Searches inside event payloads. Supports time and kind filtering"
    )]
    async fn clawprint_search(
        &self,
        Parameters(params): Parameters<SearchParams>,
    ) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        let since = params.since.as_deref().and_then(Self::parse_datetime);
        let until = params.until.as_deref().and_then(Self::parse_datetime);

        let events = ledger
            .search_events(&params.query, params.kind.as_deref(), since, until, 50)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if events.is_empty() {
            return text_result(format!("No events found matching '{}'", params.query));
        }

        let mut out = format!(
            "Search Results for '{}' ({} matches)\n\n",
            params.query,
            events.len()
        );

        for event in &events {
            let kind_str = serde_json::to_string(&event.kind)
                .unwrap_or_default()
                .trim_matches('"')
                .to_owned();

            out.push_str(&format!(
                "[{}] {} (event #{})\n",
                event.ts.format("%Y-%m-%d %H:%M:%S"),
                kind_str,
                event.event_id.0
            ));

            // Show relevant payload excerpt
            let payload_str = serde_json::to_string_pretty(&event.payload).unwrap_or_default();
            out.push_str(&format!("  {}\n\n", truncate(&payload_str, 300)));
        }

        text_result(out)
    }

    #[tool(
        description = "List tool calls the agent made. Shows tool name, arguments, and timestamp. Filter by run, time range, or tool name"
    )]
    async fn clawprint_tool_calls(
        &self,
        Parameters(params): Parameters<ToolCallsParams>,
    ) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        let since = params.since.as_deref().and_then(Self::parse_datetime);

        let calls = ledger
            .tool_calls(params.run_id.as_deref(), since, params.tool_name.as_deref())
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if calls.is_empty() {
            return text_result("No tool calls found matching the filters.".to_string());
        }

        let mut out = format!("Tool Calls ({} found)\n\n", calls.len());

        for call in &calls {
            let args_str = serde_json::to_string(&call.args).unwrap_or_default();
            out.push_str(&format!(
                "[{}] {}\n",
                call.timestamp.format("%Y-%m-%d %H:%M:%S"),
                call.tool
            ));
            if let Some(ref ar) = call.agent_run {
                out.push_str(&format!("  Run: {}\n", ar));
            }
            out.push_str(&format!("  Args: {}\n\n", truncate(&args_str, 300)));
        }

        text_result(out)
    }

    #[tool(
        description = "Security audit: scan recorded events for destructive operations, prompt injection attempts, privilege escalation, suspicious external access, and anomalies"
    )]
    async fn clawprint_security_check(
        &self,
        Parameters(params): Parameters<SecurityCheckParams>,
    ) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        // Get events to scan
        let events = if let Some(ref run_id) = params.run_id {
            ledger
                .get_agent_run_events(run_id)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?
        } else {
            let since = params.since.as_deref().and_then(Self::parse_datetime);
            ledger
                .search_events("", None, since, None, 10000)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?
        };

        if events.is_empty() {
            return text_result("No events to scan.".to_string());
        }

        let report = crate::security::scan_events(&events);
        text_result(report.to_text())
    }

    #[tool(
        description = "Verify hash chain integrity of the Clawprint recording ledger. Detects any tampering or corruption"
    )]
    async fn clawprint_verify(&self) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        let (valid, count) = ledger
            .verify_chain()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut out = String::new();
        if valid {
            out.push_str(&format!(
                "VALID — Hash chain integrity verified for {} events.\n",
                count
            ));
            if let Some(hash) = ledger.root_hash() {
                out.push_str(&format!("Root hash: {}\n", hash));
            }
        } else {
            out.push_str(&format!(
                "TAMPERED — Hash chain verification FAILED ({} events checked).\n",
                count
            ));
            out.push_str("The recording may have been modified after it was written.\n");
        }

        text_result(out)
    }

    #[tool(
        description = "Get event statistics: breakdown by type, events per minute timeline, storage size. Use 'since' for time filtering"
    )]
    async fn clawprint_stats(
        &self,
        Parameters(params): Parameters<StatsParams>,
    ) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        let since = params.since.as_deref().and_then(Self::parse_datetime);

        let breakdown = ledger
            .event_count_by_kind()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let timeline = ledger
            .events_timeline(since)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let size = ledger
            .storage_size_bytes()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let total = ledger.total_events();

        let mut out = format!("Clawprint Statistics ({} total events)\n\n", total);

        // Event breakdown
        out.push_str("Event Breakdown:\n");
        let mut sorted: Vec<_> = breakdown.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in &sorted {
            let pct = (**count as f64 / total.max(1) as f64) * 100.0;
            out.push_str(&format!("  {:<16} {:>6} ({:.1}%)\n", kind, count, pct));
        }

        // Timeline
        if !timeline.is_empty() {
            out.push_str("\nEvents per Minute:\n");
            for (minute, count) in &timeline {
                out.push_str(&format!("  {} {:>5}\n", minute, count));
            }
        }

        out.push_str(&format!("\nStorage: {}\n", format_bytes(size)));

        text_result(out)
    }

    #[cfg(feature = "cryptowerk")]
    #[tool(
        description = "List Cryptowerk proof records stored for ledger events, including retrieval IDs, proof URLs, and unresolved proof failures"
    )]
    async fn clawprint_cryptowerk_proofs(
        &self,
        Parameters(params): Parameters<CryptowerkProofsParams>,
    ) -> Result<CallToolResult, McpError> {
        let ledger = self.open_ledger()?;

        let since = params.since.as_deref().and_then(Self::parse_datetime);
        let until = params.until.as_deref().and_then(Self::parse_datetime);
        let missing_only = params.missing_only.unwrap_or(false);
        let limit = params.limit.unwrap_or(50) as usize;

        let rows = ledger
            .list_cryptowerk_proofs(since, until, missing_only, limit)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if rows.is_empty() {
            let msg = if missing_only {
                "No unresolved Cryptowerk proof rows found.".to_string()
            } else {
                "No Cryptowerk proof rows found.".to_string()
            };
            return text_result(msg);
        }

        let mut out = format!("Cryptowerk Proof Rows ({} found)\n\n", rows.len());

        for record in &rows {
            let event = &record.event;
            let kind_str = serde_json::to_string(&event.kind)
                .unwrap_or_default()
                .trim_matches('"')
                .to_owned();

            out.push_str(&format!(
                "[{}] {} (event #{})\n",
                event.ts.format("%Y-%m-%d %H:%M:%S"),
                kind_str,
                event.event_id.0
            ));
            out.push_str(&format!("  Hash: {}\n", event.hash_self));

            if let Some(proof) = &event.cryptowerk {
                if let Some(retrieval_id) = &proof.retrieval_id {
                    out.push_str(&format!("  Retrieval ID: {}\n", retrieval_id));
                } else {
                    out.push_str("  Retrieval ID: (missing)\n");
                }

                if let Some(proof_url) = &proof.proof_url {
                    out.push_str(&format!("  Proof URL:    {}\n", proof_url));
                }

                out.push_str(&format!(
                    "  Registered:   {}\n",
                    proof.registered_at.format("%Y-%m-%d %H:%M:%S UTC")
                ));

                if let Some(error_text) = &proof.error_text {
                    out.push_str(&format!("  Error:        {}\n", truncate(error_text, 200)));
                }
            }

            out.push('\n');
        }

        text_result(out)
    }
}

#[tool_handler]
impl ServerHandler for ClawprintMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "Clawprint is a flight recorder for OpenClaw AI agent runs. \
                 It records everything an AI agent does — tool calls, chat output, \
                 file operations — into a tamper-evident ledger. Use these tools to \
                 query agent activity, search events, list tool calls, audit security, \
                 and verify recording integrity. Start with clawprint_status to see \
                 the current state, then use clawprint_list_runs to browse conversations."
                    .into(),
            ),
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // Find a char boundary at or before max to avoid panicking on multi-byte chars
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_duration(secs: i64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if hours > 0 {
        format!("{}h {}m {}s", hours, mins, s)
    } else if mins > 0 {
        format!("{}m {}s", mins, s)
    } else {
        format!("{}s", s)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Ledger;
    use crate::{Event, EventId, EventKind, RunId};
    use tempfile::TempDir;

    fn make_event(kind: EventKind, payload: serde_json::Value) -> Event {
        Event::new(RunId("test".into()), EventId(0), kind, payload, None)
    }

    /// Populate a ledger with realistic test data: two agent runs with tool
    /// calls, output chunks, and ticks.
    fn seed_ledger(ledger: &mut Ledger) {
        // Agent run "run-alpha" — two tool calls + one output chunk
        let events = vec![
            make_event(
                EventKind::AgentEvent,
                serde_json::json!({
                    "data": {"runId": "run-alpha", "type": "tool_use", "tool": "read_file",
                             "args": {"path": "/src/main.rs"}}
                }),
            ),
            make_event(
                EventKind::AgentEvent,
                serde_json::json!({
                    "data": {"runId": "run-alpha", "type": "tool_use", "tool": "bash",
                             "args": {"command": "cargo test"}}
                }),
            ),
            make_event(
                EventKind::OutputChunk,
                serde_json::json!({
                    "data": {"runId": "run-alpha", "state": "final",
                             "text": "All tests passed!"}
                }),
            ),
            // Agent run "run-beta" — one tool call
            make_event(
                EventKind::AgentEvent,
                serde_json::json!({
                    "data": {"runId": "run-beta", "type": "tool_use", "tool": "write_file",
                             "args": {"path": "/tmp/out.txt", "content": "hello"}}
                }),
            ),
            // Tick with no agent run
            make_event(EventKind::Tick, serde_json::json!({"ts": 1})),
        ];

        for event in events {
            ledger.append_event(event).unwrap();
        }
        ledger.flush().unwrap();
    }

    fn setup() -> (TempDir, ClawprintMcp) {
        let tmp = TempDir::new().unwrap();
        {
            let mut ledger = Ledger::open(tmp.path(), 100).unwrap();
            seed_ledger(&mut ledger);
        }
        let mcp = ClawprintMcp::new(tmp.path().to_path_buf());
        (tmp, mcp)
    }

    fn extract_text(result: &CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.clone()))
            .collect::<Vec<_>>()
            .join("")
    }

    // -- Unit tests for helper functions --

    #[test]
    fn test_parse_datetime_iso8601() {
        let dt = ClawprintMcp::parse_datetime("2026-01-31T12:00:00Z").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2026-01-31");
    }

    #[test]
    fn test_parse_datetime_date_only() {
        let dt = ClawprintMcp::parse_datetime("2026-01-31").unwrap();
        assert_eq!(
            dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            "2026-01-31 00:00:00"
        );
    }

    #[test]
    fn test_parse_datetime_today() {
        let dt = ClawprintMcp::parse_datetime("today").unwrap();
        let today = chrono::Utc::now().date_naive();
        assert_eq!(dt.date_naive(), today);
    }

    #[test]
    fn test_parse_datetime_yesterday() {
        let dt = ClawprintMcp::parse_datetime("yesterday").unwrap();
        let yesterday = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
        assert_eq!(dt.date_naive(), yesterday);
    }

    #[test]
    fn test_parse_datetime_relative_hours() {
        let dt = ClawprintMcp::parse_datetime("3 hours ago").unwrap();
        let expected = chrono::Utc::now() - chrono::Duration::hours(3);
        let diff = (dt - expected).num_seconds().abs();
        assert!(
            diff < 2,
            "parsed datetime should be ~3 hours ago, diff={diff}s"
        );
    }

    #[test]
    fn test_parse_datetime_relative_days() {
        let dt = ClawprintMcp::parse_datetime("2 days ago").unwrap();
        let expected = chrono::Utc::now() - chrono::Duration::days(2);
        let diff = (dt - expected).num_seconds().abs();
        assert!(diff < 2);
    }

    #[test]
    fn test_parse_datetime_relative_minutes() {
        let dt = ClawprintMcp::parse_datetime("30 minutes ago").unwrap();
        let expected = chrono::Utc::now() - chrono::Duration::minutes(30);
        let diff = (dt - expected).num_seconds().abs();
        assert!(diff < 2);
    }

    #[test]
    fn test_parse_datetime_invalid() {
        assert!(ClawprintMcp::parse_datetime("not-a-date").is_none());
        assert!(ClawprintMcp::parse_datetime("").is_none());
    }

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_exact() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long() {
        assert_eq!(truncate("hello world", 5), "hello...");
    }

    #[test]
    fn test_truncate_multibyte() {
        // "café" is 5 bytes (é = 2 bytes), truncating at 4 must not split é
        let result = truncate("café", 4);
        assert_eq!(result, "caf...");
    }

    #[test]
    fn test_format_bytes_b() {
        assert_eq!(format_bytes(500), "500 B");
    }

    #[test]
    fn test_format_bytes_kb() {
        assert_eq!(format_bytes(2048), "2.0 KB");
    }

    #[test]
    fn test_format_bytes_mb() {
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn test_format_bytes_gb() {
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(45), "45s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(125), "2m 5s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3661), "1h 1m 1s");
    }

    // -- Integration tests for MCP tools --

    #[tokio::test]
    async fn test_clawprint_status() {
        let (_tmp, mcp) = setup();
        let result = mcp.clawprint_status().await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("Total events: 5"), "got: {text}");
        assert!(text.contains("VALID"));
    }

    #[tokio::test]
    async fn test_clawprint_list_runs() {
        let (_tmp, mcp) = setup();
        let params = Parameters(ListRunsParams {
            since: None,
            until: None,
            limit: None,
        });
        let result = mcp.clawprint_list_runs(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("run-alpha"), "got: {text}");
        assert!(text.contains("run-beta"), "got: {text}");
    }

    #[tokio::test]
    async fn test_clawprint_get_run() {
        let (_tmp, mcp) = setup();
        let params = Parameters(GetRunParams {
            run_id: "run-alpha".into(),
        });
        let result = mcp.clawprint_get_run(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("run-alpha"), "got: {text}");
        assert!(text.contains("read_file"), "should list tool calls");
        assert!(text.contains("bash"), "should list tool calls");
        assert!(text.contains("All tests passed!"), "should include output");
    }

    #[tokio::test]
    async fn test_clawprint_get_run_latest() {
        let (_tmp, mcp) = setup();
        let params = Parameters(GetRunParams {
            run_id: "latest".into(),
        });
        let result = mcp.clawprint_get_run(params).await.unwrap();
        let text = extract_text(&result);

        // "latest" should resolve to a real run
        assert!(
            text.contains("run-alpha") || text.contains("run-beta"),
            "got: {text}"
        );
    }

    #[tokio::test]
    async fn test_clawprint_get_run_not_found() {
        let (_tmp, mcp) = setup();
        let params = Parameters(GetRunParams {
            run_id: "nonexistent".into(),
        });
        let result = mcp.clawprint_get_run(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("No events found"), "got: {text}");
    }

    #[tokio::test]
    async fn test_clawprint_search() {
        let (_tmp, mcp) = setup();
        let params = Parameters(SearchParams {
            query: "cargo test".into(),
            kind: None,
            since: None,
            until: None,
        });
        let result = mcp.clawprint_search(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("1 matches"), "got: {text}");
        assert!(text.contains("cargo test"), "got: {text}");
    }

    #[tokio::test]
    async fn test_clawprint_search_no_results() {
        let (_tmp, mcp) = setup();
        let params = Parameters(SearchParams {
            query: "zzz_nonexistent_zzz".into(),
            kind: None,
            since: None,
            until: None,
        });
        let result = mcp.clawprint_search(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("No events found"), "got: {text}");
    }

    #[tokio::test]
    async fn test_clawprint_search_with_kind_filter() {
        let (_tmp, mcp) = setup();
        let params = Parameters(SearchParams {
            query: "run-alpha".into(),
            kind: Some("OUTPUT_CHUNK".into()),
            since: None,
            until: None,
        });
        let result = mcp.clawprint_search(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("1 matches"), "got: {text}");
    }

    #[tokio::test]
    async fn test_clawprint_tool_calls() {
        let (_tmp, mcp) = setup();
        let params = Parameters(ToolCallsParams {
            run_id: None,
            since: None,
            tool_name: None,
        });
        let result = mcp.clawprint_tool_calls(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("3 found"), "got: {text}");
        assert!(text.contains("read_file"));
        assert!(text.contains("bash"));
        assert!(text.contains("write_file"));
    }

    #[tokio::test]
    async fn test_clawprint_tool_calls_filter_by_name() {
        let (_tmp, mcp) = setup();
        let params = Parameters(ToolCallsParams {
            run_id: None,
            since: None,
            tool_name: Some("bash".into()),
        });
        let result = mcp.clawprint_tool_calls(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("1 found"), "got: {text}");
        assert!(text.contains("bash"));
    }

    #[tokio::test]
    async fn test_clawprint_tool_calls_filter_by_run() {
        let (_tmp, mcp) = setup();
        let params = Parameters(ToolCallsParams {
            run_id: Some("run-beta".into()),
            since: None,
            tool_name: None,
        });
        let result = mcp.clawprint_tool_calls(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("1 found"), "got: {text}");
        assert!(text.contains("write_file"));
    }

    #[tokio::test]
    async fn test_clawprint_security_check() {
        let (_tmp, mcp) = setup();
        let params = Parameters(SecurityCheckParams {
            since: None,
            run_id: None,
        });
        let result = mcp.clawprint_security_check(params).await.unwrap();
        let text = extract_text(&result);

        // Our test data has no malicious events
        assert!(
            text.contains("No suspicious patterns detected"),
            "got: {text}"
        );
    }

    #[tokio::test]
    async fn test_clawprint_verify() {
        let (_tmp, mcp) = setup();
        let result = mcp.clawprint_verify().await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("VALID"), "got: {text}");
        assert!(text.contains("5 events"), "got: {text}");
        assert!(text.contains("Root hash:"), "got: {text}");
    }

    #[tokio::test]
    async fn test_clawprint_stats() {
        let (_tmp, mcp) = setup();
        let params = Parameters(StatsParams { since: None });
        let result = mcp.clawprint_stats(params).await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("5 total events"), "got: {text}");
        assert!(text.contains("AGENT_EVENT"), "got: {text}");
        assert!(text.contains("TICK"), "got: {text}");
        assert!(text.contains("OUTPUT_CHUNK"), "got: {text}");
    }

    #[tokio::test]
    async fn test_clawprint_status_empty_ledger() {
        let tmp = TempDir::new().unwrap();
        {
            let _ledger = Ledger::open(tmp.path(), 100).unwrap();
            // no events
        }
        let mcp = ClawprintMcp::new(tmp.path().to_path_buf());
        let result = mcp.clawprint_status().await.unwrap();
        let text = extract_text(&result);

        assert!(text.contains("Total events: 0"), "got: {text}");
        assert!(text.contains("VALID"), "empty chain is valid");
    }
}
