//! Web viewer — dashboard for Clawprint recordings
//!
//! Serves an interactive web interface for browsing traces.

use anyhow::Result;
use axum::{
    Router,
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Json},
    routing::get,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use crate::RunId;
use crate::storage::{RunStorage, list_runs_with_stats};

#[derive(Clone)]
struct ViewerState {
    base_path: PathBuf,
}

pub async fn bearer_auth(
    State(expected): State<Arc<String>>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    match auth_header {
        Some(val) if val == format!("Bearer {}", *expected) => next.run(req).await.into_response(),
        _ => (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    }
}

pub async fn start_viewer(
    base_path: PathBuf,
    host: [u8; 4],
    port: u16,
    token: Option<String>,
) -> Result<()> {
    let state = ViewerState { base_path };

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/view/{run_id}", get(view_run_handler))
        .route("/api/runs", get(list_runs_handler))
        .route("/api/runs/{run_id}", get(get_run_handler))
        .route("/api/runs/{run_id}/events", get(get_events_handler))
        .route("/api/runs/{run_id}/stats", get(get_run_stats_handler))
        .with_state(state);

    let app = if let Some(tok) = token {
        app.layer(middleware::from_fn_with_state(Arc::new(tok), bearer_auth))
    } else {
        app
    };

    let addr = SocketAddr::from((host, port));
    info!("Viewer starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

/// Start the viewer with an external cancellation token for coordinated shutdown.
pub async fn start_viewer_with_shutdown(
    base_path: PathBuf,
    host: [u8; 4],
    port: u16,
    token: Option<String>,
    ct: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let state = ViewerState { base_path };

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/view/{run_id}", get(view_run_handler))
        .route("/api/runs", get(list_runs_handler))
        .route("/api/runs/{run_id}", get(get_run_handler))
        .route("/api/runs/{run_id}/events", get(get_events_handler))
        .route("/api/runs/{run_id}/stats", get(get_run_stats_handler))
        .with_state(state);

    let app = if let Some(tok) = token {
        app.layer(middleware::from_fn_with_state(Arc::new(tok), bearer_auth))
    } else {
        app
    };

    let addr = SocketAddr::from((host, port));
    info!("Viewer starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async move {
            ct.cancelled().await;
        })
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn format_duration_html(
    start: chrono::DateTime<chrono::Utc>,
    end: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    match end {
        Some(e) => {
            let secs = e.signed_duration_since(start).num_seconds();
            let h = secs / 3600;
            let m = (secs % 3600) / 60;
            let s = secs % 60;
            if h > 0 {
                format!("{}h {}m {}s", h, m, s)
            } else if m > 0 {
                format!("{}m {}s", m, s)
            } else {
                format!("{}s", s)
            }
        }
        None => "recording...".to_string(),
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ---------------------------------------------------------------------------
// Page handlers
// ---------------------------------------------------------------------------

async fn index_handler(State(state): State<ViewerState>) -> impl IntoResponse {
    let runs = match list_runs_with_stats(&state.base_path) {
        Ok(r) => r,
        Err(_) => return Html("<h1>Error loading runs</h1>".to_string()),
    };

    let total_runs = runs.len();
    let total_events: u64 = runs.iter().map(|(_, m, _)| m.event_count).sum();
    let total_size: u64 = runs.iter().map(|(_, _, s)| s).sum();

    let runs_html: String = runs
        .iter()
        .map(|(run_id, meta, size)| {
            let id_esc = escape_html(&run_id.0);
            let id_short = if run_id.0.len() >= 8 {
                escape_html(&run_id.0[..8])
            } else {
                id_esc.clone()
            };
            let dur = format_duration_html(meta.started_at, meta.ended_at);
            let status = if meta.ended_at.is_some() {
                r#"<span class="badge complete">Sealed</span>"#
            } else {
                r#"<span class="badge progress">Tracking</span>"#
            };
            format!(
                r#"<a href="/view/{id}" class="run-card">
                <div class="run-card-header">
                    <span class="run-id">{short}</span>
                    {status}
                    <span class="lock" title="Hash-chain sealed">&#x1f512;</span>
                </div>
                <div class="run-meta">
                    <span>{started}</span>
                    <span>{dur}</span>
                    <span>{events} traces</span>
                    <span>{size}</span>
                </div>
            </a>"#,
                id = id_esc,
                short = id_short,
                status = status,
                started = meta.started_at.format("%b %d, %H:%M"),
                dur = dur,
                events = meta.event_count,
                size = format_bytes(*size),
            )
        })
        .collect();

    Html(
        DASHBOARD_HTML
            .replace("{{TOTAL_RUNS}}", &total_runs.to_string())
            .replace("{{TOTAL_EVENTS}}", &total_events.to_string())
            .replace("{{TOTAL_SIZE}}", &format_bytes(total_size))
            .replace("{{RUNS}}", &runs_html),
    )
}

async fn view_run_handler(Path(run_id): Path<String>) -> impl IntoResponse {
    Html(RUN_DETAIL_HTML.replace("{{RUN_ID}}", &escape_html(&run_id)))
}

// ---------------------------------------------------------------------------
// API handlers
// ---------------------------------------------------------------------------

async fn list_runs_handler(State(state): State<ViewerState>) -> impl IntoResponse {
    match list_runs_with_stats(&state.base_path) {
        Ok(runs) => {
            let j: Vec<_> = runs
                .into_iter()
                .map(|(id, meta, size)| {
                    serde_json::json!({
                        "run_id": id.0,
                        "started_at": meta.started_at,
                        "ended_at": meta.ended_at,
                        "event_count": meta.event_count,
                        "size": size,
                    })
                })
                .collect();
            Json(j).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_run_handler(
    State(state): State<ViewerState>,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    let run_id = RunId(run_id);
    match RunStorage::open(run_id.clone(), &state.base_path) {
        Ok(storage) => {
            let valid = storage.verify_chain().unwrap_or(false);
            let cryptowerk = storage.load_meta().ok().and_then(|meta| meta.cryptowerk);
            Json(serde_json::json!({
                "run_id": run_id.0,
                "event_count": storage.event_count(),
                "root_hash": storage.root_hash(),
                "chain_valid": valid,
                "cryptowerk": cryptowerk,
            }))
            .into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}

async fn get_events_handler(
    State(state): State<ViewerState>,
    Path(run_id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let run_id = RunId(run_id);

    let page: usize = params.get("page").and_then(|s| s.parse().ok()).unwrap_or(1);
    let per_page: usize = params
        .get("per_page")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let offset = (page.saturating_sub(1)) * per_page;

    let kind_strs: Option<Vec<String>> = params
        .get("kind")
        .map(|k| k.split(',').map(|s| s.to_string()).collect());
    let kind_refs: Option<Vec<&str>> = kind_strs
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());

    let search = params.get("search").map(|s| s.as_str());

    match RunStorage::open(run_id, &state.base_path) {
        Ok(storage) => {
            match storage.load_events_filtered(kind_refs.as_deref(), search, offset, per_page) {
                Ok((events, total)) => {
                    let total_pages = total.div_ceil(per_page as u64);
                    Json(serde_json::json!({
                        "events": events,
                        "total": total,
                        "page": page,
                        "per_page": per_page,
                        "total_pages": total_pages,
                    }))
                    .into_response()
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}

async fn get_run_stats_handler(
    State(state): State<ViewerState>,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    let run_id = RunId(run_id);
    match RunStorage::open(run_id, &state.base_path) {
        Ok(storage) => {
            let breakdown = storage.event_count_by_kind().unwrap_or_default();
            let timeline = storage.events_timeline().unwrap_or_default();
            let agent_runs = storage.agent_run_ids().unwrap_or_default();
            Json(serde_json::json!({
                "event_breakdown": breakdown,
                "timeline": timeline,
                "agent_run_count": agent_runs.len(),
            }))
            .into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, e.to_string()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// HTML Templates
// ---------------------------------------------------------------------------

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Clawprint</title>
<style>
:root{--bg:#fafafa;--card:#fff;--accent:#111;--accent2:#6366f1;--green:#16a34a;--orange:#ea580c;--text:#111;--dim:#6b7280;--border:#e5e7eb;--hover:#f3f4f6;--radius:10px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',sans-serif;background:var(--bg);color:var(--text);padding:40px 24px;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:960px;margin:0 auto}
header{margin-bottom:40px}
h1{font-size:1.5rem;font-weight:700;letter-spacing:-.02em}
header p{color:var(--dim);font-size:.875rem;margin-top:2px}
.stats{display:flex;gap:32px;margin-bottom:40px;padding-bottom:24px;border-bottom:1px solid var(--border)}
.stat-label{font-size:.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}
.stat-value{font-size:1.75rem;font-weight:700;letter-spacing:-.02em}
h2{font-size:.875rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);margin-bottom:12px}
.run-card{display:block;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;margin-bottom:8px;text-decoration:none;color:inherit;transition:background .15s,box-shadow .15s}
.run-card:hover{background:var(--hover);box-shadow:0 1px 3px rgba(0,0,0,.04)}
.run-card-header{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.run-id{font-family:'SF Mono',SFMono-Regular,Menlo,monospace;font-size:.9rem;font-weight:600}
.badge{padding:2px 8px;border-radius:100px;font-size:.7rem;font-weight:500}
.badge.complete{background:#dcfce7;color:var(--green)}
.badge.progress{background:#fff7ed;color:var(--orange)}
.lock{font-size:.875rem;margin-left:auto;opacity:.4}
.run-meta{display:flex;gap:24px;font-size:.8rem;color:var(--dim)}
footer{margin-top:48px;padding-top:20px;border-top:1px solid var(--border);text-align:center;font-size:.75rem;color:var(--dim);letter-spacing:.02em}
footer span{opacity:.5}
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>><> Clawprint</h1>
<p>Every molt leaves a mark. Trace. Verify. Trust.</p>
</header>
<div class="stats">
<div><div class="stat-label">Impressions</div><div class="stat-value">{{TOTAL_RUNS}}</div></div>
<div><div class="stat-label">Traces</div><div class="stat-value">{{TOTAL_EVENTS}}</div></div>
<div><div class="stat-label">Evidence</div><div class="stat-value">{{TOTAL_SIZE}}</div></div>
</div>
<h2>Recorded impressions</h2>
{{RUNS}}
<footer><span>Watching the wire</span></footer>
</div>
</body>
</html>"##;

const RUN_DETAIL_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Run {{RUN_ID}} — Clawprint</title>
<style>
:root{--bg:#fafafa;--card:#fff;--accent:#111;--accent2:#6366f1;--green:#16a34a;--red:#dc2626;--orange:#ea580c;--blue:#2563eb;--purple:#7c3aed;--text:#111;--dim:#6b7280;--border:#e5e7eb;--hover:#f3f4f6;--code-bg:#f3f4f6;--radius:10px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Inter',sans-serif;background:var(--bg);color:var(--text);padding:40px 24px;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:960px;margin:0 auto}
a.back{color:var(--dim);text-decoration:none;font-size:.875rem;display:inline-block;margin-bottom:20px}
a.back:hover{color:var(--text)}
.hdr{margin-bottom:28px}
.hdr h1{font-size:1.25rem;font-weight:700;letter-spacing:-.02em;font-family:'SF Mono',SFMono-Regular,Menlo,monospace}
.stats{display:flex;gap:32px;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid var(--border)}
.stat-label{font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}
.stat-value{font-size:1.25rem;font-weight:700}
.section{margin-bottom:32px}
.section h2{font-size:.8rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);margin-bottom:12px}
.proof-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;font-size:.85rem}
.proof-card a{color:var(--accent2);text-decoration:none}
.proof-card a:hover{text-decoration:underline}
.proof-grid{display:grid;gap:12px}
.proof-row{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.proof-label{font-size:.72rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
.proof-value{font-family:'SF Mono',SFMono-Regular,Menlo,monospace;font-size:.78rem;word-break:break-all}
.proof-actions{display:flex;gap:8px;flex-wrap:wrap}
.proof-note{color:var(--dim);font-size:.78rem}
.proof-error{color:var(--red);margin-top:6px}
.mini-btn{padding:4px 10px;border:1px solid var(--border);background:var(--card);color:var(--text);border-radius:999px;cursor:pointer;font-size:.72rem;transition:all .15s}
.mini-btn:hover{border-color:var(--text)}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:4px;font-size:.8rem}
.bar-label{width:110px;color:var(--dim);font-family:'SF Mono',SFMono-Regular,Menlo,monospace;font-size:.75rem}
.bar-track{flex:1;background:var(--border);border-radius:4px;height:8px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;background:var(--accent2);transition:width .3s}
.bar-num{width:40px;text-align:right;font-size:.75rem;color:var(--dim);font-weight:500}
.filters{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.fbtn{padding:4px 12px;border:1px solid var(--border);background:var(--card);color:var(--dim);border-radius:100px;cursor:pointer;font-size:.75rem;transition:all .15s}
.fbtn:hover{border-color:var(--text);color:var(--text)}
.fbtn.on{background:var(--text);color:#fff;border-color:var(--text)}
.search{flex:1;min-width:160px;padding:6px 12px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:.8rem}
.search:focus{outline:none;border-color:var(--accent2);box-shadow:0 0 0 3px rgba(99,102,241,.1)}
.events{display:flex;flex-direction:column;gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.ev{background:var(--card);padding:12px 16px;border-left:3px solid var(--border)}
.ev.RUN_START{border-left-color:var(--green)}.ev.RUN_END{border-left-color:var(--red)}
.ev.TOOL_CALL{border-left-color:var(--orange)}.ev.TOOL_RESULT{border-left-color:var(--blue)}
.ev.OUTPUT_CHUNK{border-left-color:var(--blue)}.ev.AGENT_EVENT{border-left-color:var(--purple)}
.ev.TICK{border-left-color:var(--border)}.ev.PRESENCE{border-left-color:var(--border)}
.ev-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:4px}
.ev-kind{font-weight:600;font-size:.75rem;font-family:'SF Mono',SFMono-Regular,Menlo,monospace}
.ev-kind.RUN_START{color:var(--green)}.ev-kind.RUN_END{color:var(--red)}
.ev-kind.TOOL_CALL{color:var(--orange)}.ev-kind.OUTPUT_CHUNK{color:var(--blue)}
.ev-kind.AGENT_EVENT{color:var(--purple)}.ev-kind.CUSTOM{color:var(--dim)}
.ev-ts{font-size:.7rem;color:var(--dim)}
.ev-hash{font-size:.65rem;color:var(--dim);font-family:'SF Mono',SFMono-Regular,Menlo,monospace;margin-bottom:4px}
.ev-payload{background:var(--code-bg);border-radius:6px;padding:10px;max-height:0;overflow:hidden;transition:max-height .3s ease}
.ev-payload.open{max-height:600px;overflow-y:auto}
.ev-payload pre{margin:0;font-size:.75rem;white-space:pre-wrap;word-break:break-word;color:var(--text);font-family:'SF Mono',SFMono-Regular,Menlo,monospace}
.hash-meta{margin:0 0 10px 0;display:grid;gap:8px}
.hash-row{display:grid;gap:4px}
.hash-label{font-size:.68rem;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
.hash-value{font-size:.72rem;font-family:'SF Mono',SFMono-Regular,Menlo,monospace;word-break:break-all}
.hash-actions{display:flex;gap:8px;flex-wrap:wrap}
.toggle{background:none;border:none;color:var(--accent2);cursor:pointer;font-size:.75rem;padding:0;margin-bottom:4px}
.toggle:hover{text-decoration:underline}
.pager{display:flex;gap:4px;justify-content:center;margin-top:20px}
.pbtn{padding:6px 12px;background:var(--card);border:1px solid var(--border);border-radius:6px;color:var(--text);cursor:pointer;font-size:.8rem;transition:all .15s}
.pbtn:hover:not(:disabled){border-color:var(--text)}
.pbtn.cur{background:var(--text);color:#fff;border-color:var(--text)}
.pbtn:disabled{opacity:.3;cursor:not-allowed}
.loading{text-align:center;padding:40px;color:var(--dim);font-size:.875rem}
footer{margin-top:48px;padding-top:20px;border-top:1px solid var(--border);text-align:center;font-size:.75rem;color:var(--dim);letter-spacing:.02em}
footer span{opacity:.5}
</style>
</head>
<body>
<div class="wrap">
<a href="/" class="back">&larr; All impressions</a>
<div class="hdr">
<h1>Impression <span id="rid">{{RUN_ID}}</span></h1>
</div>
<div class="stats">
<div><div class="stat-label">Traces</div><div class="stat-value" id="s-events">-</div></div>
<div><div class="stat-label">Duration</div><div class="stat-value" id="s-dur">-</div></div>
<div><div class="stat-label">Molts</div><div class="stat-value" id="s-agents">-</div></div>
<div><div class="stat-label">Chain of evidence</div><div class="stat-value" id="s-integrity">-</div></div>
</div>

<div class="section">
<h2>Evidence breakdown</h2>
<div id="chart"></div>
</div>

<div class="section" id="proof-section" style="display:none">
<h2>Independent Verification</h2>
<div class="proof-card" id="proof-card"></div>
</div>

<div class="section">
<h2>Trace log</h2>
<div class="filters">
<button class="fbtn" data-k="AGENT_EVENT">AGENT_EVENT</button>
<button class="fbtn" data-k="OUTPUT_CHUNK">OUTPUT_CHUNK</button>
<button class="fbtn" data-k="TOOL_CALL">TOOL_CALL</button>
<button class="fbtn" data-k="RUN_START">RUN_START</button>
<button class="fbtn" data-k="RUN_END">RUN_END</button>
<button class="fbtn" data-k="TICK">TICK</button>
<button class="fbtn" data-k="CUSTOM">CUSTOM</button>
<input class="search" id="q" placeholder="Search...">
</div>
<div class="events" id="evlist"><div class="loading">Loading...</div></div>
<div class="pager" id="pager"></div>
</div>
<footer><span>Inspecting the evidence</span></footer>
</div>

<script>
const R='{{RUN_ID}}';let page=1,filters=new Set(),search='',pages=1;

async function init(){
 const[run,stats]=await Promise.all([
  fetch('/api/runs/'+R).then(r=>r.json()),
  fetch('/api/runs/'+R+'/stats').then(r=>r.json())
 ]);
 window.__run=run;
 document.getElementById('rid').textContent=R.substring(0,8);
 document.getElementById('s-events').textContent=run.event_count;
 document.getElementById('s-agents').textContent=stats.agent_run_count;
 const si=document.getElementById('s-integrity');
 si.textContent=run.chain_valid?'Sealed':'Compromised';
 si.style.color=run.chain_valid?'var(--green)':'var(--red)';
 renderProof(run.cryptowerk);
 renderChart(stats.event_breakdown);
 loadEvents();
}

function renderProof(proof){
 const section=document.getElementById('proof-section');
 const card=document.getElementById('proof-card');
 const rootHash=window.__run?.root_hash;
 if(!proof && !rootHash){return;}
 section.style.display='block';
 const parts=[];
 if(rootHash){
  parts.push(
   '<div class="proof-row">'
   +'<div><div class="proof-label">Chain of evidence hash</div><div class="proof-value">'+esc(rootHash)+'</div></div>'
   +'<div class="proof-actions"><button class="mini-btn" onclick="copyText(\''+escJs(rootHash)+'\')">Copy hash</button></div>'
   +'</div>'
  );
 }
 parts.push('<div class="proof-note">The impression hash is the final local chain hash. Each trace entry also carries its own hash and previous-link in the log details below.</div>');
 if(proof){
  const when=proof.registeredAt?new Date(proof.registeredAt).toLocaleString():'unknown';
  const retrieval=proof.retrievalId
   ?'<div class="proof-row"><div><div class="proof-label">Cryptowerk retrieval</div><div class="proof-value">'+esc(proof.retrievalId)+'</div></div><div class="proof-actions"><button class="mini-btn" onclick="copyText(\''+escJs(proof.retrievalId)+'\')">Copy retrieval ID</button></div></div>'
   :'';
  const link=proof.proofUrl
   ?'<div class="proof-row"><div><div class="proof-label">External verify</div><div><a href="'+esc(proof.proofUrl)+'" target="_blank" rel="noopener noreferrer">Verify on Cryptowerk</a></div></div><div class="proof-actions"><button class="mini-btn" onclick="copyText(\''+escJs(proof.proofUrl)+'\')">Copy proof URL</button></div></div>'
   :'';
  const status='<div class="proof-row"><div><div class="proof-label">Registered</div><div>'+esc(when)+'</div></div></div>';
  const error=proof.errorText?'<div class="proof-error">'+esc(proof.errorText)+'</div>':'';
  parts.push(status+retrieval+link+error);
 }
 card.innerHTML='<div class="proof-grid">'+parts.join('')+'</div>';
}

function renderChart(b){
 const el=document.getElementById('chart');
 const total=Object.values(b).reduce((s,v)=>s+v,0);
 const sorted=Object.entries(b).sort((a,c)=>c[1]-a[1]);
 el.innerHTML=sorted.map(([k,v])=>{
  const p=(v/total*100).toFixed(1);
  return '<div class="bar-row"><div class="bar-label">'+esc(k)+'</div><div class="bar-track"><div class="bar-fill" style="width:'+p+'%"></div></div><div class="bar-num">'+v+'</div></div>';
 }).join('');
}

async function loadEvents(){
 const p=new URLSearchParams({page,per_page:50});
 if(filters.size)p.set('kind',[...filters].join(','));
 if(search)p.set('search',search);
 const d=await fetch('/api/runs/'+R+'/events?'+p).then(r=>r.json());
 pages=d.total_pages;
 renderEvents(d.events);
 renderPager();
}

function renderEvents(evs){
 const el=document.getElementById('evlist');
 if(!evs.length){el.innerHTML='<div class="loading">No traces found</div>';return;}
 el.innerHTML=evs.map(e=>{
  const collapse=e.kind==='TICK'||e.kind==='PRESENCE';
  const ts=new Date(e.ts).toLocaleString();
  const hash=e.hash_self?e.hash_self.substring(0,16):'';
  const selfHash=e.hash_self||'Unavailable';
  const prevHash=e.hash_prev||'First event in chain';
  const proof=e.cryptowerk;
  const payload=JSON.stringify(e.payload,null,2);
  const proofBlock=proof
   ?('<div class="hash-row"><div class="hash-label">Cryptowerk retrieval</div><div class="hash-value">'+esc(proof.retrievalId||'Unavailable')+'</div>'
      +(proof.proofUrl?'<div class="hash-actions"><a href="'+esc(proof.proofUrl)+'" target="_blank" rel="noopener noreferrer">Verify on Cryptowerk</a><button class="mini-btn" onclick="copyText(\''+escJs(proof.proofUrl)+'\')">Copy proof URL</button></div>':'')
      +(proof.errorText?'<div class="proof-error">'+esc(proof.errorText)+'</div>':'')
      +'</div>')
   :'';
  return '<div class="ev '+esc(e.kind)+'">'
   +'<div class="ev-head"><span class="ev-kind '+esc(e.kind)+'">'+esc(e.kind)+'</span><span class="ev-ts">'+esc(ts)+'</span></div>'
   +'<div class="ev-hash">Hash '+esc(hash)+(e.hash_prev?' · linked':' · chain start')+'</div>'
   +'<button class="toggle" onclick="tog(this)">'+(collapse?'Show':'Hide')+'</button>'
   +'<div class="ev-payload'+(collapse?'':' open')+'">'
   +'<div class="hash-meta">'
   +'<div class="hash-row"><div class="hash-label">Event hash</div><div class="hash-value">'+esc(selfHash)+'</div><div class="hash-actions"><button class="mini-btn" onclick="copyText(\''+escJs(selfHash)+'\')">Copy event hash</button></div></div>'
   +'<div class="hash-row"><div class="hash-label">Previous hash</div><div class="hash-value">'+esc(prevHash)+'</div>'+(e.hash_prev?'<div class="hash-actions"><button class="mini-btn" onclick="copyText(\''+escJs(prevHash)+'\')">Copy previous hash</button></div>':'')+'</div>'
   +proofBlock
   +'</div>'
   +'<pre>'+esc(payload)+'</pre></div>'
   +'</div>';
 }).join('');
}

function tog(btn){
 const p=btn.nextElementSibling;
 p.classList.toggle('open');
 btn.textContent=p.classList.contains('open')?'Hide':'Show';
}

function renderPager(){
 const el=document.getElementById('pager');
 let h='<button class="pbtn" '+(page<=1?'disabled':'')+' onclick="go('+(page-1)+')">Prev</button>';
 const start=Math.max(1,page-2),end=Math.min(pages,start+4);
 for(let i=start;i<=end;i++)h+='<button class="pbtn'+(i===page?' cur':'')+'" onclick="go('+i+')">'+i+'</button>';
 if(end<pages)h+='<span style="color:var(--dim);padding:6px">...'+pages+'</span>';
 h+='<button class="pbtn" '+(page>=pages?'disabled':'')+' onclick="go('+(page+1)+')">Next</button>';
 el.innerHTML=h;
}

function go(p){if(p>=1&&p<=pages){page=p;loadEvents();}}
function copyText(text){
 if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text);return;}
 const input=document.createElement('textarea');input.value=text;document.body.appendChild(input);input.select();document.execCommand('copy');document.body.removeChild(input);
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}
function escJs(s){return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\n/g,'\\n');}

document.querySelectorAll('.fbtn[data-k]').forEach(b=>{
 b.addEventListener('click',()=>{
  const k=b.dataset.k;
  if(filters.has(k)){filters.delete(k);b.classList.remove('on');}
  else{filters.add(k);b.classList.add('on');}
  page=1;loadEvents();
 });
});

let st;document.getElementById('q').addEventListener('input',e=>{
 clearTimeout(st);st=setTimeout(()=>{search=e.target.value.trim();page=1;loadEvents();},300);
});

window.__run={};
init();
</script>
</body>
</html>"##;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_html() {
        assert_eq!(
            escape_html("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html(r#"x="y""#), "x=&quot;y&quot;");
        assert_eq!(escape_html("it's"), "it&#x27;s");
        assert_eq!(escape_html("safe text"), "safe text");
    }

    #[test]
    fn test_format_duration_html() {
        use chrono::{TimeZone, Utc};
        let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 1, 1, 1, 30, 45).unwrap();
        assert_eq!(format_duration_html(start, Some(end)), "1h 30m 45s");
        assert_eq!(format_duration_html(start, None), "recording...");
    }

    #[tokio::test]
    async fn test_viewer_with_shutdown() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_util::sync::CancellationToken;

        let tmp = tempfile::tempdir().unwrap();
        let base_path = tmp.path().to_path_buf();

        // Find a free port
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let ct = CancellationToken::new();
        let ct_clone = ct.clone();

        let handle = tokio::spawn(async move {
            start_viewer_with_shutdown(base_path, [127, 0, 0, 1], port, None, ct_clone).await
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send a raw HTTP request
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("failed to connect to viewer");

        let request = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            port
        );
        stream.write_all(request.as_bytes()).await.unwrap();

        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(
            response.contains("Clawprint"),
            "Response should contain 'Clawprint', got: {}",
            &response[..response.len().min(200)]
        );

        // Shut down gracefully
        ct.cancel();

        let result = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("viewer did not shut down in time")
            .expect("viewer task panicked");

        result.expect("viewer returned an error");
    }
}
