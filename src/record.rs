//! Recording session manager
//!
//! Coordinates gateway connection, event processing, and storage.

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::{
    Config, Event, EventId, EventKind, RunId, RunMeta,
    gateway::{GatewayClient, GatewayEvent},
    proof::{build_run_anchor, cryptowerk_failure},
    redact::redact_json,
    storage::RunStorage,
};

/// Summary returned after a recording session ends.
pub struct RecordingSummary {
    pub duration_secs: i64,
    pub event_count: u64,
    pub size_bytes: u64,
    pub valid: bool,
    pub out_dir: std::path::PathBuf,
}

/// Active recording session
pub struct RecordingSession {
    run_id: RunId,
    config: Config,
    storage: Arc<Mutex<RunStorage>>,
    shutdown_tx: mpsc::Sender<()>,
}

impl RecordingSession {
    /// Start a new recording session
    pub async fn start(config: Config, run_name: Option<String>) -> Result<Self> {
        let run_id = match run_name {
            Some(name) => RunId(name),
            None => RunId::new(),
        };

        info!("Starting recording session: {}", run_id.0);

        let storage = RunStorage::new(run_id.clone(), &config.output_dir, config.batch_size)?;

        let storage = Arc::new(Mutex::new(storage));
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let config_clone = config.clone();
        let run_id_clone = run_id.clone();
        let storage_clone = storage.clone();

        tokio::spawn(async move {
            if let Err(e) =
                recording_loop(run_id_clone, config_clone, storage_clone, shutdown_rx).await
            {
                error!("Recording loop failed: {}", e);
            }
        });

        Ok(Self {
            run_id,
            config,
            storage,
            shutdown_tx,
        })
    }

    pub fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// Stop the recording session gracefully and return a summary.
    pub async fn stop(self) -> Result<RecordingSummary> {
        info!("Stopping recording session: {}", self.run_id.0);

        let _ = self.shutdown_tx.send(()).await;

        // Give the recording loop time to write RUN_END and flush
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Finalize storage
        let mut storage = self.storage.lock().await;
        let root_hash = storage.root_hash().unwrap_or_default();

        let started_at = storage
            .load_events(Some(1))?
            .first()
            .map(|e| e.ts)
            .unwrap_or_else(chrono::Utc::now);
        let ended_at = chrono::Utc::now();

        let meta = RunMeta {
            run_id: self.run_id.clone(),
            started_at,
            ended_at: Some(ended_at),
            event_count: storage.event_count(),
            root_hash,
            gateway_url: self.config.gateway_url.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            cryptowerk: None,
        };

        storage.finalize(&meta)?;
        let valid = storage.verify_chain().unwrap_or(false);

        if valid {
            let anchor = build_run_anchor(self.config.cryptowerk.clone());
            match anchor.anchor_completed_run(&meta) {
                Ok(Some(cryptowerk)) => {
                    let mut updated_meta = meta.clone();
                    updated_meta.cryptowerk = Some(cryptowerk);
                    if let Err(error) = storage.write_meta(&updated_meta) {
                        warn!("Failed to persist Cryptowerk metadata: {}", error);
                    }
                }
                Ok(None) => {
                    if self.config.cryptowerk.is_some() {
                        info!(
                            "Cryptowerk anchoring skipped because runtime configuration was incomplete"
                        );
                    }
                }
                Err(error) => {
                    warn!("Cryptowerk anchoring failed: {}", error);
                    let mut updated_meta = meta.clone();
                    updated_meta.cryptowerk = Some(cryptowerk_failure(error.to_string()));
                    if let Err(write_error) = storage.write_meta(&updated_meta) {
                        warn!(
                            "Failed to persist Cryptowerk error metadata: {}",
                            write_error
                        );
                    }
                }
            }
        } else if self.config.cryptowerk.is_some() {
            warn!("Skipping Cryptowerk anchoring because local hash-chain verification failed");
        }

        let size_bytes = storage.storage_size_bytes().unwrap_or(0);
        let duration_secs = ended_at.signed_duration_since(started_at).num_seconds();

        info!("Recording session finalized: {}", self.run_id.0);
        Ok(RecordingSummary {
            duration_secs,
            event_count: meta.event_count,
            size_bytes,
            valid,
            out_dir: self.config.output_dir.clone(),
        })
    }
}

/// Main recording loop
async fn recording_loop(
    run_id: RunId,
    config: Config,
    storage: Arc<Mutex<RunStorage>>,
    mut shutdown_rx: mpsc::Receiver<()>,
) -> Result<()> {
    let auth_token = config.auth_token.as_deref()
        .ok_or_else(|| anyhow::anyhow!("No auth token provided. Use --token or set gateway.auth.token in ~/.openclaw/openclaw.json"))?;

    // Connect to gateway
    let mut client = GatewayClient::new(&config.gateway_url, auth_token)?;
    let conn_id = client.connect().await?;

    info!("Recording loop started, connId: {}", conn_id);

    // Write RUN_START event
    let start_event = Event::new(
        run_id.clone(),
        EventId(1),
        EventKind::RunStart,
        serde_json::json!({
            "gateway_url": config.gateway_url,
            "conn_id": conn_id,
        }),
        None,
    );

    {
        let mut storage = storage.lock().await;
        storage.write_event(start_event)?;
    }

    // Spawn the gateway event loop on a separate task
    let (event_tx, mut event_rx) = mpsc::channel::<GatewayEvent>(1000);
    tokio::spawn(async move {
        if let Err(e) = client.run(event_tx).await {
            error!("Gateway event loop ended: {}", e);
        }
    });

    let mut event_counter: u64 = 2;
    let mut flush_interval = interval(Duration::from_millis(config.flush_interval_ms));
    let redact = config.redact_secrets;

    // Progress spinner on stderr
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));

    let event_count_shared = Arc::new(AtomicU64::new(1));
    let last_kind = Arc::new(Mutex::new("RUN_START".to_string()));

    loop {
        tokio::select! {
            msg = event_rx.recv() => {
                match msg {
                    Some(gw_event) => {
                        debug!("Gateway event: {} (seq={:?})", gw_event.event, gw_event.seq);

                        let kind_name = match gw_event.event.as_str() {
                            "agent" => "AGENT_EVENT",
                            "chat" => "OUTPUT_CHUNK",
                            "tick" => "TICK",
                            "presence" => "PRESENCE",
                            "shutdown" => "SHUTDOWN",
                            _ => "CUSTOM",
                        };

                        let event = gateway_event_to_event(
                            &run_id,
                            EventId(event_counter),
                            gw_event,
                            redact,
                        );

                        {
                            let mut storage = storage.lock().await;
                            if let Err(e) = storage.write_event(event) {
                                error!("Failed to write event: {}", e);
                            }
                        }

                        event_counter += 1;
                        let count = event_count_shared.fetch_add(1, Ordering::Relaxed) + 1;
                        *last_kind.lock().await = kind_name.to_string();

                        pb.set_message(format!(
                            "{} events captured | Last: {}",
                            count, kind_name
                        ));
                    }
                    None => {
                        warn!("Gateway connection lost");
                        break;
                    }
                }
            }

            _ = flush_interval.tick() => {
                let mut storage = storage.lock().await;
                if let Err(e) = storage.flush() {
                    error!("Failed to flush: {}", e);
                }
            }

            _ = shutdown_rx.recv() => {
                info!("Received shutdown signal");
                break;
            }
        }
    }

    pb.finish_and_clear();

    // Write RUN_END event
    let end_event = Event::new(
        run_id.clone(),
        EventId(event_counter),
        EventKind::RunEnd,
        serde_json::json!({
            "conn_id": conn_id,
            "total_events": event_counter,
        }),
        None,
    );

    {
        let mut storage = storage.lock().await;
        storage.write_event(end_event)?;
        storage.flush()?;
    }

    info!("Recording loop ended, {} events captured", event_counter);
    Ok(())
}

/// Map a gateway event to a clawprint Event.
pub fn gateway_event_to_event(
    run_id: &RunId,
    event_id: EventId,
    gw: GatewayEvent,
    redact: bool,
) -> Event {
    let kind = match gw.event.as_str() {
        "agent" => EventKind::AgentEvent,
        "chat" => EventKind::OutputChunk,
        "tick" => EventKind::Tick,
        "presence" => EventKind::Presence,
        "shutdown" => EventKind::Shutdown,
        _ => EventKind::Custom,
    };

    let mut payload = serde_json::json!({
        "gateway_event": gw.event,
        "data": gw.payload,
    });

    if redact {
        redact_json(&mut payload);
    }

    let mut event = Event::new(
        run_id.clone(),
        event_id,
        kind,
        payload,
        None, // hash_prev set by storage.write_event
    );

    if let Some(seq) = gw.seq {
        event.span_id = Some(format!("seq:{}", seq));
    }

    event
}
