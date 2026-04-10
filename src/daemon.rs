//! Daemon mode — continuous 24/7 recording to the single ledger.
//!
//! Unlike `record` (session-based, Ctrl+C to stop), the daemon runs forever,
//! auto-reconnects on disconnect, and writes to a single growing ledger.

use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::{
    Config, Event, EventId, RunId,
    gateway::{GatewayClient, GatewayEvent},
    ledger::Ledger,
    proof::{build_run_anchor, cryptowerk_failure},
    record::gateway_event_to_event,
};

const CRYPTOWERK_EVENT_BATCH_SIZE: usize = 25;
const CRYPTOWERK_EVENT_FLUSH_SECS: u64 = 5;
const CRYPTOWERK_RETRY_SECS: u64 = 10;
const CRYPTOWERK_RETRY_BATCH_SIZE: usize = 100;

/// Run the daemon: connect to gateway, record to ledger, auto-reconnect.
pub async fn run_daemon(config: Config) -> Result<()> {
    let ct = tokio_util::sync::CancellationToken::new();
    let ct_clone = ct.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        ct_clone.cancel();
    });
    run_daemon_with_shutdown(config, ct).await
}

/// Run the daemon with an external cancellation token for coordinated shutdown.
pub async fn run_daemon_with_shutdown(
    config: Config,
    ct: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let ledger_path = config.output_dir.clone();
    let ledger = Ledger::open(&ledger_path, config.batch_size)?;
    let ledger = Arc::new(Mutex::new(ledger));

    // Store start time in meta
    {
        let l = ledger.lock().await;
        l.set_meta("daemon_started_at", &chrono::Utc::now().to_rfc3339())?;
        l.set_meta("gateway_url", &config.gateway_url)?;
    }

    // Progress spinner on stderr
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb.set_message("Connecting to gateway...");

    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    // Shutdown flag — survives across reconnect loop iterations
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown_clone = shutdown.clone();
        let ct_clone = ct.clone();
        tokio::spawn(async move {
            ct_clone.cancelled().await;
            shutdown_clone.store(true, Ordering::SeqCst);
        });
    }

    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        match run_connection(
            &config,
            ledger.clone(),
            &pb,
            &shutdown,
        )
        .await
        {
            Ok(ShutdownReason::Signal) => {
                break;
            }
            Ok(ShutdownReason::Disconnected) => {
                // Connection was established then lost — reset backoff
                backoff = Duration::from_secs(1);
                warn!("Gateway disconnected, reconnecting in {:?}...", backoff);
                pb.set_message(format!(
                    "Disconnected. Reconnecting in {}s...",
                    backoff.as_secs()
                ));

                // Wait for backoff duration, but check shutdown periodically
                let sleep_until = tokio::time::Instant::now() + backoff;
                loop {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let remaining =
                        sleep_until.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    tokio::time::sleep(remaining.min(Duration::from_millis(200))).await;
                }

                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                // Exponential backoff (will reset on next successful connection)
                backoff = (backoff * 2).min(max_backoff);
            }
            Err(e) => {
                warn!("Connection error: {}. Reconnecting in {:?}...", e, backoff);
                pb.set_message(format!("Error. Reconnecting in {}s...", backoff.as_secs()));

                let sleep_until = tokio::time::Instant::now() + backoff;
                loop {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let remaining =
                        sleep_until.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    tokio::time::sleep(remaining.min(Duration::from_millis(200))).await;
                }

                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }

    // Graceful shutdown: flush and record stop time
    pb.finish_and_clear();
    info!("Daemon shutting down gracefully");

    let mut l = ledger.lock().await;
    l.flush()?;
    l.set_meta("daemon_stopped_at", &chrono::Utc::now().to_rfc3339())?;

    let total = l.total_events();
    let size = l.storage_size_bytes().unwrap_or(0);
    eprintln!(
        "  Daemon stopped. {} events recorded, {} on disk.",
        total,
        format_bytes(size),
    );
    Ok(())
}

enum ShutdownReason {
    Signal,
    Disconnected,
}

/// Run a single gateway connection session, writing events to the ledger.
/// Returns the shutdown reason so the caller can decide whether to reconnect.
async fn run_connection(
    config: &Config,
    ledger: Arc<Mutex<Ledger>>,
    pb: &ProgressBar,
    shutdown: &Arc<AtomicBool>,
) -> Result<ShutdownReason> {
    let auth_token = config.auth_token.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "No auth token provided. Use --token or set gateway.auth.token in ~/.openclaw/openclaw.json"
        )
    })?;
    let mut client = GatewayClient::new(&config.gateway_url, auth_token)?;
    let conn_id = client.connect().await?;

    info!("Daemon connected to gateway, connId: {}", conn_id);
    pb.set_message("Connected. Recording...");

    // Spawn gateway event reader, track the task handle
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<GatewayEvent>(1000);
    let handle = tokio::spawn(async move {
        if let Err(e) = client.run(event_tx).await {
            error!("Gateway event loop ended: {}", e);
        }
    });

    let run_id = RunId("daemon".to_string());
    let mut flush_interval = interval(Duration::from_millis(config.flush_interval_ms));
    let mut cryptowerk_flush_interval = interval(Duration::from_secs(CRYPTOWERK_EVENT_FLUSH_SECS));
    let mut cryptowerk_retry_interval = interval(Duration::from_secs(CRYPTOWERK_RETRY_SECS));
    // Poll shutdown flag every second
    let mut shutdown_check = interval(Duration::from_secs(1));
    let mut pending_cryptowerk_events: Vec<Event> = Vec::new();

    let result = loop {
        tokio::select! {
            msg = event_rx.recv() => {
                match msg {
                    Some(gw_event) => {
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
                            EventId(0), // ledger assigns the real ID
                            gw_event,
                            config.redact_secrets,
                        );

                        {
                            let mut l = ledger.lock().await;
                            match l.append_event_and_return(event) {
                                Ok(stored_event) => pending_cryptowerk_events.push(stored_event),
                                Err(e) => error!("Failed to write event: {}", e),
                            }
                        }

                        if pending_cryptowerk_events.len() >= CRYPTOWERK_EVENT_BATCH_SIZE {
                            flush_pending_event_cryptowerk_registrations(
                                ledger.clone(),
                                config.cryptowerk.clone(),
                                &mut pending_cryptowerk_events,
                            ).await;
                        }

                        let total = {
                            let l = ledger.lock().await;
                            l.total_events()
                        };

                        pb.set_message(format!(
                            "{} events | Last: {}",
                            total, kind_name
                        ));
                    }
                    None => {
                        break ShutdownReason::Disconnected;
                    }
                }
            }

            _ = cryptowerk_flush_interval.tick() => {
                flush_pending_event_cryptowerk_registrations(
                    ledger.clone(),
                    config.cryptowerk.clone(),
                    &mut pending_cryptowerk_events,
                ).await;
            }

            _ = cryptowerk_retry_interval.tick() => {
                retry_unresolved_event_cryptowerk_registrations(
                    ledger.clone(),
                    config.cryptowerk.clone(),
                ).await;
            }

            _ = flush_interval.tick() => {
                let mut l = ledger.lock().await;
                if let Err(e) = l.flush() {
                    error!("Failed to flush: {}", e);
                }
            }

            _ = shutdown_check.tick() => {
                if shutdown.load(Ordering::SeqCst) {
                    break ShutdownReason::Signal;
                }
            }
        }
    };

    flush_pending_event_cryptowerk_registrations(
        ledger.clone(),
        config.cryptowerk.clone(),
        &mut pending_cryptowerk_events,
    ).await;
    retry_unresolved_event_cryptowerk_registrations(ledger.clone(), config.cryptowerk.clone()).await;

    // Abort the spawned gateway reader to avoid leaking tasks
    handle.abort();

    Ok(result)
}

async fn flush_pending_event_cryptowerk_registrations(
    ledger: Arc<Mutex<Ledger>>,
    cryptowerk: Option<crate::proof::CryptowerkConfig>,
    pending_events: &mut Vec<Event>,
) {
    if cryptowerk.is_none() || pending_events.is_empty() {
        return;
    }

    let events = std::mem::take(pending_events);
    let event_ids: Vec<EventId> = events.iter().map(|event| event.event_id).collect();
    let hashes: Vec<String> = events.iter().map(|event| event.hash_self.clone()).collect();

    let result = tokio::task::spawn_blocking(move || {
        let anchor = build_run_anchor(cryptowerk);
        anchor.anchor_hashes(&hashes)
    })
    .await;

    let proofs = match result {
        Ok(Ok(proofs)) => proofs,
        Ok(Err(error)) => {
            let failure = cryptowerk_failure(error.to_string());
            let mut ledger = ledger.lock().await;
            for event_id in event_ids {
                if let Err(write_error) = ledger.write_event_cryptowerk_proof(event_id, &failure) {
                    warn!(
                        "Failed to persist Cryptowerk daemon event error metadata for event {}: {}",
                        event_id.0, write_error
                    );
                }
            }
            return;
        }
        Err(join_error) => {
            let failure = cryptowerk_failure(join_error.to_string());
            let mut ledger = ledger.lock().await;
            for event_id in event_ids {
                if let Err(write_error) = ledger.write_event_cryptowerk_proof(event_id, &failure) {
                    warn!(
                        "Failed to persist Cryptowerk daemon event join-error metadata for event {}: {}",
                        event_id.0, write_error
                    );
                }
            }
            return;
        }
    };

    let mut ledger = ledger.lock().await;
    for (event_id, proof) in event_ids.into_iter().zip(proofs.into_iter()) {
        let Some(proof) = proof else {
            continue;
        };
        if let Err(write_error) = ledger.write_event_cryptowerk_proof(event_id, &proof) {
            warn!(
                "Failed to persist Cryptowerk daemon event metadata for event {}: {}",
                event_id.0, write_error
            );
        }
    }
}

async fn retry_unresolved_event_cryptowerk_registrations(
    ledger: Arc<Mutex<Ledger>>,
    cryptowerk: Option<crate::proof::CryptowerkConfig>,
) {
    let Some(config) = cryptowerk else {
        return;
    };
    if !config.is_configured() {
        return;
    }

    let unresolved_events = {
        let ledger = ledger.lock().await;
        match ledger.list_cryptowerk_proofs(None, None, true, CRYPTOWERK_RETRY_BATCH_SIZE) {
            Ok(rows) => rows
                .into_iter()
                .filter_map(|row| {
                    row.event
                        .cryptowerk
                        .as_ref()
                        .and_then(|proof| proof.retrieval_id.as_ref())
                        .filter(|value| !value.trim().is_empty())
                        .map(|_| None)
                        .unwrap_or(Some(row.event))
                })
                .collect::<Vec<_>>(),
            Err(error) => {
                warn!(
                    "Failed to load unresolved Cryptowerk daemon proofs for retry: {}",
                    error
                );
                return;
            }
        }
    };

    if unresolved_events.is_empty() {
        return;
    }

    info!(
        "Retrying {} unresolved Cryptowerk daemon proof rows",
        unresolved_events.len()
    );

    let event_ids: Vec<EventId> = unresolved_events.iter().map(|event| event.event_id).collect();
    let hashes: Vec<String> = unresolved_events
        .iter()
        .map(|event| event.hash_self.clone())
        .collect();

    let result = tokio::task::spawn_blocking(move || {
        let anchor = build_run_anchor(Some(config));
        anchor.anchor_hashes(&hashes)
    })
    .await;

    let proofs = match result {
        Ok(Ok(proofs)) => proofs,
        Ok(Err(error)) => {
            let failure = cryptowerk_failure(error.to_string());
            let mut ledger = ledger.lock().await;
            for event_id in event_ids {
                if let Err(write_error) = ledger.write_event_cryptowerk_proof(event_id, &failure) {
                    warn!(
                        "Failed to persist Cryptowerk daemon retry error metadata for event {}: {}",
                        event_id.0, write_error
                    );
                }
            }
            return;
        }
        Err(join_error) => {
            let failure = cryptowerk_failure(join_error.to_string());
            let mut ledger = ledger.lock().await;
            for event_id in event_ids {
                if let Err(write_error) = ledger.write_event_cryptowerk_proof(event_id, &failure) {
                    warn!(
                        "Failed to persist Cryptowerk daemon retry join-error metadata for event {}: {}",
                        event_id.0, write_error
                    );
                }
            }
            return;
        }
    };

    let mut ledger = ledger.lock().await;
    for (event_id, proof) in event_ids.into_iter().zip(proofs.into_iter()) {
        let Some(proof) = proof else {
            continue;
        };
        if let Err(write_error) = ledger.write_event_cryptowerk_proof(event_id, &proof) {
            warn!(
                "Failed to persist Cryptowerk daemon retry metadata for event {}: {}",
                event_id.0, write_error
            );
        }
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
