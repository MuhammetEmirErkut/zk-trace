//! `zktrace serve` high-throughput HTTP REST API verifier server.

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use zktrace_core::types::receipt::AuditReceipt;
use zktrace_ledger::bundle::AuditBundle;
use zktrace_prover::setup::ProverKeys;
use zktrace_verifier::engine::ZKTraceVerifier;

struct AppState {
    verifier: ZKTraceVerifier,
}

/// Launches the high-throughput HTTP REST API verifier daemon.
pub async fn execute_server(host: &str, port: u16, vk_path: Option<&Path>) -> Result<()> {
    let vk = if let Some(vp) = vk_path {
        let mut vk_file =
            File::open(vp).with_context(|| format!("Failed to open VK file {:?}", vp))?;
        let mut vk_bytes = Vec::new();
        vk_file.read_to_end(&mut vk_bytes)?;
        ProverKeys::deserialize_vk(&vk_bytes).map_err(|e| anyhow::anyhow!("VK error: {}", e))?
    } else {
        let keys = ProverKeys::generate_deterministic(4)
            .map_err(|e| anyhow::anyhow!("Setup error: {}", e))?;
        keys.vk
    };

    let verifier = ZKTraceVerifier::new(vk);
    let state = Arc::new(AppState { verifier });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/v1/verify", post(verify_endpoint))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let bind_addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind TCP listener to {}", bind_addr))?;

    let local_addr = listener.local_addr()?;
    println!(
        "🚀 ZKTrace REST API Verifier Server listening on http://{}",
        local_addr
    );
    println!("   Endpoints:");
    println!("     GET  /health");
    println!("     POST /v1/verify (Audits single receipt or .zktrace bundle)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    println!("🛑 ZKTrace REST API Verifier Server stopped gracefully.");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => {
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            println!("\nReceived Ctrl+C, initiating graceful shutdown...");
        },
        _ = terminate => {
            println!("\nReceived SIGTERM, initiating graceful shutdown...");
        },
    }
}

async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "service": "zktrace-verifier-api",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn verify_endpoint(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    if let Ok(receipt) = serde_json::from_value::<AuditReceipt>(payload.clone()) {
        let report = state
            .verifier
            .verify_receipt(&receipt, None, None)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Verification error: {}", e),
                )
            })?;
        return Ok(Json(json!({
            "type": "single_receipt",
            "report": report
        })));
    }

    if let Ok(bundle) = serde_json::from_value::<AuditBundle>(payload) {
        let reports = state
            .verifier
            .verify_batch(&bundle.receipts, None, Some(&bundle.ledger_root))
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Batch verification error: {}", e),
                )
            })?;
        return Ok(Json(json!({
            "type": "bundle",
            "count": reports.len(),
            "reports": reports
        })));
    }

    Err((
        StatusCode::UNPROCESSABLE_ENTITY,
        "Invalid request payload: Expected AuditReceipt or AuditBundle JSON".to_string(),
    ))
}
