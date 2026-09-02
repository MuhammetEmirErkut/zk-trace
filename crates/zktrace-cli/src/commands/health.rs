//! `zktrace healthcheck` command for container and service health monitoring.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Performs a lightweight HTTP GET probe to the `/health` endpoint.
///
/// Designed to run inside minimal Distroless / Scratch containers where `curl` or `wget` are unavailable.
pub async fn execute_healthcheck(host: &str, port: u16, timeout_ms: u64) -> Result<()> {
    let connect_timeout = Duration::from_millis(timeout_ms);

    // Resolve address (defaults to 127.0.0.1 for container internal checks)
    let addr_str = if host == "0.0.0.0" {
        format!("127.0.0.1:{}", port)
    } else {
        format!("{}:{}", host, port)
    };

    let socket_addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .with_context(|| format!("Failed to resolve target address: {}", addr_str))?
        .collect();

    if socket_addrs.is_empty() {
        bail!("Could not resolve socket address for {}", addr_str);
    }

    let socket_addr = socket_addrs[0];

    // Establish TCP connection with timeout
    let mut stream = match timeout(connect_timeout, TcpStream::connect(socket_addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            bail!(
                "Connection refused on {}: {} (Is ZKTrace server running?)",
                socket_addr,
                e
            );
        }
        Err(_) => {
            bail!("Connection timed out after {}ms on {}", timeout_ms, socket_addr);
        }
    };

    // Send HTTP/1.1 GET /health request
    let request = format!(
        "GET /health HTTP/1.1\r\nHost: {}\r\nUser-Agent: zktrace-healthcheck\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
        addr_str
    );

    timeout(connect_timeout, stream.write_all(request.as_bytes()))
        .await
        .context("Failed to send HTTP request (timeout)")?
        .context("Failed to write to TCP stream")?;

    timeout(connect_timeout, stream.flush())
        .await
        .context("Failed to flush TCP stream (timeout)")?
        .context("Flush failed")?;

    // Read response
    let mut response_buf = [0u8; 1024];
    let n = timeout(connect_timeout, stream.read(&mut response_buf))
        .await
        .context("Failed to read HTTP response (timeout)")?
        .context("Failed to read from TCP stream")?;

    if n == 0 {
        bail!("Server closed connection without sending any response");
    }

    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    if response_str.starts_with("HTTP/1.1 200") || response_str.starts_with("HTTP/1.0 200") {
        println!("✅ ZKTrace server is healthy ({})", socket_addr);
        Ok(())
    } else {
        let first_line = response_str.lines().next().unwrap_or("Unknown response");
        bail!(
            "Server returned unhealthy status on {}: {}",
            socket_addr,
            first_line
        );
    }
}
