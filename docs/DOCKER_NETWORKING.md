# 🌐 ZKTrace Docker Networking & Integration Guide

This guide details how to integrate the **ZKTrace Verifier Server** into your external projects and microservices using Docker without experiencing common network errors (such as `ECONNREFUSED`, connection timeouts, or DNS resolution failures).

---

## 📌 Summary of Network Rules

| Scenario | Target Endpoint URL | Requirements / Notes |
| :--- | :--- | :--- |
| **Inside the same Docker Compose** | `http://zktrace-verifier:8080` or `http://zktrace:8080` | Both services must share the same network. Use `condition: service_healthy`. |
| **From a separate Docker project / Compose** | `http://zktrace-verifier:8080` | Attach both compose stacks to a shared external Docker network. |
| **From Host Machine (Local Dev / CLI)** | `http://localhost:8080` or `http://127.0.0.1:8080` | Port must be published (`8080:8080`). |
| **From Container to Host Service** | `http://host.docker.internal:8080` | Requires `extra_hosts: ["host.docker.internal:host-gateway"]` on Linux. |

---

## 🛠️ Key Architectural Protections

1. **`0.0.0.0` Host Binding**: The server binds to `0.0.0.0` by default inside Docker, allowing requests from external containers and host port forwarding.
2. **Built-in `zktrace healthcheck`**: Distroless containers do not contain `curl` or `wget`. ZKTrace embeds a zero-dependency HTTP probe (`zktrace healthcheck`) so Docker native healthchecks and orchestrators can accurately track readiness.
3. **Graceful Shutdown**: The server listens for `SIGINT` (Ctrl+C) and `SIGTERM` signals, shutting down cleanly without hanging connections.

---

## 🚀 Integration Patterns

### Pattern 1: Same Docker Compose Stack (Recommended)

When running ZKTrace alongside your AI agent, web backend, or tool server in the same `docker-compose.yml`:

```yaml
version: "3.8"

services:
  # 1. ZKTrace Verifier Server
  zktrace-verifier:
    image: zktrace/zktrace:latest
    container_name: zktrace-verifier
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
      - ZKTRACE_HOST=0.0.0.0
      - ZKTRACE_PORT=8080
    command: ["serve", "--host", "0.0.0.0", "--port", "8080"]
    healthcheck:
      test: ["CMD", "/usr/local/bin/zktrace", "healthcheck", "--host", "127.0.0.1", "--port", "8080"]
      interval: 5s
      timeout: 3s
      retries: 5
      start_period: 3s
    networks:
      - app-net

  # 2. Your Application / AI Agent
  my-app:
    build: .
    depends_on:
      zktrace-verifier:
        condition: service_healthy # 💡 Waits until ZKTrace is 100% ready before starting your app
    environment:
      - ZKTRACE_VERIFIER_URL=http://zktrace-verifier:8080
    networks:
      - app-net

networks:
  app-net:
    driver: bridge
```

---

### Pattern 2: Separate Projects / Repositories (External Shared Network)

If ZKTrace runs in its own repository/compose file and your application runs in a separate compose file:

#### Step 1: Create a shared bridge network once
```bash
docker network create zktrace-shared-net
```

#### Step 2: ZKTrace `docker-compose.yml`
```yaml
version: "3.8"

services:
  zktrace-verifier:
    image: zktrace/zktrace:latest
    container_name: zktrace-verifier
    ports:
      - "8080:8080"
    networks:
      - zktrace-shared-net

networks:
  zktrace-shared-net:
    external: true
```

#### Step 3: Your Project's `docker-compose.yml`
```yaml
version: "3.8"

services:
  my-external-service:
    build: .
    environment:
      - ZKTRACE_URL=http://zktrace-verifier:8080
    networks:
      - zktrace-shared-net

networks:
  zktrace-shared-net:
    external: true
```

---

### Pattern 3: Hybrid Setup (App on Host, ZKTrace in Docker or vice versa)

#### Case A: App on Host Machine calling ZKTrace in Docker
Your application connects directly to:
```text
http://localhost:8080/v1/verify
```

#### Case B: App inside Docker calling ZKTrace running directly on Host
In your app's `docker-compose.yml`, add `extra_hosts` and use `http://host.docker.internal:8080`:

```yaml
services:
  my-app:
    build: .
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - ZKTRACE_URL=http://host.docker.internal:8080
```

---

## 💻 Client Integration Code Examples (With Retry Logic)

### Python (using `requests` & `urllib3`)
```python
import os
import time
import requests

ZKTRACE_URL = os.getenv("ZKTRACE_VERIFIER_URL", "http://zktrace-verifier:8080")

def wait_for_zktrace(timeout_sec=15):
    """Wait for ZKTrace to become ready before sending verification requests."""
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            res = requests.get(f"{ZKTRACE_URL}/health", timeout=2)
            if res.status_code == 200:
                print("Connected to ZKTrace Verifier successfully.")
                return True
        except requests.exceptions.RequestException:
            time.sleep(0.5)
    raise RuntimeError(f"Could not connect to ZKTrace Verifier at {ZKTRACE_URL}")

def verify_audit_receipt(receipt_data: dict) -> dict:
    url = f"{ZKTRACE_URL}/v1/verify"
    response = requests.post(url, json=receipt_data, timeout=5)
    response.raise_for_status()
    return response.json()
```

### TypeScript / Node.js (`fetch` / `axios`)
```typescript
import axios from 'axios';

const ZKTRACE_URL = process.env.ZKTRACE_VERIFIER_URL || 'http://zktrace-verifier:8080';

export async function verifyReceipt(receiptJson: object) {
  const response = await axios.post(`${ZKTRACE_URL}/v1/verify`, receiptJson, {
    timeout: 5000,
    headers: { 'Content-Type': 'application/json' }
  });
  return response.data;
}
```

### Go
```go
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"time"
)

func verifyReceipt(payload []byte) (*http.Response, error) {
	baseURL := os.Getenv("ZKTRACE_VERIFIER_URL")
	if baseURL == "" {
		baseURL = "http://zktrace-verifier:8080"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	return client.Post(fmt.Sprintf("%s/v1/verify", baseURL), "application/json", bytes.NewBuffer(payload))
}
```

---

## ⚙️ Environment Variables Reference

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `ZKTRACE_HOST` | `0.0.0.0` | Listening network interface/IP inside the container. |
| `ZKTRACE_PORT` | `8080` | Listening HTTP port. |
| `RUST_LOG` | `info` | Log verbosity (`error`, `warn`, `info`, `debug`, `trace`). |
| `ZKTRACE_DATA_DIR` | `/data` | Ledger checkpoints and persistent proof receipts volume. |
