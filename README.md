# Canary Token Generator

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

> **Difficulty:** Beginner | **Language:** Go | **No external dependencies**

Self-hosted honeytoken system that generates trackable URLs and file tokens, and fires webhook callbacks (Slack, Discord, etc.) when they are accessed. Any access to a canary token is an anomaly — useful for detecting insider threats, network intruders, and credential theft. Zero third-party dependencies; single binary.

---

## Project Structure

```
11-canary-token-generator/
├── README.md
├── .gitignore
├── src/
│   ├── canary.go         ← Token store, HTTP server, generation, CLI
│   ├── canary_test.go    ← Go test suite
│   └── go.mod
└── docs/
    └── NOTES.md
```

---

## Build

```bash
cd src
go build -o canary .
```

---

## Usage

### Start the server

```bash
# Basic (port 8080, no webhook)
./canary server

# With Slack webhook and public URL
./canary server --port 8080 \
  --webhook "https://hooks.slack.com/services/..." \
  --base-url "https://your-server.example.com"
```

### Generate tokens

```bash
# URL token — give this link to monitor who opens it
./canary generate url --label "HR budget spreadsheet link" --base-url http://localhost:8080

# File token — drop this file on a network share as a trap
./canary generate file --label "payroll Q4 2026" --out-dir ./drops/
```

### List and view hits

```bash
# List all tokens
./canary list

# View all access records
./canary hits
```

---

**Example output:**
```
[*] Canary server listening on :8080
    Base URL : http://localhost:8080

[HIT] 2026-04-28T14:22:07Z  token=a1b2c3d4e5f6  ip=10.0.0.105  ua=Mozilla/5.0 ...
      label="HR budget spreadsheet link"
```

**Slack notification:**
```
🪤 Canary triggered!
• Token: a1b2c3d4e5f6...
• Label: HR budget spreadsheet link
• IP: 10.0.0.105
• Time: 2026-04-28T14:22:07Z
```

---

## How It Works

1. A unique 24-character random token ID is generated for each canary.
2. For URL tokens, the tracking endpoint is `http(s)://your-server/t/<id>`.
3. When that URL is hit (GET request), the server records the timestamp, IP, and User-Agent.
4. The server fires an async webhook POST to your notification endpoint.
5. The response is a 1×1 transparent GIF — the request completes silently.
6. All tokens and hits are persisted to `canaries.json`.

For file tokens, the text file contains the tracking URL — opening the file in a browser or email client loads the URL and triggers the callback.

---

## Run Tests

```bash
cd src
go test -v ./...
```

---

---

## Challenges & Extensions

- Add **DNS canary tokens** (authoritative DNS server that logs queries)
- Add **email canary** — a tracking pixel in an HTML email
- Add **API token canary** — detect when a stolen API key is used
- Add **token expiry** — auto-disable tokens after N days
- Build a **web dashboard** to view hits and generate tokens in a browser

---

## References

- [Canarytokens.org](https://canarytokens.org/)
- [Thinkst Canary — research blog](https://canarytokens.org/ideas)
- MITRE ATT&CK: [T1518 — Software Discovery](https://attack.mitre.org/techniques/T1518/) (honeytokens detect this)
- [Deception Technology — SANS whitepaper](https://www.sans.org/white-papers/38800/)

---

