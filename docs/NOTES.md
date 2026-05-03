# Architecture Notes — Canary Token Generator

## What is a canary token / honeytoken?

A honeytoken is a resource (URL, file, credential, DNS name) that has no
legitimate use. Any access is therefore an anomaly — an insider threat,
an intruder who found the file, or an attacker using stolen credentials.

The canonical commercial implementation is canarytokens.org (Thinkst Canary).
This project is a self-hosted educational version.

## Store design

Tokens are persisted to a JSON file (`canaries.json`). An RWMutex protects
concurrent reads vs. writes. Save happens on every mutation — acceptable for
an educational tool where token creation is infrequent.

In production you would use a proper database (SQLite or Postgres) and a
connection pool, but JSON is self-contained and zero-dependency.

## HTTP server

A single `ServeHTTP` method handles all routes:
- `/t/<id>` — token hit (GET from any client)
- `/status` — health check (JSON)

The server returns a 1×1 transparent GIF on a valid hit. This allows a
URL token to be embedded as an `<img src="...">` tag in a document — the
image loads silently in any email client or browser, triggering the callback
without the victim knowing.

## Webhook delivery

Webhook calls happen in a goroutine so they do not block the HTTP response.
If the webhook endpoint is slow or down, the hit is already recorded in the
store before the goroutine fires.

## Token ID generation

`crypto/rand.Read` fills 12 bytes → 24 hex chars. This gives 96 bits of
randomness — sufficient to prevent enumeration attacks on the `/t/` endpoint.

## File tokens

A file token is a plain text file containing the token ID and a note.
When dropped on a network share, email attachment, or file server, any user
who opens it — and an attacker who exfiltrates and opens it — can be tracked.
The embedded tracking URL means the act of opening the file (in a browser or
email client) triggers the callback.
