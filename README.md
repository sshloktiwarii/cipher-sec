# Foundry Sentinel: The Zero-Trust Semantic Firewall

A high-performance security interceptor and semantic reverse proxy written in Go that guards upstream LLMs and execution engines against hallucinated destructive actions and credential leakage.

## Core Security Intercepts
1. **Destructive Command Rejection**:
   - Rejects payloads containing `rm -rf`, `mkfs`, `> /dev/sda`, fork bombs (`:(){ :|:& };:`), or `dd if=/dev/zero`.
   - Returns immediate `HTTP 403 Forbidden` before the command reaches LLMs or sandboxes.
2. **Shannon Entropy & Regex Secret Redaction**:
   - Matches known API key formats (AWS `AKIA...`, OpenAI `sk-...`, GitHub `ghp_...`, Slack, JWTs).
   - Computes Shannon entropy on string tokens; high-entropy tokens are automatically sanitized.
   - Replaces leaked tokens with `[REDACTED_BY_SENTINEL]`.
3. **Bi-Directional Inspection**:
   - Inspects inbound requests to protect sandboxes.
   - Inspects outbound model responses to prevent LLMs from emitting sensitive keys to clients.
4. **Telemetry Ingestion Integration**:
   - Forwards threat alerts directly to `foundry-pulse` (`:8082/ingest`).

## Running Sentinel
```bash
go mod tidy
go run . --port 8079 --target http://localhost:8080
```
