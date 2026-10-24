# cipher-sec

High-performance semantic firewall and credential redaction proxy.

Written in pure Go. Evaluates incoming prompts and outbound model responses for credential leakage (Shannon entropy analysis and regex signatures) and destructive commands, operating with sub-2ms latency.

---

## Detection Capabilities

1. **Destructive Command Interception**:
   - Rejects inputs containing `rm -rf`, `mkfs`, fork bombs (`:(){ :|:& };:`), or `dd if=/dev/zero`.
   - Returns immediate `HTTP 403 Forbidden` prior to execution dispatch.
2. **Entropy and Regex Credential Redaction**:
   - Matches known API token patterns (AWS `AKIA...`, OpenAI `sk-...`, GitHub `ghp_...`, Slack, JWTs).
   - Computes Shannon entropy on alphanumeric tokens; strings exceeding entropy thresholds are redacted.
   - Replaces matched secrets with `[REDACTED_BY_CIPHER_SEC]`.
3. **Bi-Directional Filtering**:
   - Ingress filtering prevents credential injection into execution sandboxes.
   - Egress filtering prevents model completions from emitting sensitive tokens to clients.

---

## Build

```bash
go build -o cipher-sec .
```

---

## Usage

```bash
./cipher-sec -port 8079 -socket /tmp/cipher/sec.sock
```

### Endpoint: `POST /inspect`

Request:
```json
{
  "prompt": "Deploy instance with AWS key AKIAIOSFODNN7EXAMPLE now"
}
```

Response:
```json
{
  "redacted": true,
  "sanitized": "Deploy instance with AWS key [REDACTED_BY_CIPHER_SEC] now",
  "threat_level": "CRITICAL_SECRET_LEAK"
}
```

---

## License

MIT License. Copyright (c) 2026 Shlok Tiwari.
