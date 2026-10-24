# 🛡️ cipher-sec — Zero-Trust Semantic Firewall & WAF

[![Language](https://img.shields.io/badge/Language-Go%201.24-00ADD8?style=flat-square&logo=go)](https://go.dev/)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=flat-square)](#)
[![Latency](https://img.shields.io/badge/Latency-%3C1.5ms-success?style=flat-square)](#)

A high-performance security interceptor and semantic reverse proxy written in Go. Guards upstream LLMs, databases, and execution engines against destructive commands, prompt injection, and credential leakage with sub-2ms latency.

---

### 💡 For Non-Techies: What does this do?
> Think of `cipher-sec` as a security guard standing in front of your AI.
>
> When you use an AI tool, it's dangerously easy for private passwords, AWS keys, or credit cards to accidentally get sent to cloud servers. It's also possible for an AI to try to run destructive commands (like accidentally wiping your hard drive).
>
> `cipher-sec` inspects every message in **under 2 milliseconds**:
> - **Redacts passwords**: If it sees an AWS key or token, it blacks it out with `[REDACTED_BY_CIPHER_SEC]`.
> - **Blocks destructive commands**: If a command contains disk-wiping instructions like `rm -rf /`, it blocks it on the spot with a `403 Forbidden` error.

---

## Core Security Intercepts

1. **Destructive Command Rejection**:
   - Rejects payloads containing `rm -rf`, `mkfs`, fork bombs (`:(){ :|:& };:`), or `dd if=/dev/zero`.
   - Returns immediate `HTTP 403 Forbidden` before the command reaches the sandbox.
2. **Shannon Entropy & Secret Redaction**:
   - Matches known API key formats (AWS `AKIA...`, OpenAI `sk-...`, GitHub `ghp_...`, Slack, JWTs).
   - Computes Shannon entropy on string tokens; high-entropy tokens are automatically sanitized.
   - Replaces leaked tokens with `[REDACTED_BY_CIPHER_SEC]`.
3. **Bi-Directional Inspection**:
   - Protects inbound prompts to sandboxes.
   - Protects outbound model responses from leaking keys to external clients.

---

## Quickstart

### Build Standalone Binary
```bash
go build -o cipher-sec .
```

### Run Standalone
```bash
./cipher-sec -port 8079 -socket /tmp/cipher/sec.sock
```

### Inspect a Prompt
```bash
curl -X POST http://localhost:8079/inspect \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Deploy instance with AWS key AKIAIOSFODNN7EXAMPLE now"}'
```
*Response:*
```json
{
  "redacted": true,
  "sanitized": "Deploy instance with AWS key [REDACTED_BY_CIPHER_SEC] now",
  "threat_level": "CRITICAL_SECRET_LEAK"
}
```

---

## License
MIT © [Shlok Tiwari](https://github.com/sshloktiwarii)
