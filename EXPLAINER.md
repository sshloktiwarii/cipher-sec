# cipher-sec: The Plain-English Guide

## What does this do?

When people use AI coding tools, they frequently paste terminal output, database connection strings, or configuration files into the chat.

This leads to a major risk: **accidentally leaking private passwords and API keys.** If you paste a key into an AI chat, that key may get logged on third-party cloud servers or committed into public code.

`cipher-sec` is an automated security filter that checks text in less than 2 milliseconds:
* **Catches and blacks out passwords:** It scans for known key formats (like AWS keys, OpenAI keys, GitHub tokens, and database passwords). It replaces them with `[REDACTED_BY_CIPHER_SEC]` before any model sees them.
* **Blocks destructive commands:** If an AI model attempts to run a dangerous command that would wipe your hard drive (such as `rm -rf /` or formatting a disk), `cipher-sec` rejects the request immediately.
* **Checks both directions:** It checks what you send to the AI, and it checks what the AI sends back to make sure private information is never exposed.

---

## What happens if I don't use this?

Without a filter like `cipher-sec`, any API token you copy and paste into a prompt is sent raw over the network. If an AI generates a command that deletes files, there is nothing stopping your computer from executing that command.

---

## Frequently Asked Questions

#### Does this check my files in the background?
No. It only inspects the text that you or your AI agent actively send through the system.

#### Will this slow down my prompts?
No. The scan completes in under 2 milliseconds, which is imperceptible to human perception.

#### How do I run it?
In the full Cipher system, `cipher appliance` runs `cipher-sec` automatically. To run it alone:
```bash
./cipher-sec -port 8079
```
