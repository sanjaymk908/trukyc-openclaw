# TruClaw

**Biometric guardrail for OpenClaw.**
Intercept sensitive tool calls and require **human validation on a paired iPhone** before execution.

---

## 🎬 Demo

Main demo:

https://youtube.com/shorts/YJ6W6gcMNew

Enrollment + verification demo:

https://youtu.be/9qI_pPATIjs

---

## Prerequisites

* OpenClaw 3.28+
* Node.js 18+
* Anthropic API key
* TruClaw iOS app installed on iPhone

---

## Installation

### 1. Install TruClaw iOS app and enroll

Search **"TruClaw"** on the App Store.

Complete one-time enrollment:

* Take a selfie
* Scan your Driver’s License or Passport
* Green badge = enrolled

---

### 2. Install plugin via ClawHub

```bash id="i0clh1"
openclaw plugins install clawhub:truclaw
```

---

### 3. Configure OpenClaw plugin

Add TruClaw to your OpenClaw configuration:

```json id="cfg01"
{
  "plugins": {
    "entries": {
      "truclaw": {
        "enabled": true,
        "config": {
          "TRUKYC_RELAY_URL": "https://trukyc-relay.trusources.workers.dev",
          "ANTHROPIC_API_KEY_TRUKYC": "your-anthropic-api-key"
        }
      }
    }
  }
}
```

No shell environment variables are required.

---

### 4. Restart OpenClaw

Restart OpenClaw to load the plugin.

---

### 5. Pair your iPhone

Send this in any OpenClaw channel (Slack, iMessage, Telegram, etc.):

```text id="pair01"
/trukyc-pair
```

On your iPhone:

* Tap the pairing link
* TruClaw app opens automatically
* Pairing completes instantly

---

### 6. (Optional) Manual plugin load

If the plugin does not auto-load, ensure:

```text id="cfgpath"
~/.openclaw/openclaw.json
```

contains:

```json id="cfg02"
{
  "plugins": {
    "load": {
      "paths": [
        "/path/to/truclaw"
      ]
    },
    "entries": {
      "truclaw": {
        "enabled": true,
        "config": {
          "TRUKYC_RELAY_URL": "https://trukyc-relay.trusources.workers.dev",
          "ANTHROPIC_API_KEY_TRUKYC": "your-anthropic-api-key"
        }
      }
    }
  }
}
```

Then restart OpenClaw.

---

## How It Works

TruClaw uses Claude Haiku to classify tool calls in real time and enforce **human validation** for sensitive actions.

---

### Flagged as dangerous

* Shell commands that write, delete, or modify (`rm`, `mv`, `cp`)
* Network requests that send data (`curl POST`)
* Installing software (`pip install`, `npm install`)
* Sending messages, emails, or executing financial actions

---

### Always safe (no challenge)

* Read-only shell commands (`ls`, `cat`, `grep`, `find`)
* Querying data or answering questions
* Git read operations (`git status`, `git log`, `git diff`)
* Explicitly safe tools: `read`, `ls`, `list`, `session_status`, `memory_search`

---

## Feature Comparison

| Feature                 | OpenClaw `/approve` | TruClaw                          |
| ----------------------- | ------------------- | -------------------------------- |
| Approval channel        | Same session        | Separate trusted device          |
| Authentication          | Manual              | Human validation (paired device) |
| Replay resistance       | Low                 | High (signed ephemeral JWTs)     |
| Prompt injection safety | Limited             | Strong (out-of-band approval)    |
| Audit trail             | Basic               | Cryptographically signed events  |

---

## Security Properties

* Secure Enclave–backed device keys
* Human validation via paired iPhone
* Out-of-band approval channel
* Tamper-proof signed audit events
* Prompt injection resistant execution guardrail
* Enterprise-ready alignment (EU AI Act, NIST AI RMF, SOC2 patterns)

---

## Trust & Data Flow

### Flow

OpenClaw → TruClaw Plugin → Relay → Mobile Device (FCM/APNs)

### What data is transmitted

* Device push tokens (FCM/APNs)
* Session identifiers (ephemeral)
* Tool call metadata (action being approved)
* Signed approval JWTs

### What is NOT transmitted

* Face images
* Biometric data
* Private keys (stored in Secure Enclave)

---

## Default Relay Behavior

TruClaw includes a **managed relay by default**:

```
https://trukyc-relay.trusources.workers.dev
```

This allows instant setup without requiring infrastructure configuration.

Advanced users may override this by changing `TRUKYC_RELAY_URL`.

---

## Domain Usage

* `aasa.trusources.ai` → Apple Universal Links only
* Does NOT handle authentication or relay traffic

---

## Local Data

Stored at:

```text id="local01"
~/.openclaw/devices/paired.json
```

Includes:

* Device public key
* Push notification tokens

No biometric data is stored or transmitted.

---

## Privacy

* Human validation happens on-device
* No images or biometric data leave the phone
* Secure Enclave protects cryptographic keys
* Relay stores only short-lived session state (~2 minutes)

---

## License

MIT

