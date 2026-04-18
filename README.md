---
title: TruClaw
description: Biometric guardrail for OpenClaw
env:
  - name: TRUKYC_RELAY_URL
    required: true
    description: Relay endpoint for pairing and approval delivery
  - name: ANTHROPIC_API_KEY_TRUKYC
    required: true
    description: Anthropic API key for tool-call risk classification
---

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

```bash
openclaw plugins install clawhub:truclaw
```

---

### 3. Configuration

Add the following to `~/.openclaw/openclaw.json` under the `"env"` key:

```json
{
  "env": {
    "ANTHROPIC_API_KEY_TRUKYC": "your-anthropic-api-key",
    "TRUKYC_RELAY_URL": "https://trukyc-relay.trusources.workers.dev"
  }
}
```

Add TruClaw to your OpenClaw configuration:

```json
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

---

### 4. Restart OpenClaw

Restart OpenClaw to load the plugin.

---

### 5. Pair your iPhone

Send this in any OpenClaw channel (Slack, iMessage, Telegram, etc.):

```text
/trukyc-pair
```

On your iPhone:

* Tap the pairing link
* TruClaw app opens automatically
* Pairing completes instantly

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

| Feature | OpenClaw /approve | TruClaw |
| :--- | :--- | :--- |
| Approval channel | Same session | Separate trusted device |
| Authentication | Manual | Human validation (paired device) |
| Replay resistance | Low | High (signed ephemeral JWTs) |
| Prompt injection safety | Limited | Strong (out-of-band approval) |
| Audit trail | Basic | Cryptographically signed events |

---

## Security Properties

* Secure Enclave-backed device keys
* Human validation via paired iPhone
* Out-of-band approval channel
* Tamper-proof signed audit events
* Prompt injection resistant execution guardrail
* Enterprise-ready alignment (EU AI Act, NIST AI RMF, SOC2 patterns)

---

## Trust & Data Flow

### Flow

OpenClaw -> TruClaw Plugin -> Relay -> Mobile Device (FCM/APNs)

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


## ⚠️ Relay & Data Flow

TruClaw requires a relay service to deliver approval requests to your paired device.

### Default behavior
By default, TruClaw uses a managed relay:
https://trukyc-relay.trusources.workers.dev

This relay receives:
- Tool-call metadata (actions being approved)
- Push notification tokens
- Ephemeral session identifiers

No biometric data or images are transmitted.

---


### Self-hosting (recommended for sensitive environments)

You may configure `TRUKYC_RELAY_URL` to point to your own relay.

A reference Cloudflare Worker implementation is included in this repository.

#### Requirements

- Cloudflare Worker
- KV namespace (for short-lived session state)
- Firebase service account (for FCM push delivery)

#### Setup (example)

```bash
wrangler kv:namespace create TRUKYC_KV
wrangler secret put FIREBASE_SERVICE_ACCOUNT < service-account.json
```


---

## Domain Usage

* `aasa.trusources.ai` -> Apple Universal Links only
* Does NOT handle authentication or relay traffic

---

## Local Data

Stored at:

```text
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
