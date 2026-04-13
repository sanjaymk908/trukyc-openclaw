# TruClaw — Biometric Guardrail for OpenClaw

> Stop AI agents from executing dangerous actions without verified human authorization.

TruClaw integrates **OpenClaw agents** with the **TruClaw iOS app** to require **biometric human verification for risky agent actions** before they execute.

This allows developers and enterprises to safely run autonomous agents without risking unintended **financial transactions, infrastructure changes, or other high-impact actions**.

---

## Demo

Short demo showing the flow:

1. A harmless **check positions** command executes normally
2. A **sell order** triggers an approval notification on the iPhone
3. The trade executes only after **biometric verification in the TruClaw app**

[![Watch the demo](https://img.youtube.com/vi/YJ6W6gcMNew/0.jpg)](https://youtube.com/shorts/YJ6W6gcMNew)

---

## The Problem

AI agents with tool access can execute **real-world actions**:

* financial trades
* infrastructure changes
* database operations
* sending emails or messages

Without guardrails, a **hallucination, prompt injection, or tool misuse** could trigger these actions automatically.

TruClaw adds a strong safety primitive:

> **High-risk agent actions require biometric authorization on a trusted mobile device, backed by hardware attestation from the Secure Enclave.**

---

## TruClaw vs Native OpenClaw Approval

| | OpenClaw `/approve` | TruClaw Biometric |
|---|---|---|
| **Authorization method** | Text command in chat (`/approve <id>`) | Face ID on iPhone |
| **Proof of human** | None — any operator with channel access can approve | Secure Enclave-backed hardware attestation — cryptographically proves a live human authorized the action |
| **Attestation** | No hardware attestation | JWT signed by iPhone Secure Enclave — tamper-proof, device-bound, non-exportable |
| **Out-of-band** | Same channel as the agent | Separate trusted device |
| **Spoofable** | Yes — compromised chat account approves silently | No — requires physical device + live biometric |
| **Audit trail** | Chat message | Signed JWT with timestamp, liveness score, device ID |
| **Enterprise compliance** | ❌ No cryptographic proof | ✅ Hardware-attested human proof — maps to EU AI Act, NIST RMF, SOC2 |
| **Setup** | None | One-time enrollment with government-issued ID |
| **Best for** | Convenience approvals, low-risk actions | High-stakes actions, regulated environments, financial operations |

### Why hardware attestation matters

When TruClaw authorizes an action, the approval is not just a message — it is a **JWT signed by the iPhone's Secure Enclave**. The Secure Enclave is a dedicated security processor that:

* generates and stores the signing key in hardware — the key never leaves the device
* binds the key to the specific iPhone — cannot be copied or exported
* requires a live biometric match to use the key

This means every TruClaw authorization produces cryptographic proof that:
1. A specific enrolled human was physically present
2. On a specific trusted device
3. At a specific point in time

No chat account compromise, no prompt injection, no replay attack can forge this.

---

## How It Works

1. OpenClaw Agent detects a tool call
2. TruClaw Plugin intercepts via `before_tool_call` hook
3. Claude Haiku classifies the tool call as safe or dangerous
4. If dangerous → TruClaw Relay (Cloudflare Worker) sends push notification via Firebase Messaging
5. TruClaw iOS App receives the notification on your iPhone
6. User completes Face ID biometric match
7. iPhone Secure Enclave signs an authorization JWT — hardware-bound, tamper-proof
8. Plugin polls the relay, receives and verifies the JWT
9. `isAbove21=true` → action proceeds ✅ / `isAbove21=false` → action blocked ❌

---

## Prerequisites

* **OpenClaw 3.28+**
* **Node.js 18+**
* **Anthropic API key**
* **TruClaw iOS app installed on iPhone**

---

## Installation

### 1. Install TruClaw iOS app and enroll

Search "TruClaw" on the App Store. Complete one-time enrollment:
- Take a selfie
- Scan your Driver's License or Passport
- Green badge = enrolled

[![Watch onboarding demo](https://img.youtube.com/vi/9qI_pPATIjs/0.jpg)](https://youtu.be/9qI_pPATIjs)

### 2. Clone and build

```bash
git clone https://github.com/sanjaymk908/trukyc-openclaw.git
cd trukyc-openclaw/trukyc-handler
npm install
npm run build
```

### 3. Add plugin to `~/.openclaw/openclaw.json`

```json
"plugins": {
  "load": {
    "paths": [
      "/path/to/trukyc-openclaw/trukyc-handler"
    ]
  },
  "entries": {
    "truclaw": {
      "enabled": true,
      "config": {}
    }
  },
  "installs": {
    "truclaw": {
      "source": "path",
      "sourcePath": "/path/to/trukyc-openclaw/trukyc-handler",
      "installPath": "/path/to/trukyc-openclaw/trukyc-handler",
      "version": "1.0.0",
      "installedAt": "2026-03-20T21:50:28.059Z"
    }
  }
}
```

### 4. Add environment variables

```json
"env": {
  "TRUKYC_RELAY_URL": "https://trukyc-relay.trusources.workers.dev",
  "ANTHROPIC_API_KEY_TRUKYC": "your-anthropic-api-key"
}
```

### 5. Restart OpenClaw

```bash
openclaw gateway stop && sleep 3 && openclaw gateway install && sleep 5
openclaw plugins list | grep truclaw
```

### 6. Pair your iPhone

Send this in any OpenClaw channel (iMessage, Slack, Telegram, etc.):
/truclaw-pair

Tap the pairing link on your iPhone — the TruClaw app opens and confirms pairing automatically.

---

## Example Interaction

### Safe action — no approval needed
with trader skill check positions

### Risky action — biometric required
with trader skill buy NVDA at $165

Flow:

1. Agent attempts trade
2. TruClaw intercepts the tool call
3. Push notification sent to iPhone
4. User opens TruClaw and completes Face ID
5. Secure Enclave signs authorization JWT
6. Plugin verifies JWT → trade executes ✅

If the user **ignores the notification** — times out after 5 minutes → blocked ❌
If **Face ID fails** — blocked ❌

---

## Danger Classification

TruClaw uses Claude Haiku to classify every tool call in real time.

**Flagged as dangerous:**
- Shell commands that write, delete, or modify (`rm`, `mv`, `cp`)
- Network requests that send data (`curl POST`)
- Installing software (`pip install`, `npm install`)
- Sending messages, emails, or executing financial actions

**Always safe (no challenge):**
- Read-only shell commands (`ls`, `cat`, `grep`, `find`)
- Querying data or answering questions
- Git read operations (`git status`, `git log`, `git diff`)
- Explicitly safe tools: `read`, `ls`, `list`, `session_status`, `memory_search`

---

## Security Properties

* **Secure Enclave hardware attestation** — every authorization is cryptographically signed by the iPhone's dedicated security processor
* **Biometric binding** — the signing key is device-bound and requires a live Face ID match to use
* **Out-of-band approval** — authorization happens on a separate trusted device, not the same channel as the agent
* **Tamper-proof audit trail** — signed JWTs with timestamp, device ID, and liveness score
* **Prompt injection resistant** — no chat-based command can forge a biometric authorization
* **Enterprise compliance ready** — hardware attestation maps to EU AI Act Article 14 (human oversight), NIST AI RMF, and SOC2 access control requirements

---

## Privacy

- All face matching runs on-device using Apple's Vision framework
- No photos, selfies, or biometric data are stored or transmitted
- Only encrypted metadata (not images) stored in Secure Enclave
- Relay server stores only temporary session tokens (auto-deleted after 2 minutes)

---

## License

MIT
