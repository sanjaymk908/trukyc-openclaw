# TruKYC Guardrail for OpenClaw

> Stop AI agents from executing dangerous actions without human approval.

TruKYC integrates **OpenClaw agents** with the **TruClaw iOS app** to require **human validation for risky agent actions** before they execute.

This allows developers and enterprises to safely run autonomous agents without risking unintended **financial transactions, infrastructure changes, or other high-impact actions**.

---

# Demo

Short demo showing the flow:

1. A harmless **check positions** command executes normally
2. A **sell order** triggers an approval notification on the iPhone
3. The trade executes only after **human approval in the TruClaw app**

[![Watch the demo](https://img.youtube.com/vi/YJ6W6gcMNew/0.jpg)](sell-order-explain.mp4)

---

# The Problem

AI agents with tool access can execute **real-world actions**:

* financial trades
* infrastructure changes
* database operations
* sending emails or messages

Without guardrails, a **hallucination, prompt injection, or tool misuse** could trigger these actions automatically.

TruClaw adds a simple safety primitive:

> **High-risk agent actions require approval on a trusted mobile device.**

---

# How It Works

```
OpenClaw Agent
      │
      │ risky action detected
      ▼
TruKYC Plugin (trukyc-handler)
      │
      ▼
TruKYC Relay (Cloudflare Worker)
      │
      ▼
TruClaw iOS App
      │
      │ human approval
      ▼
Action allowed / denied
```

This ensures:

* agents **cannot silently execute dangerous actions**
* the **human stays in the loop**
* approvals happen **out-of-band on a trusted device**

---

# Prerequisites

Before installing the plugin you will need:

* **OpenClaw 3.28+**
* **Node.js 18+**
* **Anthropic API key**
* **TruClaw iOS app installed on an iPhone**

---

# Installation

## 1. Clone the repository

```bash
git clone https://github.com/sanjaymk908/trukyc-openclaw.git
cd trukyc-openclaw/trukyc-handler
```

---

## 2. Install dependencies and build

```bash
npm install
npm run build
```

---

## 3. Add plugin to `openclaw.json`

Add the plugin path:

```json
"plugins": {
  "load": {
    "paths": [
      "/path/to/trukyc-openclaw/trukyc-handler"
    ]
  },
  "entries": {
    "trukyc-pairing": {
      "enabled": true,
      "config": {}
    }
  },
  "installs": {
    "trukyc-pairing": {
      "source": "path",
      "sourcePath": "/path/to/trukyc-openclaw/trukyc-handler",
      "installPath": "/path/to/trukyc-openclaw/trukyc-handler",
      "version": "1.0.0",
      "installedAt": "2026-03-20T21:50:28.059Z"
    }
  }
}
```

---

## 4. Add environment variables

Add these to the `env` section of `openclaw.json`:

```json
"env": {
  "TRUKYC_RELAY_URL": "https://trukyc-relay.trusources.workers.dev",
  "ANTHROPIC_API_KEY_TRUKYC": "your-anthropic-api-key"
}
```

---

## 5. Restart OpenClaw

```bash
openclaw gateway stop
sleep 3
openclaw gateway install
sleep 5
```

---

## 6. Verify plugin loaded

```bash
openclaw plugins list | grep TruKYC
```

---

## 7. Pair your iPhone

Send the pairing command:

```
/trukyc-pair
```

Then:

1. Tap the pairing link on your iPhone
2. Open it with the **TruClaw app**
3. Confirm pairing

Your device is now registered as an **approval authority**.

---

# Example Interaction

### Safe Action (No Approval Required)

```
check positions
```

In some OpenClaw setups the first invocation may need to explicitly reference the skill:

```
with trader skill check positions
```

---

### Risky Action (Approval Required)

```
sell 10 NVDA
```

or

```
with trader skill sell 10 NVDA
```

Flow:

1. Agent attempts trade
2. TruKYC intercepts the action
3. Approval request sent to the TruClaw iPhone app
4. User approves the request
5. Trade executes

If the user **denies the request**, the action is **blocked**.

---

# Security Properties

TruClaw helps protect against:

* agent hallucinations executing dangerous commands
* prompt injection triggering tool misuse
* unintended autonomous financial actions
* unauthorized automation

Key properties:

* **human-in-the-loop validation**
* **out-of-band approval channel**
* **trusted mobile device authorization**

---

# License

MIT

---
