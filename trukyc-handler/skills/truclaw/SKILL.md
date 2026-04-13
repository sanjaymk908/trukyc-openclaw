---
name: truclaw
description: Biometric guardrail for OpenClaw. Intercepts dangerous tool calls and requires Face ID verification via TruClaw iOS app before execution. Secure Enclave hardware attestation. No cloud. No compromise.
metadata: {"openclaw": {"emoji": "🔐", "homepage": "https://github.com/sanjaymk908/trukyc-openclaw", "requires": {"env": ["ANTHROPIC_API_KEY_TRUKYC"]}}}
---

# TruClaw — Biometric AI Guardrail

TruClaw stops your OpenClaw agent from executing dangerous actions without
verified human authorization. When a sensitive tool call is detected — deleting
files, sending messages, running shell commands — TruClaw sends a push
notification to your iPhone. Complete Face ID to authorize. Ignore it to block.

Every authorization is backed by a **Secure Enclave-signed JWT** — hardware
attestation that cryptographically proves a live human authorized the action
on a specific trusted device. No chat account compromise, no prompt injection,
no replay attack can forge this.

All biometric processing happens on-device. No photos or facial data ever
leave your iPhone.

---

## Plugin required

This skill is a companion to the TruClaw OpenClaw plugin. The skill alone
does nothing without the plugin installed.

Install the plugin first:
git clone https://github.com/sanjaymk908/trukyc-openclaw.git
cd trukyc-openclaw/trukyc-handler
npm install && npm run build

Then add to ~/.openclaw/openclaw.json plugins section:
"plugins": {
"load": {
"paths": ["/path/to/trukyc-openclaw/trukyc-handler"]
},
"entries": {
"truclaw": { "enabled": true, "config": {} }
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

Add env vars:
"env": {
"TRUKYC_RELAY_URL": "https://trukyc-relay.trusources.workers.dev",
"ANTHROPIC_API_KEY_TRUKYC": "your-anthropic-api-key"
}

Restart OpenClaw:
openclaw gateway stop && sleep 3 && openclaw gateway install && sleep 5
openclaw plugins list | grep truclaw

---

## Requirements

- OpenClaw 3.28+
- TruClaw iOS app (search "TruClaw" on App Store)
- Anthropic API key for Claude Haiku danger classification

---

## Setup (3 steps)

### Step 1 — Install TruClaw iOS app

Search "TruClaw" on the App Store. Complete one-time enrollment:
- Take a selfie
- Scan your Driver's License or Passport
- Green badge confirms successful enrollment

Your biometric profile is stored encrypted in your iPhone Secure Enclave.
Nobody can access or tamper with it.

### Step 2 — Install and configure plugin

See Plugin required section above.

### Step 3 — Pair your iPhone

Run this in any OpenClaw channel:
/truclaw-pair

A QR code appears. Scan it with the TruClaw iOS app. Done.

---

## How it works

1. OpenClaw Agent detects a tool call
2. TruClaw Plugin intercepts via before_tool_call hook
3. Claude Haiku classifies the tool call as safe or dangerous
4. If dangerous: TruClaw Relay sends push notification via Firebase Messaging
5. TruClaw iOS App receives notification on your iPhone
6. User completes Face ID biometric match
7. iPhone Secure Enclave signs authorization JWT — hardware-bound, tamper-proof
8. Plugin polls relay, receives and verifies JWT
9. isAbove21=true → action proceeds / isAbove21=false → action blocked

---

## TruClaw vs native OpenClaw approval

| | OpenClaw /approve | TruClaw Biometric |
|---|---|---|
| Authorization method | Text command in chat | Face ID on iPhone |
| Proof of human | None | Secure Enclave hardware attestation |
| Spoofable | Yes — compromised account approves | No — requires physical device + live biometric |
| Audit trail | Chat message | Signed JWT with timestamp and device ID |
| Enterprise compliance | No cryptographic proof | Hardware-attested human proof |

---

## What gets flagged as dangerous

- Shell commands that write, delete, or modify (rm, mv, cp)
- Network requests that send data (curl POST, wget)
- Installing software (pip install, npm install)
- Sending messages or emails
- Financial operations, killing processes, modifying permissions

## What passes through safely

- Read-only shell commands (ls, cat, grep, find)
- Querying data or answering questions
- Git read operations (git status, git log, git diff)
- Explicitly safe tools: read, ls, list, session_status, memory_search

---

## Privacy

- All face matching runs on-device using Apple Vision framework
- No photos, selfies, or biometric data stored or transmitted
- Only encrypted metadata stored in Secure Enclave
- Relay stores only temporary session tokens (auto-deleted after 2 minutes)
- Full source: https://github.com/sanjaymk908/trukyc-openclaw

