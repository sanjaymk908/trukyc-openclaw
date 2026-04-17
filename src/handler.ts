import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { randomBytes } from "node:crypto";

const POLL_INTERVAL_MS_START = 500;
const POLL_INTERVAL_MS_MAX   = 3000;
const POLL_BACKOFF_FACTOR     = 1.5;
const POLL_TIMEOUT_MS         = 300_000; // 5 min

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function getRelayUrl(): string {
  const url = process.env.TRUKYC_RELAY_URL ?? "";
  if (!url) throw new Error("TRUKYC_RELAY_URL not set");
  return url;
}

export async function pollForPairing(sessionId: string): Promise<{
  publicKey: string;
  apnsToken: string;
  fcmToken:  string;
  platform:  string;
} | null> {
  const relayUrl = getRelayUrl();
  const url = `${relayUrl}/pair-poll/${sessionId}`;
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  let interval = POLL_INTERVAL_MS_START;
  let attempts = 0;

  console.log(`[TruKYC:pair] Starting relay poll url=${url} timeout=5min`);

  while (Date.now() < deadline) {
    attempts++;
    const remaining = Math.round((deadline - Date.now()) / 1000);

    try {
      const resp = await fetch(url, {
        signal: AbortSignal.timeout(5000),
      });

      if (resp.status === 200) {
        const data = await resp.json() as {
          sessionId: string;
          publicKey: string;
          apnsToken: string;
          fcmToken:  string;
          platform:  string;
        };
        console.log(`[TruKYC:pair] ✅ Pairing received — attempts=${attempts} sessionId=${sessionId}`);
        console.log(`[TruKYC:pair] publicKey=${data.publicKey.slice(0, 16)}...`);
        console.log(`[TruKYC:pair] apnsToken=${data.apnsToken.slice(0, 8)}...`);
        console.log(`[TruKYC:pair] fcmToken=${data.fcmToken.slice(0, 20)}...`);
        console.log(`[TruKYC:pair] platform=${data.platform}`);
        return data;
      }

      if (resp.status === 202) {
        console.log(`[TruKYC:pair] Pending — attempt=${attempts} interval=${interval}ms remaining=${remaining}s`);
      } else {
        console.warn(`[TruKYC:pair] Unexpected status=${resp.status} attempt=${attempts}`);
      }
    } catch (err) {
      console.warn(`[TruKYC:pair] Fetch error attempt=${attempts}: ${err}`);
    }

    await sleep(interval);
    interval = Math.min(interval * POLL_BACKOFF_FACTOR, POLL_INTERVAL_MS_MAX);
  }

  console.error(`[TruKYC:pair] ⏱ Poll timeout after ${attempts} attempts sessionId=${sessionId}`);
  return null;
}

export async function savePairedDevice(
  sessionId: string,
  data: { publicKey: string; apnsToken: string; fcmToken: string; platform: string },
): Promise<void> {
  const storagePath = path.join(os.homedir(), ".openclaw/devices/paired.json");
  fs.mkdirSync(path.dirname(storagePath), { recursive: true });

  let devices: Record<string, unknown> = {};
  try {
    devices = JSON.parse(fs.readFileSync(storagePath, "utf8"));
    console.log(`[TruKYC:pair] Existing devices count=${Object.keys(devices).length}`);
  } catch {
    console.log(`[TruKYC:pair] No existing paired.json — starting fresh`);
  }

  if (devices[sessionId]) {
    console.log(`[TruKYC:pair] Already paired sessionId=${sessionId} — skipping`);
    return;
  }

  devices[sessionId] = {
    publicKey: data.publicKey,
    apnsToken: data.apnsToken,
    fcmToken:  data.fcmToken,
    platform:  data.platform,
    pairedAt:  new Date().toISOString(),
  };

  fs.writeFileSync(storagePath, JSON.stringify(devices, null, 2));
  console.log(`[TruKYC:pair] ✅ Saved sessionId=${sessionId} fcmToken=${data.fcmToken.slice(0, 20)}... total=${Object.keys(devices).length}`);
}

export async function handlePairCommand(): Promise<string> {
  console.log(`[TruKYC:pair] ── /trukyc-pair command invoked ──`);

  let relayUrl: string;
  try {
    relayUrl = getRelayUrl();
  } catch (err) {
    console.error(`[TruKYC:pair] ❌ ${err}`);
    return `❌ TRUKYC_RELAY_URL is not configured. Add it to ~/.openclaw/openclaw.json under "env".`;
  }

  const sessionId   = randomBytes(16).toString("hex");
  const webhookURL  = `${relayUrl}/pair/${sessionId}`;
  const pairingLink = `https://aasa.trusources.ai/openclaw?sessionId=${sessionId}&webhookURL=${encodeURIComponent(webhookURL)}`;
  const qrImageUrl  = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(pairingLink)}`;

  console.log(`[TruKYC:pair] sessionId=${sessionId}`);
  console.log(`[TruKYC:pair] webhookURL=${webhookURL}`);
  console.log(`[TruKYC:pair] pairingLink=${pairingLink}`);

  // Start polling in background
  pollForPairing(sessionId).then(async (data) => {
    if (!data) {
      console.error(`[TruKYC:pair] ❌ Pairing timed out sessionId=${sessionId}`);
      return;
    }
    await savePairedDevice(sessionId, data);
    console.log(`[TruKYC:pair] ✅ Device paired and saved sessionId=${sessionId} platform=${data.platform}`);
  });

  return [
    "📱 TruKYC Device Pairing",
    "",
    "Scan this QR code with your iPhone camera:",
    qrImageUrl,
    "",
    "Or tap this link directly on your iPhone:",
    pairingLink,
    "",
    `Session: ${sessionId.slice(0, 8)}...`,
    "⏳ Waiting for pairing (5 min timeout)...",
  ].join("\n");
}
