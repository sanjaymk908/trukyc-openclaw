import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { pollRelayForJWT, verifyJWT, kycResults, type KYCResult } from "./verify.js";

export type PendingChallenge = {
  nonce: string;
  timestamp: string;
  salt: string;
  sessionId: string;
  toolName: string;
  toolArgs: unknown;
  action: string;
  resolve: (passed: boolean) => void;
  timer: ReturnType<typeof setTimeout>;
};

export type PairedDevice = {
  publicKey: string;
  fcmToken:  string;
  apnsToken: string | null;
  pairedAt:  string;
};

export const pendingChallenges = new Map<string, PendingChallenge>();

export function loadPairedDevices(): Record<string, any> {
  const p = path.join(os.homedir(), ".openclaw/devices/paired.json");
  console.log(`[TruKYC:challenge] Loading paired devices from ${p}`);
  try {
    const raw = fs.readFileSync(p, "utf8");
    const devices = JSON.parse(raw);
    console.log(`[TruKYC:challenge] Loaded ${Object.keys(devices).length} device(s)`);
    return devices;
  } catch (err) {
    console.warn(`[TruKYC:challenge] Could not load paired devices: ${err}`);
    return {};
  }
}

export function findPairedDevice(): PairedDevice | null {
  const devices = loadPairedDevices();

  // Find any device with fcmToken — that's a TruKYC paired device
  const entry = Object.entries(devices).find(
    ([, d]: [string, any]) => d.fcmToken
  );

  if (!entry) {
    console.warn("[TruKYC:challenge] No TruKYC-paired device found (needs fcmToken)");
    console.warn(`[TruKYC:challenge] Available device keys: ${Object.keys(devices).join(", ") || "none"}`);
    return null;
  }

  const [id, device] = entry;
  console.log(`[TruKYC:challenge] Found device id=${id.slice(0,16)} fcmToken=${(device as any).fcmToken.slice(0, 20)}...`);
  return device as PairedDevice;
}

function getRelayUrl(): string {
  const url = process.env.TRUKYC_RELAY_URL ?? "";
  if (!url) throw new Error("TRUKYC_RELAY_URL not set");
  return url;
}

async function sendChallengeViaRelay(
  fcmToken: string,
  nonce: string,
  timestamp: string,
  salt: string,
  sessionId: string,
  actionText: string,
  relayUrl: string,
): Promise<void> {
  const webhookURL = `${relayUrl}/verify/${sessionId}`;
  const url = `${relayUrl}/challenge`;

  console.log(`[TruKYC:challenge] POSTing to relay ${url}`);
  console.log(`[TruKYC:challenge] fcmToken=${fcmToken.slice(0, 20)}...`);
  console.log(`[TruKYC:challenge] sessionId=${sessionId} action="${actionText}"`);
  console.log(`[TruKYC:challenge] iOS will POST JWT to: ${webhookURL}`);

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      fcmToken,
      nonce,
      timestamp,
      salt,
      sessionId,
      webhookURL,
      action: actionText,
    }),
    signal: AbortSignal.timeout(10_000),
  });

  const text = await resp.text();
  console.log(`[TruKYC:challenge] Relay response status=${resp.status} body=${text}`);

  if (!resp.ok) {
    throw new Error(`Relay challenge failed ${resp.status}: ${text}`);
  }
}

export async function sendChallenge(
  device: PairedDevice,
  toolName: string,
  toolArgs: unknown,
  actionText: string,
): Promise<boolean> {
  const nonce     = randomBytes(16).toString("hex");
  const timestamp = new Date().toISOString();
  const salt      = randomBytes(8).toString("hex");
  const sessionId = createHash("sha256")
    .update(`${nonce}${timestamp}`)
    .digest("hex")
    .slice(0, 16);

  console.log(`[TruKYC:challenge] ── New challenge ──`);
  console.log(`[TruKYC:challenge] nonce=${nonce}`);
  console.log(`[TruKYC:challenge] sessionId=${sessionId}`);
  console.log(`[TruKYC:challenge] toolName=${toolName}`);
  console.log(`[TruKYC:challenge] toolArgs=${JSON.stringify(toolArgs)}`);
  console.log(`[TruKYC:challenge] action="${actionText}"`);

  let relayUrl: string;
  try {
    relayUrl = getRelayUrl();
    console.log(`[TruKYC:challenge] relayUrl=${relayUrl}`);
  } catch (err) {
    console.error(`[TruKYC:challenge] ❌ ${err}`);
    return false;
  }

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      console.error(`[TruKYC:challenge] ⏱ TIMEOUT 120s nonce=${nonce} tool=${toolName}`);
      pendingChallenges.delete(nonce);
      resolve(false);
    }, 120_000);

    pendingChallenges.set(nonce, {
      nonce, timestamp, salt, sessionId,
      toolName, toolArgs, action: actionText,
      resolve, timer,
    });

    console.log(`[TruKYC:challenge] Pending in flight: ${pendingChallenges.size}`);
    console.log(`[TruKYC:challenge] All nonces: ${[...pendingChallenges.keys()].join(", ")}`);

    sendChallengeViaRelay(
      device.fcmToken,
      nonce, timestamp, salt, sessionId,
      actionText, relayUrl,
    )
      .then(async () => {
        console.log(`[TruKYC:challenge] ✅ Challenge sent — polling relay for JWT`);

        const jwt = await pollRelayForJWT(sessionId);
        if (!jwt) {
          console.error(`[TruKYC:challenge] ❌ No JWT received from relay`);
          clearTimeout(timer);
          pendingChallenges.delete(nonce);
          resolve(false);
          return;
        }

        const challenge = pendingChallenges.get(nonce);
        if (!challenge) {
          console.warn(`[TruKYC:challenge] Challenge expired before JWT arrived`);
          resolve(false);
          return;
        }

        const result = await verifyJWT(jwt, nonce);
        if (!result.valid || !result.claims) {
          console.error(`[TruKYC:challenge] ❌ JWT invalid: ${result.error}`);
          clearTimeout(timer);
          pendingChallenges.delete(nonce);
          resolve(false);
          return;
        }

        const kycResult: KYCResult = {
          sessionId:     result.claims.sessionId,
          isHuman:       result.claims.isHuman,
          isAbove21:     result.claims.isAbove21,
          livenessScore: result.claims.livenessScore,
          matchScore:    result.claims.matchScore,
          verifiedAt:    new Date().toISOString(),
          toolName:      challenge.toolName,
          toolArgs:      challenge.toolArgs,
        };

        console.log(`[TruKYC:challenge] ✅ KYC result: ${JSON.stringify(kycResult)}`);
        kycResults.set(result.claims.sessionId, kycResult);

        clearTimeout(timer);
        pendingChallenges.delete(nonce);
        resolve(result.claims.isHuman);
      })
      .catch((err) => {
        console.error(`[TruKYC:challenge] ❌ Relay challenge failed: ${err}`);
        clearTimeout(timer);
        pendingChallenges.delete(nonce);
        resolve(false);
      });
  });
}
