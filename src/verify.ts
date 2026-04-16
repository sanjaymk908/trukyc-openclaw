import type { IncomingMessage, ServerResponse } from "node:http";
import { createVerify, createPublicKey } from "node:crypto";
import { readRequestBodyWithLimit } from "openclaw/plugin-sdk";
import { pendingChallenges, loadPairedDevices } from "./challenge.js";

export type KYCResult = {
  sessionId: string;
  isHuman: boolean;
  isAbove21: boolean;
  livenessScore: number;
  matchScore: number;
  verifiedAt: string;
  toolName: string;
  toolArgs: unknown;
};

export const kycResults = new Map<string, KYCResult>();

// ── Relay polling ─────────────────────────────────────────────────────────────

const RELAY_URL = process.env.TRUKYC_RELAY_URL ?? "";
const POLL_INTERVAL_MS_START = 500;   // start fast
const POLL_INTERVAL_MS_MAX   = 3000;  // back off to 3s max
const POLL_BACKOFF_FACTOR     = 1.5;  // multiply each step
const POLL_TIMEOUT_MS         = 120_000;

export async function pollRelayForJWT(sessionId: string): Promise<string | null> {
  if (!RELAY_URL) {
    console.error(`[TruKYC:verify] ❌ TRUKYC_RELAY_URL not set`);
    return null;
  }

  const url = `${RELAY_URL}/poll/${sessionId}`;
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  let interval = POLL_INTERVAL_MS_START;
  let attempts = 0;

  console.log(`[TruKYC:verify] Starting relay poll — url=${url} timeout=120s`);

  while (Date.now() < deadline) {
    attempts++;
    const remaining = Math.round((deadline - Date.now()) / 1000);

    try {
      const resp = await fetch(url, {
        signal: AbortSignal.timeout(5000), // 5s per request
      });

      if (resp.status === 200) {
        const data = await resp.json() as { jwt: string; sessionId: string };
        console.log(`[TruKYC:verify] ✅ JWT received from relay — attempts=${attempts} sessionId=${sessionId}`);
        return data.jwt;
      }

      if (resp.status === 202) {
        console.log(`[TruKYC:verify] Pending — attempt=${attempts} interval=${interval}ms remaining=${remaining}s`);
      } else {
        console.warn(`[TruKYC:verify] Unexpected relay status=${resp.status} — attempt=${attempts}`);
      }
    } catch (err) {
      console.warn(`[TruKYC:verify] Relay fetch error attempt=${attempts}: ${err}`);
    }

    // Wait then back off
    await sleep(interval);
    interval = Math.min(interval * POLL_BACKOFF_FACTOR, POLL_INTERVAL_MS_MAX);
  }

  console.error(`[TruKYC:verify] ⏱ Poll timeout after ${attempts} attempts for sessionId=${sessionId}`);
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── JWT verification ──────────────────────────────────────────────────────────

export async function verifyJWT(
  jwt: string,
  nonce: string,
): Promise<{
  valid: boolean;
  claims?: {
    nonce: string;
    sessionId: string;
    isHuman: boolean;
    isAbove21: boolean;
    livenessScore: number;
    matchScore: number;
    exp: number;
  };
  error?: string;
}> {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    return { valid: false, error: `JWT has ${parts.length} parts, expected 3` };
  }

  const [headerB64, claimsB64, sigB64] = parts;
  console.log(`[TruKYC:verify] JWT header=${headerB64}`);

  let claims: any;
  try {
    const claimsJson = Buffer.from(claimsB64, "base64url").toString();
    console.log(`[TruKYC:verify] Raw claims: ${claimsJson}`);
    claims = JSON.parse(claimsJson);
    console.log(`[TruKYC:verify] Claims — nonce=${claims.nonce} isHuman=${claims.isHuman} isAbove21=${claims.isAbove21} exp=${claims.exp}`);
  } catch (err) {
    return { valid: false, error: `claims parse failed: ${err}` };
  }

  // Check expiry
  const now = Date.now() / 1000;
  if (now > claims.exp) {
    return { valid: false, error: `JWT expired — delta=${(now - claims.exp).toFixed(0)}s` };
  }
  console.log(`[TruKYC:verify] JWT expiry OK — ${(claims.exp - now).toFixed(0)}s remaining`);

  // Check nonce matches
  if (claims.nonce !== nonce) {
    return { valid: false, error: `nonce mismatch — expected=${nonce} got=${claims.nonce}` };
  }
  console.log(`[TruKYC:verify] Nonce matches ✅`);

  // Find public key
  const devices = loadPairedDevices();
  const deviceEntry = Object.entries(devices).find(
    ([, d]: [string, any]) => d.apnsToken && !d.role
  );
  if (!deviceEntry) {
    return { valid: false, error: "no paired device found" };
  }
  const [deviceId, device] = deviceEntry as [string, any];
  console.log(`[TruKYC:verify] Using device=${deviceId} publicKey=${device.publicKey.slice(0, 16)}...`);

  // Verify signature
  try {
    const rawKey = Buffer.from(device.publicKey, "base64");
    console.log(`[TruKYC:verify] Raw public key bytes=${rawKey.length} (expect 65 for uncompressed P-256)`);

    const spkiHeader = Buffer.from(
      "3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"
    );
    const spkiDer = Buffer.concat([spkiHeader, rawKey]);
    const pubKey = createPublicKey({ key: spkiDer, format: "der", type: "spki" });
    console.log(`[TruKYC:verify] Public key imported OK`);

    const signingInput = `${headerB64}.${claimsB64}`;
    const sig = Buffer.from(sigB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    console.log(`[TruKYC:verify] sig_bytes=${sig.length} signingInput_length=${signingInput.length}`);

    const verifier = createVerify("SHA256");
    verifier.update(signingInput);
    const valid = verifier.verify(pubKey, sig);
    console.log(`[TruKYC:verify] Signature valid=${valid}`);

    if (!valid) {
      return { valid: false, error: "invalid signature" };
    }
  } catch (err) {
    return { valid: false, error: `signature check threw: ${err}` };
  }

  return { valid: true, claims };
}

// ── HTTP handler (kept for direct LAN testing) ────────────────────────────────

export async function handleVerify(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  console.log(`[TruKYC:verify] ── POST /trukyc/verify received (direct) ──`);

  if (req.method !== "POST") {
    res.statusCode = 405;
    res.end("method not allowed");
    return;
  }

  let raw: string;
  try {
    raw = await readRequestBodyWithLimit(req, { maxBytes: 64 * 1024, timeoutMs: 10_000 });
    console.log(`[TruKYC:verify] Body read OK length=${raw.length}`);
  } catch (err) {
    console.error(`[TruKYC:verify] ❌ Body read failed: ${err}`);
    res.statusCode = 400;
    res.end("read failed");
    return;
  }

  let body: { jwt: string; sessionId: string };
  try {
    body = JSON.parse(raw);
    console.log(`[TruKYC:verify] sessionId=${body.sessionId} jwt_length=${body.jwt?.length}`);
  } catch (err) {
    console.error(`[TruKYC:verify] ❌ JSON parse failed: ${err}`);
    res.statusCode = 400;
    res.end("invalid json");
    return;
  }

  const { jwt, sessionId } = body;
  if (!jwt || !sessionId) {
    res.statusCode = 400;
    res.end(JSON.stringify({ status: "error", reason: "missing jwt or sessionId" }));
    return;
  }

  // Find pending challenge
  const challenge = [...pendingChallenges.values()].find(
    (c) => c.sessionId === sessionId
  );
  if (!challenge) {
    console.warn(`[TruKYC:verify] ❌ No pending challenge for sessionId=${sessionId}`);
    res.statusCode = 404;
    res.end(JSON.stringify({ status: "error", reason: "challenge not found or expired" }));
    return;
  }

  const result = await verifyJWT(jwt, challenge.nonce);
  if (!result.valid || !result.claims) {
    console.error(`[TruKYC:verify] ❌ JWT invalid: ${result.error}`);
    challenge.resolve(false);
    pendingChallenges.delete(challenge.nonce);
    res.statusCode = 401;
    res.end(JSON.stringify({ status: "error", reason: result.error }));
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

  console.log(`[TruKYC:verify] ✅ Storing KYC result: ${JSON.stringify(kycResult)}`);
  kycResults.set(result.claims.sessionId, kycResult);

  clearTimeout(challenge.timer);
  pendingChallenges.delete(challenge.nonce);
  challenge.resolve(result.claims.isHuman);

  console.log(`[TruKYC:verify] ✅ Challenge resolved isHuman=${result.claims.isHuman}`);

  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ status: "ok", verified: result.claims.isHuman }));
}
