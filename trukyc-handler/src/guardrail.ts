import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const RELAY_URL = process.env.TRUKYC_RELAY_URL ?? "";
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY_TRUKYC ?? "";

const SAFE_TOOLS = new Set([
  "read",
  "session_status",
  "memory_search",
  "list",
  "ls",
]);

const kycResults: Map<string, {
  sessionId:  string;
  isHuman:    boolean;
  isAbove21:  boolean;
  verifiedAt: string;
}> = new Map();

export function storeKYCResult(result: {
  sessionId:  string;
  isHuman:    boolean;
  isAbove21:  boolean;
  verifiedAt: string;
}): void {
  kycResults.set(result.sessionId, result);
  console.log(`[TruKYC:guardrail] Stored KYC result sessionId=${result.sessionId} isHuman=${result.isHuman}`);
}

function loadPairedDevices(): Record<string, any> {
  const storagePath = path.join(os.homedir(), ".openclaw/devices/paired.json");
  try {
    return JSON.parse(fs.readFileSync(storagePath, "utf8"));
  } catch {
    return {};
  }
}

function findPairedDevice(): { fcmToken: string; apnsToken: string; publicKey: string } | null {
  const devices = loadPairedDevices();
  console.log(`[TruKYC:challenge] Loading paired devices from ${path.join(os.homedir(), ".openclaw/devices/paired.json")}`);
  console.log(`[TruKYC:challenge] Loaded ${Object.keys(devices).length} device(s)`);

  const entry = Object.entries(devices).find(
    ([, d]: [string, any]) => d.fcmToken
  );

  if (!entry) {
    console.warn(`[TruKYC:challenge] No TruKYC-paired device found (needs fcmToken)`);
    console.warn(`[TruKYC:challenge] Available device keys: ${Object.keys(devices).join(", ") || "none"}`);
    return null;
  }

  const [id, device] = entry;
  console.log(`[TruKYC:challenge] Found device id=${id.slice(0, 16)} fcmToken=${(device as any).fcmToken.slice(0, 20)}...`);
  return device as any;
}

async function checkDanger(toolName: string, toolArgs: unknown): Promise<{
  dangerous: boolean;
  reason: string;
  action: string;
}> {
  console.log(`[TruKYC:guardrail] ── Danger check ──`);
  console.log(`[TruKYC:guardrail] toolName=${toolName}`);
  console.log(`[TruKYC:guardrail] toolArgs=${JSON.stringify(toolArgs)}`);

  if (!ANTHROPIC_API_KEY) {
    console.error(`[TruKYC:guardrail] ❌ ANTHROPIC_API_KEY_TRUKYC not set — failing closed`);
    return { dangerous: true, reason: "API key not configured", action: toolName };
  }

  console.log(`[TruKYC:guardrail] Using API key ${ANTHROPIC_API_KEY.slice(0, 14)}...`);

  const systemPrompt = `You are a security guardrail for an AI agent.
You will be given a tool name and its arguments.
Reply with JSON only — no markdown, no preamble, no explanation outside the JSON:
{ "dangerous": true/false, "reason": "one line explanation", "action": "short human-readable description shown to the user on their phone for authorization e.g. 'Allow terminal command: rm -rf /tmp/test'" }
Rules:
- dangerous=true: write/delete/modify files, network requests that send data, payments, system changes, sending messages, installing software, running scripts, modifying permissions, killing processes
- dangerous=false: read-only operations (ls, pwd, cat, grep, find, head, tail, echo), reading files, querying data, math, answering questions, summarizing, git status/log/diff (read only)
- For shell/exec tools: only dangerous if the command modifies, deletes, sends, or installs something
- When in doubt: ls, cat, grep = safe. rm, mv, curl POST, pip install = dangerous`;

  try {
    const resp = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "x-api-key":         ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
      },
      body: JSON.stringify({
        model:      "claude-haiku-4-5-20251001",
        max_tokens: 256,
        system:     systemPrompt,
        messages:   [{ role: "user", content: `Tool: ${toolName}\nArgs: ${JSON.stringify(toolArgs)}` }],
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) {
      const body = await resp.text();
      console.error(`[TruKYC:guardrail] Haiku API error ${resp.status}: ${body}`);
      return { dangerous: true, reason: `API error ${resp.status}`, action: toolName };
    }

    const data = await resp.json() as { content: Array<{ type: string; text: string }> };
    const raw = data.content?.[0]?.text ?? "";
    console.log(`[TruKYC:guardrail] Haiku raw response: ${raw}`);

    const cleaned = raw.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
    const parsed = JSON.parse(cleaned);
    console.log(`[TruKYC:guardrail] Decision — dangerous=${parsed.dangerous} reason="${parsed.reason}" action="${parsed.action}"`);
    return parsed;

  } catch (err) {
    console.error(`[TruKYC:guardrail] Danger check failed: ${err} — failing closed`);
    return { dangerous: true, reason: `Check failed: ${err}`, action: toolName };
  }
}

async function sendChallenge(device: { fcmToken: string }, action: string): Promise<string> {
  const { randomBytes } = await import("node:crypto");
  const sessionId  = randomBytes(8).toString("hex");
  const nonce      = randomBytes(16).toString("hex");
  const salt       = randomBytes(8).toString("hex");
  const timestamp  = new Date().toISOString();
  const webhookURL = `${RELAY_URL}/verify/${sessionId}`;

  console.log(`[TruKYC:challenge] Sending challenge via relay sessionId=${sessionId} action="${action}"`);

  const resp = await fetch(`${RELAY_URL}/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      fcmToken: device.fcmToken,
      nonce,
      timestamp,
      salt,
      sessionId,
      webhookURL,
      action,
    }),
    signal: AbortSignal.timeout(15000),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Challenge relay error ${resp.status}: ${body}`);
  }

  console.log(`[TruKYC:challenge] ✅ Challenge sent sessionId=${sessionId}`);
  return sessionId;
}

async function pollForJWT(sessionId: string, timeoutMs = 120_000): Promise<{
  isHuman:   boolean;
  isAbove21: boolean;
} | null> {
  const url      = `${RELAY_URL}/poll/${sessionId}`;
  const deadline = Date.now() + timeoutMs;
  let   interval = 1000;

  console.log(`[TruKYC:verify] Polling for JWT sessionId=${sessionId} timeout=${timeoutMs / 1000}s`);

  while (Date.now() < deadline) {
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(5000) });

      if (resp.status === 200) {
        const data = await resp.json() as { jwt: string; sessionId: string };
        console.log(`[TruKYC:verify] ✅ JWT received sessionId=${sessionId}`);
        return verifyJWT(data.jwt);
      }

      if (resp.status === 202) {
        console.log(`[TruKYC:verify] Pending — waiting ${interval}ms...`);
      } else {
        console.warn(`[TruKYC:verify] Unexpected status=${resp.status}`);
      }
    } catch (err) {
      console.warn(`[TruKYC:verify] Poll error: ${err}`);
    }

    await new Promise((r) => setTimeout(r, interval));
    interval = Math.min(interval * 1.5, 3000);
  }

  console.error(`[TruKYC:verify] ⏱ JWT poll timeout sessionId=${sessionId}`);
  return null;
}

function verifyJWT(jwt: string): { isHuman: boolean; isAbove21: boolean } | null {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    const payload = JSON.parse(
      Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")
    );

    console.log(`[TruKYC:verify] JWT payload: isHuman=${payload.isHuman} isAbove21=${payload.isAbove21} exp=${payload.exp}`);

    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      console.error(`[TruKYC:verify] ❌ JWT expired`);
      return null;
    }

    return {
      isHuman:   Boolean(payload.isHuman),
      isAbove21: Boolean(payload.isAbove21),
    };
  } catch (err) {
    console.error(`[TruKYC:verify] ❌ JWT parse failed: ${err}`);
    return null;
  }
}

function buildKYCBlock(results: typeof kycResults): string {
  const lines = ["[TruKYC Biometric Verification]"];
  for (const [, r] of results) {
    lines.push(
      `- sessionId=${r.sessionId} isHuman=${r.isHuman} isAbove21=${r.isAbove21} verifiedAt=${r.verifiedAt}`
    );
  }
  return lines.join("\n");
}

export function registerGuardrail(api: any): void {
  console.log(`[TruKYC:guardrail] Registering before_tool_call hook`);

  api.on("before_tool_call", async (ctx: any) => {
    const toolName = ctx.tool ?? ctx.toolName ?? ctx.name ?? "unknown";
    const toolArgs = ctx.args ?? ctx.input ?? ctx.params ?? {};

    console.log(`[TruKYC:guardrail] ── before_tool_call fired ──`);
    console.log(`[TruKYC:guardrail] tool=${toolName} args=${JSON.stringify(toolArgs)}`);

    // Skip safe tools
    if (SAFE_TOOLS.has(toolName)) {
      console.log(`[TruKYC:guardrail] ✅ Safe tool — skipping danger check for tool=${toolName}`);
      return;
    }

    // Danger check via Haiku
    const { dangerous, reason, action } = await checkDanger(toolName, toolArgs);

    if (!dangerous) {
      console.log(`[TruKYC:guardrail] ✅ Safe — allowing tool=${toolName}`);
      return;
    }

    console.warn(`[TruKYC:guardrail] 🚨 DANGEROUS — tool=${toolName} reason="${reason}"`);

    // Find paired device
    const device = findPairedDevice();
    if (!device) {
      console.error(`[TruKYC:guardrail] ❌ No paired device — blocking tool=${toolName}`);
      return {
        block: true,
        blockReason: `TruKYC: no paired device found. Run /trukyc-pair first.`,
      };
    }

    // Send challenge push
    let challengeSessionId: string;
    try {
      challengeSessionId = await sendChallenge(device, action);
    } catch (err) {
      console.error(`[TruKYC:guardrail] ❌ Challenge send failed: ${err}`);
      return {
        block: true,
        blockReason: `TruKYC: failed to send biometric challenge: ${err}`,
      };
    }

    // Poll for JWT response
    console.log(`[TruKYC:guardrail] ⏳ Waiting for biometric response sessionId=${challengeSessionId}...`);
    const result = await pollForJWT(challengeSessionId);

    if (!result) {
      console.error(`[TruKYC:guardrail] ❌ Challenge timed out — blocking tool=${toolName}`);
      return {
        block: true,
        blockReason: `TruKYC: biometric challenge timed out.`,
      };
    }

    if (!result.isHuman) {
      console.error(`[TruKYC:guardrail] ❌ Biometric failed — blocking tool=${toolName} isHuman=false`);
      return {
        block: true,
        blockReason: `TruKYC: biometric verification failed. Tool blocked.`,
      };
    }

    // Store result for injection
    storeKYCResult({
      sessionId:  challengeSessionId,
      isHuman:    result.isHuman,
      isAbove21:  result.isAbove21,
      verifiedAt: new Date().toISOString(),
    });

    console.log(`[TruKYC:guardrail] ✅ Authorized — allowing tool=${toolName} isHuman=${result.isHuman}`);
    return;
  });

  console.log(`[TruKYC:guardrail] Registering before_prompt_build hook`);

  api.on("before_prompt_build", (ctx: any) => {
    console.log(`[TruKYC:guardrail] ── before_prompt_build fired — kycResults count=${kycResults.size}`);

    if (kycResults.size === 0) {
      console.log(`[TruKYC:guardrail] No KYC results to inject`);
      return;
    }

    const kycBlock = buildKYCBlock(kycResults);

    for (const [sessionId, r] of kycResults) {
      console.log(`[TruKYC:guardrail] Injecting KYC result — sessionId=${sessionId} isHuman=${r.isHuman} verifiedAt=${r.verifiedAt}`);
    }

    if (typeof ctx.prompt === "string") {
      ctx.prompt = `${ctx.prompt}\n\n${kycBlock}`;
      console.log(`[TruKYC:guardrail] ✅ KYC result injected into ctx.prompt`);
    } else if (typeof ctx.systemPrompt === "string") {
      ctx.systemPrompt = `${ctx.systemPrompt}\n\n${kycBlock}`;
      console.log(`[TruKYC:guardrail] ✅ KYC result injected into ctx.systemPrompt`);
    } else {
      console.warn(`[TruKYC:guardrail] ⚠️ Cannot inject — ctx keys=${Object.keys(ctx).join(", ")}`);
    }
  });

  console.log(`[TruKYC:guardrail] ✅ All hooks registered`);
}
