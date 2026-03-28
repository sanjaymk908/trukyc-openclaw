const KV_TTL = 180;

async function b64url(buf) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function getFirebaseAccessToken(serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const header = await b64url(
    new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" }))
  );
  const claims = await b64url(
    new TextEncoder().encode(JSON.stringify({
      iss: serviceAccount.client_email,
      scope: "https://www.googleapis.com/auth/firebase.messaging",
      aud: "https://oauth2.googleapis.com/token",
      iat: now,
      exp: now + 3600,
    }))
  );

  const signingInput = `${header}.${claims}`;

  const pemContents = serviceAccount.private_key
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  const keyData = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    new TextEncoder().encode(signingInput),
  );

  const jwt = `${signingInput}.${await b64url(sig)}`;
  console.log(`[relay:fcm] Fetching OAuth2 token for ${serviceAccount.client_email}`);

  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  const data = await resp.json();
  if (!resp.ok) throw new Error(`OAuth2 failed: ${JSON.stringify(data)}`);
  console.log(`[relay:fcm] ✅ Got access token`);
  return data.access_token;
}

async function sendFCMPush(fcmToken, pushData, env) {
  const serviceAccount = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const accessToken = await getFirebaseAccessToken(serviceAccount);
  const fcmUrl = `https://fcm.googleapis.com/v1/projects/${serviceAccount.project_id}/messages:send`;

  console.log(`[relay:fcm] Sending to ${fcmUrl}`);
  console.log(`[relay:fcm] fcmToken=${fcmToken.slice(0, 20)}...`);
  console.log(`[relay:fcm] data=${JSON.stringify(pushData)}`);

  const message = {
    message: {
      token: fcmToken,
      notification: {
        title: "🔐 Authorization Required",
        body:  pushData.action ?? "An action requires your biometric authorization",
      },
      // data must be string values only
      data: {
        openClaw: JSON.stringify(pushData),
      },
      apns: {
        headers: {
          "apns-push-type": "alert",
          "apns-priority":  "10",
        },
        payload: {
          aps: {
            sound:               "default",
            badge:               1,
            "content-available": 1,
          },
          // also embed directly for Swift to read from userInfo
          openClaw: pushData,
        },
      },
      android: {
        priority: "high",
        notification: {
          sound: "default",
        },
      },
    },
  };

  console.log(`[relay:fcm] Full message: ${JSON.stringify(message, null, 2)}`);

  const resp = await fetch(fcmUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type":  "application/json",
    },
    body: JSON.stringify(message),
  });

  const text = await resp.text();
  console.log(`[relay:fcm] Response status=${resp.status} body=${text}`);
  if (!resp.ok) throw new Error(`FCM ${resp.status}: ${text}`);
  console.log(`[relay:fcm] ✅ Push sent`);
}

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    const cors = {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    function json(data, status = 200) {
      return new Response(JSON.stringify(data), {
        status,
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    function logRequest() {
      console.log(`[relay] ${request.method} ${path}`);
    }

    // ── iOS → relay: POST /pair/:sessionId ───────────────────────────
    if (request.method === "POST" && path.startsWith("/pair/")) {
      logRequest();
      const sessionId = path.slice("/pair/".length);
      if (!sessionId) return json({ error: "missing sessionId" }, 400);

      let body;
      try { body = await request.json(); }
      catch { return json({ error: "invalid json" }, 400); }

      console.log(`[relay] pair body keys=${Object.keys(body).join(",")}`);

      if (!body.publicKey) return json({ error: "missing publicKey" }, 400);
      if (!body.fcmToken)  return json({ error: "missing fcmToken — iOS app must send FCM registration token" }, 400);

      await env.TRUKYC_KV.put(
        `pair:${sessionId}`,
        JSON.stringify({
          sessionId,
          publicKey:  body.publicKey,
          fcmToken:   body.fcmToken,
          apnsToken:  body.apnsToken ?? null,  // keep for reference
          platform:   body.platform ?? "ios",
          receivedAt: Date.now(),
        }),
        { expirationTtl: KV_TTL },
      );

      console.log(`[relay] ✅ pair stored sessionId=${sessionId} platform=${body.platform ?? "ios"}`);
      return json({ status: "ok", paired: sessionId });
    }

    // ── openclaw → relay: GET /pair-poll/:sessionId ──────────────────
    if (request.method === "GET" && path.startsWith("/pair-poll/")) {
      logRequest();
      const sessionId = path.slice("/pair-poll/".length);
      if (!sessionId) return json({ error: "missing sessionId" }, 400);

      const stored = await env.TRUKYC_KV.get(`pair:${sessionId}`);
      if (!stored) {
        console.log(`[relay] pair pending sessionId=${sessionId}`);
        return json({ status: "pending" }, 202);
      }

      await env.TRUKYC_KV.delete(`pair:${sessionId}`);
      console.log(`[relay] ✅ pair picked up sessionId=${sessionId}`);
      return new Response(stored, {
        status: 200,
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    // ── openclaw → relay: POST /challenge ────────────────────────────
    if (request.method === "POST" && path === "/challenge") {
      logRequest();
      let body;
      try { body = await request.json(); }
      catch { return json({ error: "invalid json" }, 400); }

      console.log(`[relay] challenge body keys=${Object.keys(body).join(",")}`);

      const { fcmToken, nonce, timestamp, salt, sessionId, webhookURL, action } = body;
      if (!fcmToken)   return json({ error: "missing fcmToken" }, 400);
      if (!nonce)      return json({ error: "missing nonce" }, 400);
      if (!sessionId)  return json({ error: "missing sessionId" }, 400);
      if (!webhookURL) return json({ error: "missing webhookURL" }, 400);

      const pushData = { nonce, timestamp, salt, sessionId, webhookURL, action };

      try {
        await sendFCMPush(fcmToken, pushData, env);
        console.log(`[relay] ✅ challenge sent sessionId=${sessionId}`);
        return json({ status: "ok" });
      } catch (err) {
        console.error(`[relay] ❌ FCM push failed: ${err}`);
        return json({ error: String(err) }, 500);
      }
    }

    // ── iOS → relay: POST /verify/:sessionId ─────────────────────────
    if (request.method === "POST" && path.startsWith("/verify/")) {
      logRequest();
      const sessionId = path.slice("/verify/".length);
      if (!sessionId) return json({ error: "missing sessionId" }, 400);

      let body;
      try { body = await request.json(); }
      catch { return json({ error: "invalid json" }, 400); }

      if (!body.jwt) return json({ error: "missing jwt" }, 400);

      console.log(`[relay] verify sessionId=${sessionId} jwt_length=${body.jwt.length}`);

      await env.TRUKYC_KV.put(
        `jwt:${sessionId}`,
        JSON.stringify({ jwt: body.jwt, sessionId, receivedAt: Date.now() }),
        { expirationTtl: KV_TTL },
      );

      console.log(`[relay] ✅ jwt stored sessionId=${sessionId}`);
      return json({ status: "ok" });
    }

    // ── openclaw → relay: GET /poll/:sessionId ───────────────────────
    if (request.method === "GET" && path.startsWith("/poll/")) {
      logRequest();
      const sessionId = path.slice("/poll/".length);
      if (!sessionId) return json({ error: "missing sessionId" }, 400);

      const stored = await env.TRUKYC_KV.get(`jwt:${sessionId}`);
      if (!stored) {
        console.log(`[relay] poll pending sessionId=${sessionId}`);
        return json({ status: "pending" }, 202);
      }

      await env.TRUKYC_KV.delete(`jwt:${sessionId}`);
      console.log(`[relay] ✅ jwt picked up sessionId=${sessionId}`);
      return new Response(stored, {
        status: 200,
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    // ── health ────────────────────────────────────────────────────────
    if (path === "/health") {
      return json({ status: "ok", ts: Date.now() });
    }

    return json({ error: "not found" }, 404);
  },
};
