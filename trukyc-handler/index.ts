import { emptyPluginConfigSchema } from "openclaw/plugin-sdk";
import { handlePairCommand } from "./src/handler.js";
import { registerGuardrail } from "./src/guardrail.js";

const plugin = {
  id: "trukyc-pairing",
  name: "TruKYC Pairing",
  description: "Secure Enclave device pairing + biometric guardrails for TruKYC",
  configSchema: emptyPluginConfigSchema(),
  register(api: any) {
    console.log(`[TruKYC] ── Plugin registering ──`);
    console.log(`[TruKYC] TRUKYC_RELAY_URL=${process.env.TRUKYC_RELAY_URL ?? "NOT SET"}`);
    console.log(`[TruKYC] ANTHROPIC_API_KEY_TRUKYC=${process.env.ANTHROPIC_API_KEY_TRUKYC ? "SET" : "NOT SET"}`);

    api.registerCommand({
      name: "trukyc-pair",
      description: "Pair a TruKYC iOS device for biometric guardrails",
      acceptsArgs: false,
      handler: async () => {
        console.log(`[TruKYC] /trukyc-pair command fired`);
        const response = await handlePairCommand();
        return { text: response };
      },
    });

    console.log(`[TruKYC] Registered /trukyc-pair command`);
    registerGuardrail(api);
    console.log(`[TruKYC] ✅ Plugin registered`);
  },
};

export default plugin;
