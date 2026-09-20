// Model selection: scripted (deterministic, CI — no LLM) by default; live
// when DRIVER=live. Live uses @ai-sdk/openai-compatible against Together or
// DeepSeek; the API key comes from the environment and is never baked in.

import { createOpenAICompatible } from "@ai-sdk/openai-compatible";

export type Driver = "scripted" | "live";

export function driverFromEnv(): Driver {
  return process.env.DRIVER === "live" ? "live" : "scripted";
}

export interface LiveModelSpec {
  provider: string;
  modelId: string;
  model: ReturnType<ReturnType<typeof createOpenAICompatible>>;
}

export function liveModel(): LiveModelSpec {
  const provider = process.env.LLM_PROVIDER ?? "together";
  const modelId =
    process.env.LLM_MODEL ??
    (provider === "deepseek" ? "deepseek-chat" : "meta-llama/Llama-3.3-70B-Instruct-Turbo");
  const keyEnv = provider === "deepseek" ? "DEEPSEEK_API_KEY" : "TOGETHER_API_KEY";
  const baseURL =
    process.env.LLM_BASE_URL ??
    (provider === "deepseek" ? "https://api.deepseek.com/v1" : "https://api.together.xyz/v1");
  const apiKey = process.env[keyEnv];
  if (!apiKey) throw new Error(`DRIVER=live requires ${keyEnv} in the environment`);
  const p = createOpenAICompatible({ name: provider, baseURL, apiKey });
  return { provider, modelId, model: p(modelId) };
}
