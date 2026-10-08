# Run the server, with or without models

`oneiron serve` needs no model. Capture, search, reopen, export and backup all
work on a fresh vault with nothing configured. Models attach afterwards as
config, in a `[models]` section of the same `oneiron.toml`. One edit swaps
the model behind any seat, and no model or vendor is named in code.

## 1. No model

```bash
export ONEIRON_AUTH_SECRET="$(openssl rand -hex 32)"   # host root; the Dreamer needs it later
oneiron init ~/oneiron/vault --config ~/.config/oneiron/oneiron.toml --embedder none
oneiron serve --config ~/.config/oneiron/oneiron.toml
```

`GET /api/health` reports `"ai": {"dreamer": "idle", "dreamer_reason": "no_model_configured"}`.
Chat answers `503 no_model_configured`, and nothing that needs no model waits on one.

## 2. Point a seat at a model

Each provider is one entry of data. Pick any of the three levels below. HIGH
and MID are shorthands that expand to the DETAILED form, and a role written
out in DETAILED replaces what a shorthand gave it.

```toml
# HIGH: one model for every seat (chat and agents, checks, the Dreamer).
[models]
default = "cpa:olety7/gpt-6.1-sol"     # "<provider>:<the provider's own model id>"
prompt = "Answer briefly."             # optional; or prompt_file = "rung.md"

[models.providers.cpa]
kind = "openai-compat"
base_url = "http://127.0.0.1:8317"     # with or without a trailing /v1
key_env = "CPA_API_KEY"                 # the variable's NAME; never the key itself
```

```toml
# MID: a local stack and a cloud, local first. `local` also fills local_reasoner.
[models]
local = "llama:qwen3:8b"
cloud = "router:anthropic/claude-sonnet-4.5"
prefer_local = true                     # false puts the cloud rung first

[models.providers.llama]                # llama.cpp `llama-server`, vLLM, MLX `mlx_lm.server`
kind = "local-openai-compat"
base_url = "http://127.0.0.1:8080"

[models.providers.router]               # OpenRouter, or any OpenAI-compatible endpoint
kind = "openai-compat"
base_url = "https://openrouter.ai/api"
key_env = "OPENROUTER_API_KEY"
```

```toml
# DETAILED: one role's ladder, rung by rung. A rung that fails hands the call
# to the next; each rung may carry its own prompt.
[models.roles.dreamer_current]
rungs = [
  { model = "llama:qwen3:8b", prompt_file = "prompts/dreamer-local.md" },
  { model = "claude:claude-sonnet-4-5" },
]

[models.providers.claude]               # any Anthropic-compatible /v1/messages server
kind = "anthropic-compat"
base_url = "https://api.anthropic.com"
key_env = "ANTHROPIC_API_KEY"
```

Role keys are the model manifest's (ARCH-0036): `generative_reasoner` (chat and
saved workflows), `local_reasoner`, `checker`, `dreamer_current`,
`dreamer_target`, `extraction_encoder` (a tagger, `kind = "oneironer"`), and the
rest of the manifest list. The retrieval embedder stays in `[embedder]`, where
`provider = "endpoint"` takes any OpenAI-compatible `/v1/embeddings` server.

Provider fields: `kind` (`openai-compat`, `anthropic-compat`,
`local-openai-compat`, `oneironer`), `base_url`, `key_env`, `headers`
(non-credential only), `timeout_secs` (120), `context_tokens` (128000),
`max_output_tokens`, `capabilities` (`streaming`, `json_response`,
`tool_calling`, `tool_results`, `image_input`, `reasoning`), `locality`
(`own_server` or `third_party`) and `revision` (`live`). Plain `http://` is
accepted only for this machine, or for a `local-openai-compat` server on the
private network.

A reply may name its model differently from the request (a proxy that strips a
login prefix, say). The answer is kept, and the receipt records both names under
`usage.raw_provider` (`requested_model`, `reported_model`, `rung`).

## 3. Let the Dreamer work

The Dreamer consolidates witnessed turns into claims in the background. It
starts when all of these hold, and `GET /v1/ai/status` names the one that is
missing:

| Needs | Reason when missing |
|---|---|
| a rung on `dreamer_current` | `no_model_configured` |
| `ONEIRON_AUTH_SECRET` set (host root, machine identity) | `no_host_authority` |
| `extraction_egress = true` under `[models]`, for any model reached over HTTP | `extraction_egress_not_allowed` |
| the owner's weave grant, made once with the server stopped: `oneiron dreamer grant --config …` | `needs_owner_grant` |

Extraction leaves the device only on that explicit opt-in. With it, the vault's
extraction and consolidation defaults are aligned to the Dreamer seat's widest
rung, and only the Dreamer's own seat model is admitted.

A sitting ends, and its turns dream, on `POST /v1/ai/session {"event":"end"}`,
after `models.dreamer.idle_floor_secs` (1200) without activity, or after
`session_ceiling_secs` (43200). Apps send `{"event":"open"}` and
`{"event":"activity"}`; chat turns send them for you. Per-pass spend is
`models.dreamer.pass_budget_units` (400000), metered through the usual budget
guard. If the server is killed mid-pass, the next start requeues the
interrupted attempt and runs it once more; durable steps that already have a
response are not paid for again. `SIGTERM` or Ctrl-C stops cleanly: a pass in
flight reaches its attempt boundary first.

## 4. Chat

`POST /v1/ai/chat` with `{"conversation_ref": "<32-hex>", "text": "…"}` (plus
optional `history` and `agent_ref`) streams NDJSON: `accepted`, one `delta` per
text chunk, `done`, then `saved` with the message receipt. The same deltas
reach every owner socket on `/ws` as transient presence. Only the final
message is written to the vault, once.

## 5. Saved workflows

A dispatched saved workflow runs its steps on the `generative_reasoner` seat
with no further call. Each step's system message is the agent definition's
`instructions`; each later step sees the earlier steps' outputs. Spend per step:
`models.workflows.step_budget_units` (64000). `models.workflows.enabled = false`
turns the pump off.

## 6. Raw calls

With `[models]` set, `/v1/llm/generate` and `/v1/llm/stream` call any
configured model by its engine id (`<provider>/<model>@<revision>`, shown in
`GET /v1/ai/status`), or a seat by its seat id. Their process-lifetime meter is
`models.raw_budget_units`.
