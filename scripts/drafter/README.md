# drafter: a vault's own drafter trainer (FIX 14974, FIX 12569)

`worker.py` trains one version of a vault's own small draft model for its target, on this host's
GPU, from the version's training examples. The engine's drafter trainer adapter
(`crates/oneiron-server/src/ai_host/drafter.rs`) runs it on a connector that
`[models.training.drafters.<name>]` names (docs/ops/run-with-models.md, section 16):

```sh
<python> -I scripts/drafter/worker.py --request <job>/request.json --output <job>/output
```

There is no shell and no network. The worker reads only the paths its request names, downloads
nothing, runs no remote code (`trust_remote_code` is off, files are local only), calls no model
service, reads no held-out example, picks no held-out sample and sets no binding. Its receipt is
producer evidence: not a qualification, an activation or a held-out evaluation. The host's
evaluator (FIX 14975) decides whether a trained version serves.

`dflash_recipe.py` is the one recipe, `drafter.dflash.exl3.v1`, and states its provenance: the
DFlash block-diffusion drafter as its authors describe it, the EAGLE-3 (Apache-2.0) tap
convention, and the in-house step-A prototype. It copies no code from them.

## Environment

One Linux x86_64 CUDA host, the one the target's managed EXL3 worker runs on. The interpreter
holds `requirements.txt`. The serving-format converter runs with the same interpreter, so
exllamav3 must be installed in it. The receipt records every installed distribution, the device,
CUDA and the driver. No CUDA device refuses the job.

## Request: `oneiron.drafter.train-job/1` (every object closed; unknown or missing keys refuse)

```json
{"format": "oneiron.drafter.train-job/1",
 "version": "<32 hex>", "spec_blake3": "<64 hex>", "generation": 0,
 "admission": "<the run admission's ref, verbatim>",
 "recipe": {"id": "drafter.dflash.exl3.v1", "revision": {"repository": "...", "revision": "<immutable>"},
            "settings": SETTINGS, "gpu_seconds": 0, "device_memory_mib": 0},
 "target": {"model": "<backend model digest>", "tokenizer": "<tokenizer digest>", "runtime": "exl3"},
 "served_target": "<abs dir: the served target's tokenizer and chat_template.jinja>",
 "tap_model": "<abs dir: the target checkpoint the taps are read from>",
 "converter": "<abs path: the serving-format converter script>",
 "parent": {"kind": "stock", "dir": "<abs dir: the trainable stock drafter>"}
        | {"kind": "version", "version": "<32 hex>", "dir": "<abs dir>",
           "files": [{"name": "trainable-...", "bytes": 0, "blake3": "<hex>"}]},
 "training": {"path": "<abs training.jsonl>", "bytes": 0, "blake3": "<hex>", "examples": 0,
              "form": "oneiron.drafter.chat_traffic.v1"}}
```

`version`, `spec_blake3`, `generation`, `admission`, `recipe` and `target` are echoed, never
recomputed. The served target's tokenizer digest (the EXL3 worker's: SHA-256 over
`tokenizer.json`, `tokenizer_config.json`, `special_tokens_map.json`, `added_tokens.json` and
`config.json`, each as `name\0len\0bytes`) must equal `target.tokenizer`, or the job refuses. The
stock drafter directory and the tap model directory are pinned by the BLAKE3 of every file in
them; a kept parent's trainable files must match the BLAKE3 the request names.

## Settings (`recipe.settings`): every key required, none has a default

The same settings may also hold `qualification`, the evaluator's rule (epsilon, cases, schedule, slowdown metrics; `crates/oneiron/src/drafter/evaluation.rs`). The trainer accepts it and never reads it.

| Key | Meaning |
|---|---|
| `seed` | The seed of the window order and torch. |
| `learning_rate` | The AdamW peak learning rate. |
| `epochs` | Passes over every anchor window. |
| `anchors_per_step` | Anchors one optimizer step takes. |
| `anchors_per_window` | Consecutive anchors one forward pass takes; also the loss chunk. |
| `slot_weight_decay` | `gamma`: slot `k` of a block weighs `exp(-(k-1)/gamma)`. |
| `warmup_fraction` | The share of steps the learning rate warms up over; cosine after. |
| `adam_betas` | AdamW's two betas. |
| `weight_decay` | AdamW's weight decay. |
| `grad_clip` | The gradient norm clip. |
| `context_window` | Target tokens before its anchor a block sees; `null` uses the drafter config's own window, or the whole prefix when it has none. |
| `tap_max_gpu_mib` | The GPU memory the tap model may take, the rest offloaded to the CPU; `null` lets the loader place it. |
| `export_args` | The converter's arguments after `-i <trained> -o <serving> -w <scratch>` (for exllamav3: `["-b", "<bits per weight>", ...]`). |

`gpu_seconds` and `device_memory_mib` are read by the host, not the worker: the quote the night
is admitted under (and after which the host stops the worker) and the memory it declares on the
target's device work line. The lab's recipe pilot (lr 2e-5, 2 epochs, 1024 anchors in windows of
64, CPU optimizer) is evidence for a Glimmer llama.cpp drafter only; no value here is a default.

## Recipe `drafter.dflash.exl3.v1`

1. **Examples.** Each training line is one answered chat reply of the vault's traffic
   (`oneiron.drafter.chat_traffic.v1`): `request`, exactly as the reply's answering rung sent it,
   and `generated`, the span the reply generated (its reasoning, tool calls and text, in the
   engine's provider-neutral parts, in order), with `finish_reason`. The request becomes the
   template's input as the engine's OpenAI-compatible chat wire maps it
   (`oneiron.drafter.openai-chat-render/2`): one text part as a string, several as text parts,
   the request's tools, its `chat_template_kwargs` and an own server's seat effort. The span
   becomes the assistant's message: its text as `content`, its reasoning as `reasoning_content`
   and its tool calls as `tool_calls`. The prompt renders with the served target's
   `chat_template.jinja` (generation prompt on), then with that message appended. A reply that
   reasoned or called a tool spans everything the template renders after the generation prompt;
   a text-only reply spans from its text, the template's own bridge to it joining the prompt.
   The span runs to the turn's first end token, and through it for a reply that stopped or
   called a tool. A request with anything but text, a reasoning part whose tokens the line does
   not hold (a summary, a count or opaque data), a template that refuses or does not extend its
   prompt, a text it does not render, tokens that do not extend the prompt's, or a turn with no
   end token leaves the example out, counted by reason.
2. **Taps.** The tap model (transformers, bf16, local files only, no remote code) reads each
   example; a forward hook keeps the output of each decoder layer the drafter's
   `dflash_config.target_layer_ids` names, concatenated, for the positions a block may see, and
   the pass stops after the last tap layer. The model's raw embedding table and lm_head are copied
   out and stay frozen.
3. **Training.** The parent drafter (the stock `config.json` and safetensors, or a kept version's
   `trainable-config.json` and `trainable-weights.bf16`) loads into a plain-torch DFlash drafter
   whose tensor names must be exactly `fc`, `hidden_norm`, `layers.N.{input_layernorm,
   post_attention_layernorm, self_attn.{q,k,v,o}_proj, self_attn.{q,k}_norm,
   mlp.{gate,up,down}_proj}` and `norm` (one shared prefix allowed); anything else refuses.
   Anchors lie only inside spans. A block's slot 0 is its anchor's token and the rest the mask
   token; it sees the taps of the tokens before its anchor within the window and its own block;
   its labels are the next tokens of the same span, none at or past the span's end. The loss is
   the slot-weighted cross-entropy of the raw lm_head logits. bf16 weights and gradients on the
   GPU, fp32 master weights and AdamW on the CPU, gradient clip, warmup then cosine.
4. **Export.** The trained drafter is written in its parent's HF layout, with the served target's
   tokenizer files beside it, and the converter runs on it with this interpreter (`-I`, no shell).
   The serving directory must hold plain files only.

## Output (a new or empty directory, mode 0700; files 0600)

`worker.lock` is held for the worker's whole life: a host that finds it free and no receipt
knows the job is gone. `load-set/` holds the serving files the converter wrote (`role:
serving`) and the trainable state a continued version trains from (`trainable-config.json`,
`trainable-weights.bf16`, `role: trainable`); the serving runtime loads neither of the
trainable files. `receipt.json` (`oneiron.drafter.train-receipt/1`) is written for every outcome,
renamed into place whole: `status` `trained` (exit 0), `failed` (1) or `refused` (2), the echoes,
the request's BLAKE3 and length, the pins (served target tokenizer digest, chat template SHA-256
and end tokens; the tap model's files and layers; the parent's files; the converter's BLAKE3),
the code's SHA-256, the corpus counts (examples, used, left out by reason, tokens, generated
tokens), the training record (steps, anchors, first and last loss, per-step loss and gradient
norm), the output files with their length, BLAKE3 and role, `service_units` (GPU wall seconds
from the first GPU use to the end) and the environment. It holds no example text. The worker's
`work/` scratch (taps, the trained HF copy, the converter's scratch) is removed before the
receipt is written; the host removes the whole job directory once it has sealed the load set.

## What the host does with it

The host checks the receipt against its job (the request it echoes, version, spec, generation,
recipe, target, runtime), rehashes every load-set file, and seals each one under the version's
own erasable key (`begin_drafter_artifact`, `DrafterSealing::seal_file`,
`publish_drafter_artifact`). The publication checks the version's generation again, so a
completion an erase overtook never publishes.
