# Attribution: mistral.rs

The local embedder provider in `local/` is a rebuild of the embedding stack in
[mistral.rs](https://github.com/EricLBuehler/mistral.rs), standing on the
released `candle-core` / `candle-nn` 0.11.0 rather than on that project's own
crates. No `mistralrs-*` crate is a dependency of this workspace, and no file
here is a byte-for-byte copy; the structure, the tensor names, the module chain
and the quantise-at-load mechanism are theirs.

mistral.rs carries no per-file copyright headers, so this notice is where the
attribution lives. Each rebuilt file names it in its own header comment.

## Licence

mistral.rs is MIT, from its repository root `LICENSE`:

```
MIT License

Copyright (c) 2024 Eric Buehler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

`candle` remains a dependency under its own `MIT OR Apache-2.0`.

## What was taken, and from where

Read at mistral.rs master `8be4595` (2026-09-06); the per-file commits are the
last that touched each source at that point.

| Our file | Their source | Last touched | What we took |
|---|---|---|---|
| `local/qwen3_embedding.rs` | `mistralrs-core/src/embedding_models/qwen3_embedding.rs` | `a31c74f7`, 2026-07-23 | The body-only Qwen3 decoder stack and its safetensors tensor names: `embed_tokens`, N decoder layers with q/k/v/o projections and per-head `q_norm`/`k_norm`, RoPE, SwiGLU MLP, a final norm, and no language head. |
| `local/st_modules.rs` | `mistralrs-core/src/embedding_models/layers.rs` | `246b44af`, 2025-11-05 (born `230e9c7c`, 2025-11-02) | The sentence-transformers module chain: `modules.json` read rather than assumed, `Pooling` parsed field for field from `1_Pooling/config.json`, `Normalize` as L2 over the last dimension, and an unsupported module refused by name. |
| `local/isq.rs` | `mistralrs-quant/src/utils/isq.rs`, `mistralrs-quant/src/gguf/mod.rs` | read at `8be4595` | In-situ quantisation: read the official bf16 weight on the host, quantise to Q8_0, move the blocks to the run device, wrap in candle's own `QMatMul`. Their wrapper around candle is replaced by candle directly. |
| `local/attention.rs` | `mistralrs-core/src/attention/mod.rs` (`run_attention_noflash`) | read at `8be4595` | The branch pair: the fused `candle_nn::ops::sdpa` path on Metal for supported head dims, and the eager tiled matmul + softmax path everywhere else. |
| `local/batcher.rs` | `mistralrs-core/src/scheduler/default_scheduler.rs`, `mistralrs-core/src/embedding_models/inputs_processor.rs` | read at `8be4595` | Bucketing waiting sequences by IDENTICAL token length and running one bucket per step — the property that makes their padding-free, mask-free forward correct. Their right-padding is not taken; grouping by equal length makes padding unreachable instead of harmless. |

## What was deliberately not taken

The CLI, the OpenAI server, and the whole `mistralrs-core` engine around the
embedding pipeline: the scheduler, the request and sequence channels, paged
attention, device mapping, AnyMoE, the ISQ executor and UQFF, the MCP client,
and the vision, audio, diffusion, speech and code-execution stacks. None of it
is feature-gated, and the embedding pipeline cannot be called without the engine
loop, so taking the library means taking all of it: a hello-world that links the
`mistralrs` library crate with `default-features = false` measured 109.4 MB
stripped against 6.9 MB for candle plus a tokenizer (M4 Max, 2026-09-08).

`mistralrs-quant` is also not a dependency. For bf16 and Q8_0 it wraps candle's
own `QTensor::quantize` and `QMatMul`; its own Metal kernels serve formats this
model does not use, and it pins candle as a git dependency 41 commits past the
0.11.0 tag, which would move this whole provider onto that pin.

Their CPU flash-attention kernels are a separate question left open: the measured
CPU bottleneck is the quantised matmul, not attention.
