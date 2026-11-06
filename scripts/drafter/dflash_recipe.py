"""FIX 14974: recipe `drafter.dflash.exl3.v1`, a vault's own DFlash drafter for an EXL3 target.

Provenance. The drafter architecture and its training objective follow the DFlash block-diffusion
drafter as its authors (z-lab) describe it in their paper and reference implementation: a few
decoder layers that read a projection of the target's hidden states at chosen layers, draft one
block of masked positions in one pass, and share the target's embedding table and lm_head. The
tap convention (the outputs of chosen target decoder layers, concatenated, then projected) is the
one EAGLE-3 (Apache-2.0) publishes. The training loop is the in-house prototype's step-A recipe
(muse-glimmer-afterglow `drafter/train_drafter.py`, 3 Nov 2026). This file copies no code from any
of them: it is written from those descriptions in plain torch.

What is new engineering here, not a port: rendering the engine's kept chat requests and the spans
their replies generated with the served target's own chat template and tokenizer, reading taps
from an HF checkpoint of the served target, and exporting through the operator's EXL3 converter.
Nothing here is qualified: the host's evaluator (FIX 14975) decides whether a trained version
serves.

Every number the recipe uses is a setting the job carries (`SETTINGS`): this file supplies none.
"""

from __future__ import annotations

import json
import math
import os
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import torch
import torch.nn.functional as F
from safetensors.torch import load_file, save_file

FAMILY = "drafter.dflash.exl3.v1"
RUNTIME = "exl3"
CORPUS_FORM = "oneiron.drafter.chat_traffic.v1"
# How a kept request and its generated span become the template's input: the engine's
# OpenAI-compatible chat mapping, the span as the assistant's message with its reasoning and its
# tool calls.
RENDER = "oneiron.drafter.openai-chat-render/2"
# The tap convention: the output of each named decoder layer, 0-based.
TAP_CONVENTION = "decoder_layer_output"
# The load set's trainable state: the serving loader reads `config.json` and globs
# `*.safetensors`, so neither name is one it loads.
TRAINABLE_PREFIX = "trainable-"
TRAINABLE_CONFIG = "trainable-config.json"
TRAINABLE_WEIGHTS = "trainable-weights.bf16"
# The served target's files the tokenizer digest reads, in order (deploy/house-model/cache_usage.py).
TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
                   "added_tokens.json", "config.json")
# The tokenizer files copied beside the trained weights for the converter.
CONVERTER_TOKENIZER_FILES = ("tokenizer.json", "tokenizer_config.json", "special_tokens_map.json")
# (setting, kind) of every recipe setting; every one is required and none has a default.
SETTINGS = (
    ("seed", "count"), ("learning_rate", "positive"), ("epochs", "positive_count"),
    ("anchors_per_step", "positive_count"), ("anchors_per_window", "positive_count"),
    ("slot_weight_decay", "positive"), ("warmup_fraction", "fraction"), ("adam_betas", "betas"),
    ("weight_decay", "nonnegative"), ("grad_clip", "positive"),
    ("context_window", "optional_positive_count"), ("tap_max_gpu_mib", "optional_positive_count"),
    ("export_args", "strings"),
)
# The evaluator's qualification rule (crates/oneiron/src/drafter/evaluation.rs
# DRAFTER_QUALIFICATION_KEY): pinned in the same recipe settings, never a trainer setting.
QUALIFICATION_KEY = "qualification"
# The drafter's own tensors per layer, as the DFlash checkpoint names them.
LAYER_TENSORS = (
    "input_layernorm.weight", "post_attention_layernorm.weight",
    "self_attn.q_proj.weight", "self_attn.k_proj.weight", "self_attn.v_proj.weight",
    "self_attn.o_proj.weight", "self_attn.q_norm.weight", "self_attn.k_norm.weight",
    "mlp.gate_proj.weight", "mlp.up_proj.weight", "mlp.down_proj.weight",
)
TOP_TENSORS = ("fc.weight", "hidden_norm.weight", "norm.weight")


class Refusal(Exception):
    """The job cannot run as asked: nothing trained, the receipt says why."""


class Failure(Exception):
    """A started job that produced no trained drafter: the receipt keeps what it measured."""


def need(condition: object, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def parse_settings(value: object) -> dict:
    """The recipe's trainer settings, closed: every key in `SETTINGS`, each of its kind, nothing
    else, beside the evaluator's optional `QUALIFICATION_KEY` rule, which rides the same pinned
    settings and which the trainer neither reads nor returns."""
    keys = {name for name, _ in SETTINGS}
    need(isinstance(value, dict), "recipe.settings must be an object")
    value = {name: item for name, item in value.items() if name != QUALIFICATION_KEY}
    need(set(value) == keys, f"recipe.settings needs keys {sorted(keys)} (plus an optional {QUALIFICATION_KEY})")
    for name, kind in SETTINGS:
        item, where = value[name], f"recipe.settings.{name}"
        number = type(item) in (int, float) and math.isfinite(item)
        if kind == "count":
            need(type(item) is int and item >= 0, f"{where} must be a nonnegative integer")
        elif kind == "positive_count":
            need(type(item) is int and item > 0, f"{where} must be a positive integer")
        elif kind == "optional_positive_count":
            need(item is None or (type(item) is int and item > 0), f"{where}: null or positive")
        elif kind == "positive":
            need(number and item > 0, f"{where} must be a positive number")
        elif kind == "nonnegative":
            need(number and item >= 0, f"{where} must be a nonnegative number")
        elif kind == "fraction":
            need(number and 0 <= item < 1, f"{where} must be in [0, 1)")
        elif kind == "betas":
            ok = isinstance(item, list) and len(item) == 2
            need(ok and all(type(b) in (int, float) and 0 < b < 1 for b in item), f"{where}: two in (0, 1)")
        elif kind == "strings":
            ok = isinstance(item, list) and item and all(isinstance(a, str) and a for a in item)
            need(ok, f"{where} must be a nonempty list of nonempty strings")
            need(not {"-i", "-o", "-w"} & set(item), f"{where} must not name -i, -o or -w")
    need(value["anchors_per_step"] >= value["anchors_per_window"],
         "recipe.settings.anchors_per_step must be at least anchors_per_window")
    return value


# ---------------------------------------------------------------------------------------------
# The served target: its tokenizer, chat template and end tokens.


def tokenizer_digest(directory: Path) -> str | None:
    """`deploy/house-model/cache_usage.py::tokenizer_digest`: the SHA-256 the EXL3 worker names
    as its tokenizer identity, over the tokenizer files of the served target's directory."""
    import hashlib

    if not (directory / TOKENIZER_FILES[0]).is_file():
        return None
    digest = hashlib.sha256()
    for name in TOKENIZER_FILES:
        path = directory / name
        if path.is_file():
            data = path.read_bytes()
            digest.update(f"{name}\0{len(data)}\0".encode("utf-8"))
            digest.update(data)
    return digest.hexdigest()


@dataclass
class ServedTarget:
    """The served target's tokenizer, chat template and end tokens, read from its directory."""

    directory: Path
    tokenizer: object
    template: object
    template_sha256: str
    eos_ids: frozenset
    record: dict


def load_served_target(directory: Path, tokenizer_pin: str) -> ServedTarget:
    """The served target's directory, checked against the target's tokenizer pin."""
    import hashlib

    from jinja2.sandbox import ImmutableSandboxedEnvironment
    from tokenizers import Tokenizer

    digest = tokenizer_digest(directory)
    need(digest == tokenizer_pin, "the served target's tokenizer is not the target's tokenizer pin")
    template_path = directory / "chat_template.jinja"
    need(template_path.is_file(), "the served target has no chat_template.jinja")
    source = template_path.read_text(encoding="utf-8")
    environment = ImmutableSandboxedEnvironment()

    def raise_exception(message):
        raise ValueError(message)

    environment.globals["raise_exception"] = raise_exception
    eos: set[int] = set()
    for name in ("generation_config.json", "config.json"):
        path = directory / name
        if path.is_file():
            value = json.loads(path.read_text(encoding="utf-8")).get("eos_token_id")
            eos.update([value] if type(value) is int else [v for v in value or [] if type(v) is int])
    need(eos, "the served target names no end token (eos_token_id)")
    template_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    record = {"tokenizer_digest": digest, "chat_template_sha256": template_sha256,
              "eos_token_ids": sorted(eos)}
    return ServedTarget(directory, Tokenizer.from_file(str(directory / "tokenizer.json")),
                        environment.from_string(source), template_sha256, frozenset(eos), record)


# ---------------------------------------------------------------------------------------------
# Rendering one kept request as the served target saw it.


def wire_messages(request: dict) -> list[dict] | None:
    """The request's messages as the OpenAI-compatible chat wire carries them: one text part as a
    string, several as text parts. `None` when a message holds anything but text."""
    out = []
    for message in request.get("messages") or []:
        role, parts = message.get("role"), message.get("content") or []
        if role not in ("system", "user", "assistant"):
            return None
        if not all(isinstance(p, dict) and p.get("kind") == "text" for p in parts):
            return None
        texts = [p.get("text", "") for p in parts]
        content = texts[0] if len(texts) == 1 else [{"type": "text", "text": t} for t in texts]
        out.append({"role": role, "content": content})
    return out or None


def wire_tools(request: dict) -> list[dict] | None:
    tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                               "parameters": t["input_schema"]}}
             for t in request.get("tools") or []]
    return tools or None


def template_kwargs(request: dict) -> dict:
    """The template arguments the request ran with: its `chat_template_kwargs` param, and an own
    server's seat effort as the chat wire maps it (`enable_thinking` false, or the effort)."""
    params = request.get("params") or {}
    kwargs = dict(params.get("chat_template_kwargs") or {})
    envelope = request.get("envelope") or {}
    effort = envelope.get("seat_effort")
    if effort is not None and envelope.get("locality") == "own_server":
        kwargs.pop("reasoning_effort", None)
        kwargs.pop("enable_thinking", None)
        if effort == "none":
            kwargs["enable_thinking"] = False
        else:
            kwargs["reasoning_effort"] = effort
    return kwargs


def encode(served: ServedTarget, text: str) -> list[int]:
    return served.tokenizer.encode(text, add_special_tokens=False).ids


def generated_message(line: dict) -> dict | str:
    """The reply's generated span (`generated`: the engine's provider-neutral parts, in the order
    the target generated them) as the chat template's assistant message: its text joined as
    `content`, its reasoning joined as `reasoning_content` and its tool calls as `tool_calls`. A
    string is the reason the example stays out: a reasoning part whose tokens the line does not
    hold (a summary, a count, or opaque data), a part no assistant generates, or nothing at all."""
    generated = line.get("generated")
    if not isinstance(generated, dict) or generated.get("role") != "assistant":
        return "not_generated"
    texts, thoughts, calls = [], [], []
    for part in generated.get("content") or []:
        kind = part.get("kind") if isinstance(part, dict) else None
        if kind == "text":
            texts.append(part.get("text", ""))
        elif kind == "reasoning":
            if part.get("reasoning_kind", "full") != "full" or part.get("data") is not None:
                return "reasoning_unrendered"
            thoughts.append(part.get("text", ""))
        elif kind == "tool_call":
            calls.append({"type": "function", "id": part.get("call_id"),
                          "function": {"name": part.get("name"), "arguments": part.get("input")}})
        else:
            return "generated_part"
    message = {"role": "assistant", "content": "".join(texts)}
    if "".join(thoughts):
        message["reasoning_content"] = "".join(thoughts)
    if calls:
        message["tool_calls"] = calls
    if not message["content"] and len(message) == 2:
        return "generated_empty"
    return message


def render_example(served: ServedTarget, line: dict) -> tuple[list[int], int, int] | str:
    """One corpus example as `(ids, span start, span end)`: the served prompt, then the span the
    target generated, rendered as the template renders the assistant's message, up to the turn's
    end token, and through it for a reply that stopped or called a tool. A reply that reasoned or
    called a tool spans everything the template renders after the generation prompt; a text-only
    reply spans from its text, the template's own bridge to the text joining the prompt. The span
    is the tokens the target generated that the corpus holds. A string is the reason the example
    stays out."""
    request = line.get("request") or {}
    messages = wire_messages(request)
    if messages is None:
        return "not_text"
    reply = generated_message(line)
    if isinstance(reply, str):
        return reply
    tools, kwargs = wire_tools(request), template_kwargs(request)
    try:
        before = served.template.render(messages=messages, tools=tools, add_generation_prompt=True,
                                        add_vision_id=False, **kwargs)
        full = served.template.render(messages=messages + [reply], tools=tools,
                                      add_generation_prompt=False, add_vision_id=False, **kwargs)
    except Exception:  # noqa: BLE001 - a template refusal is the example's, never the job's
        return "template_refused"
    if not full.startswith(before):
        return "template_prefix"
    tail = full[len(before):]
    if "reasoning_content" in reply or "tool_calls" in reply:
        at = 0
    else:
        at = tail.find(reply["content"])
        if at < 0:
            return "answer_not_rendered"
    prefix_ids, full_ids = encode(served, before + tail[:at]), encode(served, full)
    if full_ids[: len(prefix_ids)] != prefix_ids:
        return "token_prefix"
    start = len(prefix_ids)
    end = next((index for index in range(start, len(full_ids)) if full_ids[index] in served.eos_ids),
               None)
    if end is None:
        return "turn_end_not_rendered"
    if line.get("finish_reason") in ("stop", "tool_calls"):
        end += 1
    if end - start < 2:
        return "span_too_short"
    return full_ids[:end], start, end


# ---------------------------------------------------------------------------------------------
# Taps from the target checkpoint.


class _Stop(Exception):
    pass


def _decoder_layers(model, count: int):
    for _, module in model.named_modules():
        if isinstance(module, torch.nn.ModuleList) and len(module) == count:
            return module
    raise Refusal("the tap model has no decoder layer list of its configured depth")


def _text_config(config):
    return getattr(config, "text_config", None) or config


def _physical_ram_mib() -> int:
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // 2**20


@dataclass
class TapModel:
    model: object
    layers: list
    # Where the model's first module takes its input ids.
    input_device: object
    embed: torch.Tensor
    lm_head: torch.Tensor
    record: dict


def load_tap_model(directory: Path, layers: list[int], vocab: int, settings: dict) -> TapModel:
    """The target checkpoint the taps are read from: transformers, no remote code, local files
    only. Its raw embedding table and lm_head are copied out frozen for the drafter."""
    from transformers import AutoConfig, AutoModelForCausalLM

    config = AutoConfig.from_pretrained(directory, local_files_only=True, trust_remote_code=False)
    depth = _text_config(config).num_hidden_layers
    need(layers and max(layers) < depth and min(layers) >= 0, "a tap layer is outside the tap model")
    kwargs = {"dtype": torch.bfloat16, "local_files_only": True, "trust_remote_code": False,
              "low_cpu_mem_usage": True, "device_map": "auto"}
    if settings["tap_max_gpu_mib"] is not None:
        kwargs["max_memory"] = {0: f"{settings['tap_max_gpu_mib']}MiB", "cpu": f"{_physical_ram_mib()}MiB"}
    model = AutoModelForCausalLM.from_pretrained(directory, **kwargs)
    model.eval()
    embed = model.get_input_embeddings().weight
    head = model.get_output_embeddings().weight
    for name, tensor in (("embedding table", embed), ("lm_head", head)):
        need(tensor.device.type != "meta", f"the tap model's {name} is offloaded to disk")
        need(tensor.dtype in (torch.bfloat16, torch.float16, torch.float32), f"the tap model's {name} is quantized")
    need(embed.shape[0] >= vocab and head.shape[0] >= vocab, "the tap model's vocabulary is smaller than the tokenizer's")
    record = {"layers": layers, "convention": TAP_CONVENTION, "depth": depth,
              "hidden_size": int(embed.shape[1]), "vocab": int(head.shape[0])}
    return TapModel(model, _decoder_layers(model, depth), embed.device,
                    embed.detach().to("cpu", torch.bfloat16).clone(),
                    head.detach().to("cpu", torch.bfloat16).clone(), record)


def extract_taps(tap: TapModel, ids: list[int], keep_from: int, keep_to: int) -> torch.Tensor:
    """The concatenated outputs of the tap layers for `ids[keep_from:keep_to]`, on the CPU. The
    forward pass stops after the last tap layer."""
    want, captured, hooks = set(tap.record["layers"]), {}, []
    last = max(want)

    def hook(index):
        def run(module, inputs, output):
            hidden = output[0] if isinstance(output, tuple) else output
            if index in want:
                captured[index] = hidden[0, keep_from:keep_to].detach().to("cpu", torch.bfloat16)
            if index == last:
                raise _Stop()
        return run

    for index in want:
        hooks.append(tap.layers[index].register_forward_hook(hook(index)))
    try:
        x = torch.tensor([ids], dtype=torch.long, device=tap.input_device)
        with torch.no_grad():
            try:
                tap.model(input_ids=x, attention_mask=torch.ones_like(x), use_cache=False)
            except _Stop:
                pass
    finally:
        for handle in hooks:
            handle.remove()
    need(set(captured) == want, "a tap layer produced no output")
    return torch.cat([captured[i] for i in tap.record["layers"]], dim=-1).contiguous()


# ---------------------------------------------------------------------------------------------
# The DFlash drafter, in plain torch.


@dataclass(frozen=True)
class DrafterShape:
    hidden: int
    intermediate: int
    heads: int
    kv_heads: int
    head_dim: int
    layers: int
    eps: float
    rope_theta: float
    block: int
    mask_token: int
    tap_layers: list
    window: int | None


def drafter_shape(config: dict) -> DrafterShape:
    """The DFlash drafter's shape from its HF `config.json`; anything this recipe does not train
    refuses."""
    dflash = config.get("dflash_config") or {}
    for key in ("hidden_size", "intermediate_size", "num_attention_heads", "num_key_value_heads",
                "num_hidden_layers", "rms_norm_eps", "block_size"):
        need(key in config, f"the drafter config has no {key}")
    need(isinstance(dflash.get("target_layer_ids"), list) and dflash["target_layer_ids"],
         "the drafter config names no dflash_config.target_layer_ids")
    need(type(dflash.get("mask_token_id")) is int, "the drafter config names no dflash_config.mask_token_id")
    need(not config.get("attention_bias"), "this recipe trains a drafter without attention biases")
    rope = config.get("rope_parameters") or {}
    theta = rope.get("rope_theta", config.get("rope_theta"))
    need(isinstance(theta, (int, float)), "the drafter config names no rope_theta")
    scaling = config.get("rope_scaling") or {}
    kind = scaling.get("rope_type", scaling.get("type")) if scaling else None
    need(kind in (None, "default") and rope.get("rope_type", "default") == "default",
         "this recipe trains default rotary positions only")
    heads = config["num_attention_heads"]
    head_dim = config.get("head_dim") or config["hidden_size"] // heads
    sliding = config.get("sliding_window")
    window = sliding if config.get("use_sliding_window", sliding is not None) and sliding else None
    return DrafterShape(config["hidden_size"], config["intermediate_size"], heads,
                        config["num_key_value_heads"], head_dim, config["num_hidden_layers"],
                        float(config["rms_norm_eps"]), float(theta), int(config["block_size"]),
                        dflash["mask_token_id"], list(dflash["target_layer_ids"]), window)


class RMSNorm(torch.nn.Module):
    def __init__(self, width: int, eps: float):
        super().__init__()
        self.weight = torch.nn.Parameter(torch.ones(width))
        self.eps = eps

    def forward(self, x):
        y = x.float()
        y = y * torch.rsqrt(y.pow(2).mean(-1, keepdim=True) + self.eps)
        return self.weight * y.to(x.dtype)


class _Attention(torch.nn.Module):
    def __init__(self, s: DrafterShape):
        super().__init__()
        self.q_proj = torch.nn.Linear(s.hidden, s.heads * s.head_dim, bias=False)
        self.k_proj = torch.nn.Linear(s.hidden, s.kv_heads * s.head_dim, bias=False)
        self.v_proj = torch.nn.Linear(s.hidden, s.kv_heads * s.head_dim, bias=False)
        self.o_proj = torch.nn.Linear(s.heads * s.head_dim, s.hidden, bias=False)
        self.q_norm = RMSNorm(s.head_dim, s.eps)
        self.k_norm = RMSNorm(s.head_dim, s.eps)


class _Mlp(torch.nn.Module):
    def __init__(self, s: DrafterShape):
        super().__init__()
        self.gate_proj = torch.nn.Linear(s.hidden, s.intermediate, bias=False)
        self.up_proj = torch.nn.Linear(s.hidden, s.intermediate, bias=False)
        self.down_proj = torch.nn.Linear(s.intermediate, s.hidden, bias=False)

    def forward(self, x):
        return self.down_proj(F.silu(self.gate_proj(x)) * self.up_proj(x))


class _Layer(torch.nn.Module):
    def __init__(self, s: DrafterShape):
        super().__init__()
        self.input_layernorm = RMSNorm(s.hidden, s.eps)
        self.self_attn = _Attention(s)
        self.post_attention_layernorm = RMSNorm(s.hidden, s.eps)
        self.mlp = _Mlp(s)


class DFlashDrafter(torch.nn.Module):
    """The drafter's own tensors, named as its checkpoint names them: `fc` projects the
    concatenated taps, `hidden_norm` normalizes them, `layers` draft, `norm` ends."""

    def __init__(self, s: DrafterShape):
        super().__init__()
        self.shape = s
        self.fc = torch.nn.Linear(len(s.tap_layers) * s.hidden, s.hidden, bias=False)
        self.hidden_norm = RMSNorm(s.hidden, s.eps)
        self.layers = torch.nn.ModuleList(_Layer(s) for _ in range(s.layers))
        self.norm = RMSNorm(s.hidden, s.eps)


def expected_tensors(shape: DrafterShape) -> set[str]:
    return set(TOP_TENSORS) | {f"layers.{i}.{name}" for i in range(shape.layers) for name in LAYER_TENSORS}


def load_drafter(config: dict, tensors: dict, device) -> tuple[DFlashDrafter, str]:
    """The drafter from `tensors`, its names exactly the shape's, with one shared prefix (such as
    `model.`) allowed; returns the drafter and the prefix its checkpoint used."""
    shape = drafter_shape(config)
    expected = expected_tensors(shape)
    prefix = ""
    if set(tensors) != expected:
        prefixes = {name[: len(name) - len("norm.weight")] for name in tensors if name.endswith(".norm.weight")}
        prefix = next((p for p in prefixes if {p + n for n in expected} == set(tensors)), None)
        need(prefix is not None, "the parent drafter's tensors are not the DFlash drafter this recipe trains")
    model = DFlashDrafter(shape)
    model.load_state_dict({name[len(prefix):]: t for name, t in tensors.items()}, strict=True)
    return model.to(device=device, dtype=torch.bfloat16), prefix


# ---------------------------------------------------------------------------------------------
# Training.


@dataclass
class Example:
    """One rendered example: its token ids, its span, and its taps for positions
    `[taps_from, end - 1)`, kept on disk."""

    ids: torch.Tensor
    start: int
    end: int
    taps_from: int
    taps_path: Path


class Trainer:
    """The DFlash objective on blocks anchored inside generated spans, from the parent drafter,
    with the target's embedding table and lm_head frozen. Drafter weights train in bf16 on the
    GPU; their fp32 master copy and the AdamW state stay on the CPU."""

    def __init__(self, model: DFlashDrafter, embed: torch.Tensor, lm_head: torch.Tensor,
                 settings: dict, device):
        self.model, self.settings, self.device = model, settings, device
        self.shape = model.shape
        self.embed = embed  # CPU, frozen
        self.lm_head = lm_head.to(device)  # frozen
        s = self.shape
        self.inv_freq = 1.0 / (s.rope_theta ** (torch.arange(0, s.head_dim, 2, dtype=torch.float32,
                                                                   device=device) / s.head_dim))
        decay = settings["slot_weight_decay"]
        self.weights = torch.exp(-torch.arange(0, s.block - 1, dtype=torch.float32) / decay).to(device)
        window = settings["context_window"]
        self.window = window if window is not None else s.window
        self._cache: dict = {}

    def taps(self, example: Example) -> torch.Tensor:
        key = str(example.taps_path)
        if key not in self._cache:
            self._cache = {key: torch.load(example.taps_path, weights_only=True, mmap=True)}
        return self._cache[key]

    def _rope(self, positions):
        f = positions.float()[:, None] * self.inv_freq[None]
        e = torch.cat([f, f], -1)
        return e.cos().to(torch.bfloat16), e.sin().to(torch.bfloat16)

    def _rotate(self, x, cos, sin):
        half = self.shape.head_dim // 2
        x1, x2 = x[..., :half], x[..., half:]
        return x * cos[None] + torch.cat([-x2, x1], -1) * sin[None]

    def forward(self, example: Example, anchors: list[int]):
        """The drafter on one block per anchor of `example`: each block's slot 0 is the anchor's
        token and the rest the mask token; it sees the taps of the tokens before its anchor (within
        the context window) and its own block. Returns the final hidden states and the labels:
        the next tokens of the same span, none at or past its end."""
        s, ids = self.shape, example.ids
        nb, bs = len(anchors), s.block
        a = torch.tensor(anchors, dtype=torch.long)
        lo = example.taps_from if self.window is None else max(example.taps_from, int(a.min()) - self.window)
        hi = int(a.max())
        taps = self.taps(example)
        ctx = taps[lo - example.taps_from: hi - example.taps_from].to(self.device, non_blocking=True)
        noise = torch.full((nb, bs), s.mask_token, dtype=torch.long)
        noise[:, 0] = ids[a]
        x = self.embed[noise.view(-1)].to(self.device)
        qpos = (a[:, None] + torch.arange(bs)[None]).view(-1).to(self.device)
        cpos = torch.arange(lo, hi, device=self.device)
        label_pos = a[:, None] + torch.arange(1, bs)[None]
        inside = label_pos < example.end
        labels = torch.where(inside, ids[label_pos.clamp(max=ids.numel() - 1)],
                             torch.full_like(label_pos, -100)).to(self.device)
        anchor_row = a.to(self.device).repeat_interleave(bs)
        sees = cpos[None] < anchor_row[:, None]
        if self.window is not None:
            sees &= cpos[None] >= (anchor_row[:, None] - self.window)
        block = torch.arange(nb, device=self.device).repeat_interleave(bs)
        mask = torch.cat([sees, block[:, None] == block[None]], 1)[None, None]
        cos_q, sin_q = self._rope(qpos)
        cos_k, sin_k = self._rope(torch.cat([cpos, qpos]))
        context = self.model.hidden_norm(self.model.fc(ctx))
        h = x
        for layer in self.model.layers:
            att = layer.self_attn
            residual = h
            y = layer.input_layernorm(h)
            kv = torch.cat([context, y], 0)
            q = att.q_norm(att.q_proj(y).view(-1, s.heads, s.head_dim)).transpose(0, 1)
            k = att.k_norm(att.k_proj(kv).view(-1, s.kv_heads, s.head_dim)).transpose(0, 1)
            v = att.v_proj(kv).view(-1, s.kv_heads, s.head_dim).transpose(0, 1)
            q, k = self._rotate(q, cos_q, sin_q), self._rotate(k, cos_k, sin_k)
            repeat = s.heads // s.kv_heads
            k, v = k.repeat_interleave(repeat, 0), v.repeat_interleave(repeat, 0)
            o = F.scaled_dot_product_attention(q[None], k[None], v[None], attn_mask=mask,
                                               scale=s.head_dim ** -0.5)
            h = residual + att.o_proj(o[0].transpose(0, 1).reshape(-1, s.heads * s.head_dim))
            h = h + layer.mlp(layer.post_attention_layernorm(h))
        return self.model.norm(h).view(nb, bs, -1), labels

    def block_loss(self, hidden, labels):
        """Weighted cross-entropy on the raw lm_head logits of slots 1.. of each block."""
        total = torch.zeros((), device=self.device)
        chunk = self.settings["anchors_per_window"]
        for begin in range(0, hidden.shape[0], chunk):
            hh, ll = hidden[begin: begin + chunk, 1:], labels[begin: begin + chunk]

            def loss(hh, ll):
                logits = (hh.reshape(-1, hh.shape[-1]) @ self.lm_head.T).float()
                ce = F.cross_entropy(logits, ll.reshape(-1), ignore_index=-100, reduction="none")
                return (ce.view(ll.shape) * self.weights[None] * (ll >= 0)).sum()

            total = total + (torch.utils.checkpoint.checkpoint(loss, hh, ll, use_reentrant=False)
                             if torch.is_grad_enabled() else loss(hh, ll))
        return total

    def train(self, examples: list[Example]) -> dict:
        settings, bs = self.settings, self.shape.block
        per_window = settings["anchors_per_window"]
        windows = []
        for index, example in enumerate(examples):
            anchors = list(range(example.start, example.end - 1))
            windows += [(index, anchors[i: i + per_window]) for i in range(0, len(anchors), per_window)]
        if not windows:
            raise Failure("no anchor lies inside a generated span")
        per_step = max(1, settings["anchors_per_step"] // per_window)
        steps_per_epoch = math.ceil(len(windows) / per_step)
        total = steps_per_epoch * settings["epochs"]
        warm = math.ceil(total * settings["warmup_fraction"])
        lr = settings["learning_rate"]

        def lr_at(step):
            if step < warm:
                return lr * (step + 1) / warm
            return lr * 0.5 * (1 + math.cos(math.pi * (step - warm) / max(1, total - warm)))

        params = list(self.model.parameters())
        master = [p.detach().float().cpu().requires_grad_(True) for p in params]
        for m in master:
            m.grad = torch.zeros_like(m)
        stage = [torch.empty(p.shape, dtype=torch.bfloat16, pin_memory=torch.cuda.is_available()) for p in params]
        optimizer = torch.optim.AdamW(master, lr=lr, betas=tuple(settings["adam_betas"]),
                                      weight_decay=settings["weight_decay"])
        rng = random.Random(settings["seed"])
        torch.manual_seed(settings["seed"])
        self.model.train()
        history, step = [], 0
        for _ in range(settings["epochs"]):
            order = list(windows)
            rng.shuffle(order)
            for begin in range(0, len(order), per_step):
                batch = order[begin: begin + per_step]
                norm = sum(float(self.weights[: max(0, min(bs - 1, examples[i].end - 1 - p))].sum())
                           for i, part in batch for p in part)
                loss_sum = 0.0
                for index, part in batch:
                    hidden, labels = self.forward(examples[index], part)
                    loss = self.block_loss(hidden, labels) / max(norm, 1e-12)
                    loss.backward()
                    loss_sum += float(loss.detach())
                if not math.isfinite(loss_sum):
                    raise Failure("the training loss is not finite")
                grad_norm = float(torch.nn.utils.clip_grad_norm_(params, settings["grad_clip"]))
                with torch.no_grad():
                    for p, st in zip(params, stage):
                        st.copy_(p.grad, non_blocking=True)
                        p.grad = None
                    if torch.cuda.is_available():
                        torch.cuda.synchronize()
                    for m, st in zip(master, stage):
                        m.grad.copy_(st)
                    for group in optimizer.param_groups:
                        group["lr"] = lr_at(step)
                    optimizer.step()
                    for m, st in zip(master, stage):
                        st.copy_(m)
                    for p, st in zip(params, stage):
                        p.copy_(st, non_blocking=True)
                    if torch.cuda.is_available():
                        torch.cuda.synchronize()
                history.append({"step": step + 1, "loss": round(loss_sum, 6), "grad_norm": round(grad_norm, 4)})
                step += 1
        self.model.eval()
        anchors = sum(len(part) for _, part in windows)
        return {"optimizer_steps": step, "steps_per_epoch": steps_per_epoch, "warmup_steps": warm,
                "anchors": anchors, "windows": len(windows), "first_loss": history[0]["loss"],
                "last_loss": history[-1]["loss"], "history": history,
                "frozen": ["target_embedding", "target_lm_head"]}


def trained_tensors(model: DFlashDrafter, prefix: str) -> dict:
    return {prefix + name: t.detach().to("cpu", torch.bfloat16).contiguous()
            for name, t in model.state_dict().items()}


# ---------------------------------------------------------------------------------------------
# Export.


def export(converter: Path, trained_dir: Path, out_dir: Path, work_dir: Path, args: list[str],
           log: Path) -> list[Path]:
    """The operator's serving-format converter on the trained HF drafter, run with this
    interpreter, isolated and without a shell: `-i` the trained drafter, `-o` the new serving
    directory, `-w` its scratch directory, then the recipe's own arguments. Returns the files the
    serving directory holds; a subdirectory there refuses."""
    command = [sys.executable, "-I", str(converter), "-i", str(trained_dir), "-o", str(out_dir),
               "-w", str(work_dir), *args]
    with open(log, "wb") as output:
        done = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                              cwd=work_dir, check=False)
    if done.returncode != 0:
        raise Failure(f"the serving-format converter exited with {done.returncode}")
    files = sorted(out_dir.iterdir())
    if not files or any(not path.is_file() or path.is_symlink() for path in files):
        raise Failure("the converter's serving directory is empty or holds more than plain files")
    return files


def converter_input(trained_dir: Path, config: dict, tensors: dict, served: ServedTarget) -> None:
    """The trained drafter in its parent's HF layout: its config, its weights in one safetensors
    file, and the served target's tokenizer files beside them for the converter."""
    trained_dir.mkdir(mode=0o700)
    (trained_dir / "config.json").write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
    save_file(tensors, str(trained_dir / "model.safetensors"), metadata={"format": "pt"})
    for name in CONVERTER_TOKENIZER_FILES:
        source = served.directory / name
        if source.is_file():
            shutil.copyfile(source, trained_dir / name)


def read_parent(parent: dict) -> tuple[dict, dict]:
    """The parent drafter's HF config and tensors: the stock drafter's `config.json` and
    `*.safetensors`, or a kept version's trainable files."""
    directory = Path(parent["dir"])
    if parent["kind"] == "stock":
        config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
        tensors: dict = {}
        shards = sorted(directory.glob("*.safetensors"))
        need(shards, "the stock drafter has no safetensors file")
        for shard in shards:
            part = load_file(str(shard))
            need(not set(part) & set(tensors), "two stock drafter shards name one tensor")
            tensors.update(part)
        return config, tensors
    config = json.loads((directory / TRAINABLE_CONFIG).read_text(encoding="utf-8"))
    return config, load_file(str(directory / TRAINABLE_WEIGHTS))

