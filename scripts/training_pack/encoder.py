"""FIX 7263 (OF-418 L1): the frozen Oneironer trunk in PyTorch, for the question-head trainer.

A port of the Candle backbone that serves extraction
(crates/oneiron-server/src/oneironer/local/backbone.rs). It uses the same config checks and
the same tensor names under the trunk's `encoder.` prefix. Layers are post-norm. GTE ("new")
uses packed QKV with non-interleaved rotary attention; BERT uses absolute positions. GELU is
the exact erf form. Each pass is one unpadded window of tokenizer.json ids with special
tokens. A longer text is split into consecutive windows and pooled across them, never
truncated or refused. It reads only the pinned files it is given and verifies each pin
before parsing. It never downloads and never runs remote code. Weights stay frozen: no
tensor here requires a gradient, and every forward pass runs under `torch.no_grad()`.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import blake3
import safetensors.torch
import torch
import torch.nn.functional as F
from tokenizers import Tokenizer

# The trunk's encoder tensors sit under this prefix, as Candle's `weights.pp("encoder")`.
PREFIX = "encoder."
# Per window: the mean of every position's last hidden state, specials included; per target:
# the unweighted mean of its windows' means (`tokenize_targets` makes the windows).
POOLING = "window-mean-of-position-means/1"
# Per layer, as backbone.rs names them: attention output, its norm, MLP down, its norm.
LAYER_NAMES = {
    True: ("attention.o_proj", "attn_ln", "mlp.down_proj", "mlp_ln"),
    False: (
        "attention.output.dense",
        "attention.output.LayerNorm",
        "output.dense",
        "output.LayerNorm",
    ),
}


HEX = set("0123456789abcdef")


class Refusal(Exception):
    """A job this recipe does not run. Messages name fields and row ids, never their text."""


@dataclass(frozen=True)
class FilePin:
    """One file under a pinned directory: its relative name, SHA-256, BLAKE3 and exact size."""

    file: str
    sha256: str
    blake3: str
    bytes: int

    @staticmethod
    def parse(value: object, where: str) -> FilePin:
        keys = {"file", "sha256", "blake3", "bytes"}
        if not isinstance(value, dict) or set(value) != keys:
            raise Refusal(f"{where} must hold exactly {sorted(keys)}")
        name, size = value["file"], value["bytes"]
        parts = PurePosixPath(name).parts if isinstance(name, str) else ()
        if not parts or name.startswith("/") or "\\" in name or {".", ".."} & set(parts):
            raise Refusal(f"{where}.file must be a relative path of plain names")
        for algorithm in ("sha256", "blake3"):
            digest = value[algorithm]
            if not (isinstance(digest, str) and len(digest) == 64 and set(digest) <= HEX):
                raise Refusal(f"{where}.{algorithm} must be 64 lowercase hex digits")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise Refusal(f"{where}.bytes must be a nonnegative integer")
        return FilePin(name, value["sha256"], value["blake3"], size)


def read_pinned(directory: Path, pin: FilePin) -> bytes:
    """Reads one pinned file whole and checks its size, SHA-256 and BLAKE3 before any parse."""
    data = (directory / pin.file).read_bytes()
    if len(data) != pin.bytes:
        raise Refusal(f"{pin.file} is {len(data)} bytes; its pin says {pin.bytes}")
    if hashlib.sha256(data).hexdigest() != pin.sha256:
        raise Refusal(f"{pin.file} SHA-256 differs from its pin")
    if blake3.blake3(data).hexdigest() != pin.blake3:
        raise Refusal(f"{pin.file} BLAKE3 differs from its pin")
    return data


def _count(body: dict, key: str) -> int:
    value = body.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Refusal(f"config.json {key} must be a nonnegative integer")
    return value


@dataclass(frozen=True)
class EncoderConfig:
    """The trunk's config.json, checked as Candle's `Config::validate` checks it."""

    gte: bool
    hidden: int
    layers: int
    heads: int
    intermediate: int
    vocab: int
    positions: int
    type_vocab: int
    eps: float
    rope_theta: float

    @staticmethod
    def parse(body: object) -> EncoderConfig:
        if not isinstance(body, dict):
            raise Refusal("config.json must be an object")
        kind = body.get("model_type")
        if kind not in ("new", "bert"):
            raise Refusal("the frozen encoder supports new (GTE) and bert backbones only")
        gte = kind == "new"
        hidden, heads = _count(body, "hidden_size"), _count(body, "num_attention_heads")
        layers, intermediate = _count(body, "num_hidden_layers"), _count(body, "intermediate_size")
        vocab, positions = _count(body, "vocab_size"), _count(body, "max_position_embeddings")
        type_vocab, eps = _count(body, "type_vocab_size"), body.get("layer_norm_eps")
        finite = isinstance(eps, (int, float)) and not isinstance(eps, bool) and math.isfinite(eps)
        if not (
            min(hidden, heads, layers, intermediate, vocab, positions) > 0
            and hidden % heads == 0
            and finite
            and eps > 0
        ):
            raise Refusal("invalid encoder dimensions or layer norm epsilon")
        if body.get("hidden_act") != "gelu":
            raise Refusal("the frozen encoder requires exact GELU")
        if (
            body.get("layer_norm_type") not in (None, "layer_norm")
            or body.get("rope_scaling") is not None
            or body.get("logn_attention_scale", False) is not False
        ):
            raise Refusal("unsupported encoder normalization or attention scaling")
        theta = body.get("rope_theta")
        if gte:
            numeric = isinstance(theta, (int, float)) and not isinstance(theta, bool)
            if not (
                body.get("pack_qkv") in (None, True)
                and body.get("position_embedding_type") == "rope"
                and (hidden // heads) % 2 == 0
                and numeric
                and math.isfinite(theta)
                and theta > 0
            ):
                raise Refusal("GTE requires packed QKV and unscaled rotary attention")
        elif body.get("position_embedding_type") not in (None, "absolute"):
            raise Refusal("BERT requires absolute positions")
        rope = float(theta) if gte else 0.0
        return EncoderConfig(
            gte, hidden, layers, heads, intermediate, vocab, positions, type_vocab, eps, rope
        )

    def tensor_shapes(self) -> dict[str, tuple[int, ...]]:
        """Every tensor Candle's `Backbone::load` reads, by its full name and exact shape."""
        h, i = self.hidden, self.intermediate
        shapes: dict[str, tuple[int, ...]] = {
            "embeddings.word_embeddings.weight": (self.vocab, h),
            "embeddings.LayerNorm.weight": (h,),
            "embeddings.LayerNorm.bias": (h,),
        }
        if self.type_vocab:
            shapes["embeddings.token_type_embeddings.weight"] = (self.type_vocab, h)
        if not self.gte:
            shapes["embeddings.position_embeddings.weight"] = (self.positions, h)
        output, output_norm, down, down_norm = LAYER_NAMES[self.gte]
        layer = {output: (h, h), output_norm: (h,), down: (h, i), down_norm: (h,)}
        if self.gte:
            layer["attention.qkv_proj"] = (3 * h, h)
        else:
            layer.update({f"attention.self.{x}": (h, h) for x in ("query", "key", "value")})
            layer["intermediate.dense"] = (i, h)
        for n in range(self.layers):
            prefix = f"encoder.layer.{n}."
            for name, shape in layer.items():
                shapes[f"{prefix}{name}.weight"], shapes[f"{prefix}{name}.bias"] = shape, shape[:1]
            if self.gte:
                shapes[f"{prefix}mlp.up_gate_proj.weight"] = (2 * i, h)
        return {PREFIX + name: shape for name, shape in shapes.items()}


def _rope(x: torch.Tensor, cos: torch.Tensor, sin: torch.Tensor) -> torch.Tensor:
    """`candle_nn::rotary_emb::rope`: the non-interleaved form (halves, not pairs)."""
    half = x.shape[-1] // 2
    first, second = x[..., :half], x[..., half:]
    return torch.cat((first * cos - second * sin, first * sin + second * cos), dim=-1)


class FrozenOneironerEncoder(torch.nn.Module):
    """The trunk's forward pass, frozen: one unpadded sequence of ids in, its hidden states out."""

    def __init__(self, config: EncoderConfig, tensors: dict[str, torch.Tensor], device):
        super().__init__()
        expected = config.tensor_shapes()
        missing = sorted(name for name in expected if name not in tensors)
        if missing:
            raise Refusal(f"trunk lacks {len(missing)} encoder tensors, first {missing[0]}")
        for name, shape in expected.items():
            if tuple(tensors[name].shape) != shape or not tensors[name].is_floating_point():
                raise Refusal(f"trunk tensor {name} is not a float tensor of shape {shape}")
        self.config, self.device = config, torch.device(device)
        # Candle ignores every other tensor; the record names them.
        self.unused = sorted(set(tensors) - set(expected))
        self.weights = {
            name: tensors[name].to(self.device, torch.float32).contiguous().requires_grad_(False)
            for name in expected
        }
        self.requires_grad_(False)
        self.eval()

    def _linear(self, x: torch.Tensor, name: str) -> torch.Tensor:
        return F.linear(x, self.weights[name + ".weight"], self.weights[name + ".bias"])

    def _norm(self, x: torch.Tensor, name: str) -> torch.Tensor:
        weight, bias = self.weights[name + ".weight"], self.weights[name + ".bias"]
        return F.layer_norm(x, (self.config.hidden,), weight, bias, self.config.eps)

    def _rotary(self, length: int, dim: int) -> tuple[torch.Tensor, torch.Tensor]:
        """Candle's table: position / theta^(index / dim) for even index, in float32."""
        f32 = {"dtype": torch.float32, "device": self.device}
        theta = torch.tensor(self.config.rope_theta, **f32)
        exponents = torch.arange(0, dim, 2, **f32) / dim
        frequencies = torch.arange(length, **f32)[:, None] / theta.pow(exponents)[None, :]
        return frequencies.cos(), frequencies.sin()

    def forward(self, ids: list[int]) -> torch.Tensor:
        c, w = self.config, self.weights
        length, dim = len(ids), c.hidden // c.heads
        tokens = torch.tensor(ids, dtype=torch.long, device=self.device)
        hidden = F.embedding(tokens, w[PREFIX + "embeddings.word_embeddings.weight"])
        if c.type_vocab:
            hidden = hidden + w[PREFIX + "embeddings.token_type_embeddings.weight"][0]
        if not c.gte:
            hidden = hidden + w[PREFIX + "embeddings.position_embeddings.weight"][:length]
        hidden = self._norm(hidden, PREFIX + "embeddings.LayerNorm")
        rotary = self._rotary(length, dim) if c.gte else None
        for n in range(c.layers):
            p = f"{PREFIX}encoder.layer.{n}."
            output, output_norm, down, down_norm = LAYER_NAMES[c.gte]
            if c.gte:
                q, k, v = self._linear(hidden, p + "attention.qkv_proj").split(c.hidden, dim=-1)
            else:
                names = ("query", "key", "value")
                q, k, v = (self._linear(hidden, f"{p}attention.self.{x}") for x in names)
            q, k, v = (x.reshape(length, c.heads, dim).transpose(0, 1) for x in (q, k, v))
            if rotary is not None:
                q, k = _rope(q, *rotary), _rope(k, *rotary)
            # Candle divides a tensor by an f64 as affine(1 / x): a multiply.
            scores = q.matmul(k.transpose(-1, -2)) * (1.0 / math.sqrt(dim))
            attention = scores.softmax(dim=-1).matmul(v).transpose(0, 1).reshape(length, c.hidden)
            hidden = self._norm(self._linear(attention, p + output) + hidden, p + output_norm)
            if c.gte:
                up = F.linear(hidden, w[p + "mlp.up_gate_proj.weight"])
                gate = F.gelu(up[:, c.intermediate :], approximate="none")
                activated = up[:, : c.intermediate] * gate
            else:
                activated = F.gelu(self._linear(hidden, p + "intermediate.dense"))
            hidden = self._norm(self._linear(activated, p + down) + hidden, p + down_norm)
        return hidden


@dataclass
class PinnedEncoder:
    """A loaded trunk, its tokenizer, the verified bytes it came from and what it loaded."""

    model: FrozenOneironerEncoder
    tokenizer: Tokenizer
    files: dict[str, bytes]
    record: dict


def load_pinned_encoder(directory: Path, pins: dict[str, FilePin], device) -> PinnedEncoder:
    """Verifies every pin, then parses config, tokenizer and trunk from the verified bytes.

    `pins` holds `config`, `tokenizer` and `trunk`, plus `manifest` for a released bundle.
    The bundle's own `oneironer.json` (format 2) must name exactly those three pinned files.
    """
    files = {role: read_pinned(directory, pin) for role, pin in pins.items()}
    if "manifest" in files:
        manifest = json.loads(files["manifest"].decode("utf-8"))
        if not isinstance(manifest, dict) or manifest.get("format_version") != 2:
            raise Refusal("oneironer.json is not a format-2 bundle manifest")
        for role in ("config", "tokenizer", "trunk"):
            row, pin = manifest.get(role), pins[role]
            if row != {"file": pin.file, "sha256": pin.sha256, "bytes": pin.bytes}:
                raise Refusal(f"oneironer.json {role} row is not the pinned {pin.file}")
    config = EncoderConfig.parse(json.loads(files["config"].decode("utf-8")))
    tokenizer = Tokenizer.from_str(files["tokenizer"].decode("utf-8"))
    tokenizer.no_padding()
    tokenizer.no_truncation()
    tensors = safetensors.torch.load(files["trunk"])
    model = FrozenOneironerEncoder(config, tensors, device)
    record = {
        "backbone": "gte" if config.gte else "bert",
        "hidden_size": config.hidden,
        "layers": config.layers,
        "max_positions": config.positions,
        "tensors_loaded": len(model.weights),
        "tensors_unused": model.unused,
    }
    return PinnedEncoder(model, tokenizer, files, record)


def tokenize_targets(
    tokenizer: Tokenizer, texts: list[str], positions: int
) -> list[list[list[int]]]:
    """Each text as consecutive windows of at most `positions` ids, each with its specials.

    The content ids (`add_special_tokens=False`) are cut into consecutive runs of `positions`
    minus the specials' count, and each run is wrapped in the prefix and suffix the tokenizer
    adds around this text (`add_special_tokens=True`). A text that fits is one window, exactly
    its encoding with specials. No id is dropped and no length is refused (Rule 5).
    """
    windows = []
    for text in texts:
        full = tokenizer.encode(text, add_special_tokens=True).ids
        content = tokenizer.encode(text, add_special_tokens=False).ids
        starts = [
            start
            for start in range(len(full) - len(content) + 1)
            if full[start : start + len(content)] == content
        ]
        if not starts:
            raise Refusal("the tokenizer changes a sequence beyond adding special tokens")
        prefix, suffix = full[: starts[0]], full[starts[0] + len(content) :]
        room = positions - len(prefix) - len(suffix)
        if room <= 0:
            raise Refusal("the tokenizer's special tokens fill every encoder position")
        runs = [content[start : start + room] for start in range(0, len(content), room)]
        windows.append([prefix + run + suffix for run in runs or [[]]])
    return windows


def pool_hidden(windows: list[torch.Tensor]) -> torch.Tensor:
    """`window-mean-of-position-means/1`: the unweighted mean of each window's position mean."""
    return torch.stack([hidden.mean(dim=0) for hidden in windows]).mean(dim=0)


def encode_targets(model: FrozenOneironerEncoder, targets: list[list[list[int]]]) -> torch.Tensor:
    """The pooled state of each target: one unpadded pass per window, no encoder gradient."""
    model.eval()
    with torch.no_grad():
        pooled = [pool_hidden([model(window) for window in target]) for target in targets]
    return torch.stack(pooled)
