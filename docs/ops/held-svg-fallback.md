# Held SVG picture compatibility fallback

A live-born or retargeted held picture still names its original SVG through
Office's `asvg:svgBlip` extension. When the retained deck already supplies a
raster for that SVG, export reuses it exactly as before.

For an SVG-only part, export can now derive a transparent PNG from the **existing
closed SVG geometry compiler** and tiny-skia. This is a separate embedding output,
not a change to `compile_graphic`: native figure compilation still produces
editable shapes and refuses unsupported SVG. `set_picture` keeps its PNG/JPEG
admission. The SVG bytes are never replaced or removed.

The initial fallback covers the existing closed subset: rectangles, rounded
rectangles, ellipses, lines and supported custom paths, with its existing fill,
stroke and transform rules. SVG text, CSS, filters, images and other unsupported
input keep the prior plain-SVG blip. No-op imports are not rasterized. Failure to
produce or install this optional PNG also keeps the prior path; tentative PNG,
content-type and relationship changes are discarded together.

## Derivation receipt and output size

`Conversion::SvgFallbackDerived` records the original part and BLAKE3 hash, PNG
part and BLAKE3 hash, pixel dimensions, EMU-per-pixel mapping, and process identity
and version. It travels through the existing `Effect::Converted` export effects:
land and Keep bind those effects to the actual artifact version, source version,
actor and host-recorded time; proposal reports expose the same effects. The
stateless projector does not add a clock or fabricate a separate asset identity.
This does not claim font licences, source authorship or per-face attribution.

The bitmap uses the SVG's intrinsic dimensions at the existing 96-dpi mapping
(`EMU_PER_PX = 9525`), rounded up to positive whole pixels. The existing Office
picture frame, crop and stretch remain unchanged. Source order, fill and stroke,
rotated frame centres and rising line direction come from the existing native
geometry. Antialiasing and rounded-corner approximations are the pinned path
renderer’s behavior, not a claim of pixel identity with PowerPoint.

The process uses tiny-skia 0.12.0 (`std`, `simd`, no default features) and png
0.18.1. It does not load system fonts, access files, fetch external SVG resources
or introduce another SVG parser. tiny-skia's BSD-3-Clause licence is already
allowed by `deny.toml`.

## Resources and current limits

The optional attempt uses existing `GraphicLimits` SVG bytes, raster pixels and
PNG bytes. The existing compiler uses the operation's `Resources` for its parse
and geometry. The renderer reserves the exact RGBA surface before allocation,
checks the caller's checkpoint between shapes and path segments, and admits PNG
output growth before allocation. It adds no timeout or operation-level refusal.

Renderer scanline/stroke scratch and PNG codec internals are not measured by
these public APIs. Checkpoints cannot interrupt one Skia paint or PNG compression
call. No full-memory, whole-SVG, bounded-latency or PowerPoint-runtime guarantee
is claimed. Broader SVG support and those internal resource hooks remain open.

This behavior changes the deterministic export, so `PROJECTOR_VERSION` advances
from `live-deck-projector/17` to `live-deck-projector/18`. Existing export memo keys
and gate receipts must refer to the actual new projector; no receipt is relabeled.
See [the export gate](deck-gate.md). This source change does not run its oracle,
any regression corpus, or tests.
