# Deck transaction graphic ceilings

The native `DeckTransaction` grammar accepts an optional `graphics` object:

- `svg_bytes`: maximum bytes for one SVG payload.
- `raster_bytes`: maximum bytes for one raster payload.
- `raster_pixels`: maximum pixels for one raster payload.

When present, all three values are required. Every `set_picture` step in the
transaction uses these values through the existing graphic compiler. This applies
to direct native transaction execution and the document organ's `deck.transaction`
operation, whose `transaction` value carries the native grammar unchanged. The
outer operation's `limits` remain OPC package limits, not graphic ceilings.

When `graphics` is absent, the existing engine defaults remain unchanged:
1 MiB SVG bytes, 50 MiB raster bytes, and 64,000,000 raster pixels. The absent
field is omitted from canonical transaction text. Explicit values are serialized
and bound by the existing handoff hash and settlement replay.

Settings do not bypass asset identity, content hashes, provenance, rights,
factual-use rules, operation resource admission, or candidate part-diff checks.
An asset exceeding a selected ceiling returns the existing capacity error; it is
not truncated. These settings do not change native deck creation or live deck
export, which still use their existing defaults (FIX 10653 remains partial).
