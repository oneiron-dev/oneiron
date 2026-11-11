# Masked image metadata

A marked masked-lane image read sanitizes raster metadata before serving bytes. PNG,
JPEG, WebP, GIF, TIFF, BMP and ICO use the existing decode-to-PNG path, with the existing
PNG/JPEG/WebP/GIF walkers when needed. PNM now uses the same decode-to-PNG path through
the existing image crate's pure-Rust decoder. Re-encoding keeps an image and removes
PNM header comments and trailing data; it does not substitute a text rendering.

The PNM feature adds no dependency. PNM variants that the decoder cannot sanitize keep
the owner's existing unsupported-format passthrough policy. Other unsupported formats
still use that same policy constant. This is not a universal image sanitizer.
Unmarked and owner reads, stored blobs, canonical hashes, view handles and secret-mark
custody remain unchanged.
