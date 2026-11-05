# Hydrated image projection

A live ASSET hydrate first reads the asset through its scoped lane and selects a
form within the read's existing body budget. A full image or thumbnail is a
native `HydratedAsset::Served` body. Its `ImageFormBody.bytes` member carries
standard-base64 image bytes for JSON transport, not authored credential text.

The server uses the typed served-form rung to project these native bodies.
It separates the encoded pixels before applying the ordinary memory-body release
filter to every other field, including caption text and MIME metadata. It adds
the original encoded pixels to the released object only for Standard and Full
views. If the metadata is withheld as a whole, the pixels are not added back.

Stored ASSET bodies and text-only ladder forms keep the ordinary projection and
credential filter. No field named `bytes` in an arbitrary stored body is exempt.
The scoped read, body-budget accounting and served-form receipt are unchanged.
Provider-key detection and other credential rules are unchanged.
