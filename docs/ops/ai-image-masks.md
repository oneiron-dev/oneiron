# Image-edit masks on `ai.image`

`POST /v1/ai/image`, the `ai.image` facade and code-mode call accept an
optional `mask` alongside the existing `references`:

```json
{
  "prompt": "Replace the selected region",
  "references": [
    {"kind": "image", "media_type": "image/png", "data": "<source image base64>"}
  ],
  "mask": {"media_type": "image/png", "data": "<mask image base64>"}
}
```

The mask is an image, not another reference and not a `params` entry. It is
valid only on an image edit with reference images. Invalid base64, empty
image bytes or a mask on another operation uses the existing invalid-part
response. The provider interprets the mask; the engine does not resize it,
change its pixels or impose a new numeric image limit.

## Provider selection and transport

The ladder checks the actual backend's mask support before opening a permit.
A masked edit passes an unsupported offer unsent and keeps the existing rung
and owner-fallback order. An unsupported offer never receives an unmasked
substitute. If no offer can carry the mask, the call ends through the
existing invalid-request path. Unmasked calls keep their existing selection.

The OpenAI-compatible image adapter carries the mask. A masked edit uses the
documented JSON `/v1/images/edits` body: all references, in their original
order, become `images` entries with base64 data URLs; the mask is a separate
`mask` image reference. Direct and credential-brokered transports use the
same endpoint and execution lease. The existing unmasked generation JSON
and reference-edit multipart bodies are unchanged.

OpenAI mask inputs use the adapter's existing PNG, JPEG and WebP image types.
The engine leaves provider-specific mask interpretation and geometry to the
provider. OpenAI's separate `markup` input is not this API's `mask`; its
transparency and geometry rules are not imposed on masks. The `images` and
`mask` JSON fields are owned by the adapter, so a masked call cannot also
supply them as generic params.

Gemini, OpenRouter and ComfyUI do not advertise a native mask wire in this
slice. Their ordinary generation and reference edits are unchanged. Adding
mask support to another adapter requires both its actual send and its backend
capability, not a listing-only flag.

## Native seam and replay

`MediaRequest.mask` contains typed image bytes. `ImageBackend::reference_edit`
and `ImageCatalog::render` also accept the explicit optional mask. The native
`ImageIntent` has no copied mask, so preflight borrows mask bytes without
encoding them. Encoding happens only when the new masked request is sent.

Mask bytes participate in the existing canonical request hash and replay
identity. An absent mask is omitted from serialization, preserving unmasked
request bytes and replay keys. Existing admission, inference policy, payer,
lease, native image units, response decoding and settlement remain in place.

This is unrelated to privacy metadata masking or canonical-image redaction.

Wire reference: [OpenAI Create image edit](https://platform.openai.com/docs/api-reference/images/createEdit).
