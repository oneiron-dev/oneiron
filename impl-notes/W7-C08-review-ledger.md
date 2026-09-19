# W7-C08 review recovery ledger

Refreshed PR #933 REST issue comments, reviews, inline comments and GraphQL threads before fixes. Published head `0c458e0a63562eeecf75db0e90732f186a8a2c8e`; local review head `ff5e713c`. Snapshot: 10 issue comments, 3 reviews, 28 inline comments, 28 threads. No newer bodies or inline IDs since the consolidation packet. Every nested thread page is complete. Raw receipts: `/home/lexi/w7-build/tickets/W7-C08/fix-review-receipts/`; original packet: `/home/lexi/w7-build/recovery/pr933-review-consolidation-20260919/`. Internal root verdicts supplied in this fix-review session supersede incomplete child previews. Codex supplied a completed substantive review, not a quota failure or pending review.

- F01: Fallback responses bypass JSON schema. Inline IDs: 4052784002. Disposition below.
- F02: Missing own-server LLM routes. Inline IDs: 4052784004, 4052796170. Disposition below.
- F03: Done published before durable sink succeeds. Inline IDs: 4052784005, 4052796175. Disposition below.
- F04: Provider export redaction misses camelCase credentials and private keys. Inline IDs: 4052784009, 4052796173. Disposition below.
- F05: Driver featureless test unresolved imports. Inline IDs: 4052784000. Disposition below.
- F06: Gemini helper public surface. Inline IDs: 4052784001. Disposition below.
- F07: Gemini success status rejected by stream. Inline IDs: 4052784008. Disposition below.
- F08: Shadow verdict converts legacy Hold/Unavailable to Allow. Inline IDs: 4052796169, 4052800041. Disposition below.
- F09: Malformed before-tags accepted. Inline IDs: 4052796174. Disposition below.
- F10: Owner voice refs accept self-declared provenance. Inline IDs: 4052796181. Disposition below.
- F11: Consent withdrawal leaves owner source clips. Inline IDs: 4052796185. Disposition below.
- F12: Anthropic raw usage delta overwrites earlier fields. Inline IDs: 4052800019. Disposition below.
- F13: Gemini metadata-only thoughtSignature aborts stream. Inline IDs: 4052800022. Disposition below.
- F14: Remote blocking stream read ignores cancellation. Inline IDs: 4052800025. Disposition below.
- F15: Remote stream inherits 120s total response timeout. Inline IDs: 4052800030. Disposition below.
- F16: Provider wire serialization lives in core. Inline IDs: 4052800031. Disposition below.
- F17: BYOA user_login flag bypasses hosted credential restriction. Inline IDs: 4052800032. Disposition below.
- F18: Named provider runners in core. Inline IDs: 4052800034. Disposition below.
- F19: Provider wire ingest lives in core. Inline IDs: 4052800036. Disposition below.
- F20: Empty Anthropic system record accepted. Inline IDs: 4052800038. Disposition below.
- F21: Malformed text blocks imported as JSON text. Inline IDs: 4052800039. Disposition below.
- F22: Conflicting equal-time model scores overwrite nondeterministically. Inline IDs: 4052800042. Disposition below.
- F23: Scraper config accepts downstream-overlong identifiers. Inline IDs: 4052800044. Disposition below.
- F24: Soniox string error codes gain JSON quotes. Inline IDs: 4052800048. Disposition below.

Internal Opus blockers map to F08, F03, F04, F02, F01, F09, F13. Grok duplicates F08, F04, F13. Opus nonblocking findings map to F12, F24, F23, F20/F21. O01 rejected: Acceptance 24 requires exactly three bad responses, not four. O02 rejected as blocking: extraction acceptance is covered and conflict fallback uses the same declared seam; missing separate conflict coverage is informational. F05 rejected by root: test-local imports exist; voice-only glob is correctly gated.

## Final applicability assessment

### F01

Fixed: deterministic fatal fallback must satisfy the requested JSON schema before persistence; invalid fallback remains terminal, settles prior spend, and is not memoized.

### F02

Fixed: /v1/llm/generate and /v1/llm/stream now have server counterparts with owner authentication, explicit backend injection, and server-side budget admission. Real HTTP integration drives the shipped RemoteLlmClient against the server router.

### F03

Fixed: the durable sink must succeed before Done enters subscriber queues or history. A rejected terminal can be retried; no false Done is observable.

### F04

Fixed: normalize credential key case and separators, cover private/SSH keys, and reject PEM private-key values before truncation as well as at serialization.

### F05

Dismissed: the new driver test already imports its dependencies inside the function. The separate voice-only glob correctly uses cfg(all(unix, feature = "voice")). No unresolved featureless imports reproduced; internal root rejected this finding.

### F06

Fixed: Gemini accumulator and wire helpers now use private re-exports and pub(super) definitions, not a public helper API.

### F07

Fixed: stream Status frames in 200..300 continue decoding; non-success status classification is unchanged.

### F08

Fixed: legacy Hold (including all host reasons) and Unavailable survive both verdict modes. Calibrated verdict floor behavior remains shadow/enforce-specific.

### F09

Fixed: validate before and after retrieval tags before surprise calculation and any paid call.

### F10

Dismissed as a caller-boundary allegation: store_owner_voice_refs is a trusted in-process Vault owner-capture door, not a wire or guest API. No server/NAPI/Python mapping exposes it. Origin rejects vendor identity but is not an authentication token. As with record_voice_consent and enrollment, the embedding host authenticates its owner before calling; an untrusted host with a Vault already has full write authority. No authenticated remote enrollment contract is added by this ticket.

### F11

Fixed: owner-indexed reference packs are deleted inside the same transaction as biometric withdrawal/retention. Withdrawal leaves neither readable nor cloneable source packs and is reflected in already_absent.

### F12

Fixed: Anthropic raw usage merges delta keys rather than replacing the message-start raw object; typed totals stay guarded.

### F13

Fixed: thoughtSignature-only Gemini metadata is a no-op; unsupported content with a signature is still refused.

### F14

Fixed: a cancellable asynchronous response reader runs in the transport-owned worker. Dropping the stream interrupts an active network read and closes the connection.

### F15

Fixed: the streaming client has connect and idle-read deadlines but no whole-response timeout. Non-streaming calls retain the existing total timeout.

### F16

Dismissed: contract step 20 explicitly requires these provider read formats in PackFormat and the serializer. They are upstream wire protocols shared by arbitrary engine consumers, not downstream product/persona conveniences.

### F17

Dismissed as a caller-boundary allegation: DispatchByoa is an in-process host request, with user_login explicitly host-stamped; no server, NAPI or Python ingress accepts that field from a guest. The trusted host also injects the credential executor and egress authority. Dispatch and execution both enforce the host-stamped placement. A future untrusted request mapping must derive it from custody, not deserialize it as authority.

### F18

Dismissed: steps 12–13 explicitly require DreamerProviderAdapter and the three named CLI runners. They are upstream provider integrations, not downstream consumer products, and retain argv-only/handle-only sandbox execution.

### F19

Dismissed: step 19 explicitly requires registered provider IngestSources. These upstream wire protocols normalize at Imported/Proposed trust and do not introduce a downstream product into the engine.

### F20

Fixed: trimmed-empty Anthropic system text is refused with EmptyText.

### F21

Fixed: malformed text/thinking and unknown block shapes are refused instead of importing arbitrary JSON. Explicit supported tool blocks retain typed-field validation.

### F22

Fixed: same-time conflicting existing model/benchmark observations are rejected atomically; identical same-time replay stays idempotent.

### F23

Fixed: source IDs and benchmark identifiers over 128 bytes are rejected during scraper config validation before fetch.

### F24

Fixed: Soniox string error codes are extracted as strings; numeric/non-string codes retain JSON fallback.

## Validation

Pending touched-crate tests on the repaired source. No prior green result or interrupted job is a pass for these changes.
