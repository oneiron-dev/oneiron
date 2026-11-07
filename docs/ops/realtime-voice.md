# Realtime voice sockets

The server exposes a raw Rust adapter for OpenAI Realtime and Gemini Live:
`RealtimeVoiceRung`, `RealtimeVoiceSession` and `RealtimeWire` in
`oneiron_server::models`. These are voice-loop sessions, not `ai.*` calls.
A host supplies its existing `RunAdmission` to `RealtimeVoiceSession::open`.
The first response permit is admitted before the socket opens.

This is an adapter seam, not an installed voice-loop driver. No configured
rung, HTTP route, cascade session or automatic provider selection invokes it
yet. A host must build and drive the session explicitly. FIX 462 remains
partial until that caller integration is connected.

## Provider and credentials

Pass the existing provider entry, configured model and explicit wire to
`RealtimeVoiceRung::new`. The key comes from the provider's `key_env` and
rides a sensitive upgrade header. OpenAI uses `Authorization: Bearer`;
Gemini uses `x-goog-api-key`. Neither adapter places the key in its socket
URL or returns a provider transport error containing it. Vault-secret,
ephemeral-token and Vertex credentials are not implemented by this seam.

The base URL is the provider origin plus any reverse-proxy path prefix.
OpenAI appends `/realtime` and the model query. Gemini appends
`/ws/google.ai.generativelanguage.v1beta.GenerativeService.BidiGenerateContent`;
use `https://generativelanguage.googleapis.com` for the direct Developer API,
without an HTTP API-version suffix. The adapter converts HTTP(S) to WS(S).
Gemini Live v1beta is the reference wire pinned here; it does not follow a
separately installed SDK's default API version.

## Raw event ordering

`open` sends an optional OpenAI `session.update`, as before. On Gemini it
always sends `setup` first, binding `setup.model` to the rung's configured
model in `models/{model}` form. The optional `session` argument is the raw
setup object, not another `setup` envelope. Other fields pass through.
The engine selects no response modality. For example, an audio caller can
supply `{"generationConfig":{"responseModalities":["AUDIO"]}}`.

Opening the socket does not prove that the provider accepted its setup.
Server acknowledgments remain in `next()`'s raw event stream. A Gemini
caller must receive `setupComplete` before sending additional client
messages. It then sends the provider's `clientContent`, `realtimeInput` or
`toolResponse` envelopes through `send()`. Audio remains the provider's
base64-encoded payload; this adapter performs no audio conversion.

`next()` returns original JSON server envelopes, including audio chunks,
transcriptions, tool calls, resumption updates and `goAway`. Gemini JSON
can arrive in text or binary UTF-8 frames. OpenAI keeps its existing text
frame behavior. There is no hidden event pump, reconnect or session
resumption. A host handles any `goAway` and drives close itself.

## Response accounting

Both wires use the existing realtime paid connector and response permits.
The reservation stays 16,384 tokens, or the previous response's reported
total when larger. The upgrade timeout stays the provider timeout capped
at 30 seconds.

OpenAI starts a response on `response.created` and settles it on
`response.done`, using `response.usage.total_tokens`.

Gemini model content, a tool call, generation completion or interruption
marks an observed response. Only `serverContent.turnComplete` ends that turn;
`generationComplete` or `interrupted` alone does not. The last actual
`usageMetadata.totalTokenCount` observed during that response, including
its completion frame, settles it. Repeated count snapshots are not summed.
A standalone report with no active or completing response is not assigned
to a later response. Reports reset at completion.

Missing usage follows the existing counted-zero rule, not a fabricated
provider report. Closing between responses settles the open reservation
on zero. Closing during an observed response whose usage has not settled
uses the existing unknown-usage failure outcome. The next response permit
is admitted at completion. If that next permit is refused, the completed
JSON event is still returned; the next read returns the typed refusal,
then further reads end. This also fixes the previous OpenAI behavior that
discarded its completion event on a prospective refusal. Close and drop
release the same socket and permit.

The provider reference defines `totalTokenCount` per generation request.
It does not promise usage metadata on every turn. No live-provider run,
usage-cadence proof or end-to-end voice-loop proof is claimed by this
adapter change.

## Wire references

- [Gemini Live API reference](https://ai.google.dev/api/live): v1beta endpoint,
  setup ordering, client/server envelopes, turn completion and token counts.
- [Official Python SDK at 2d0f9476](https://github.com/googleapis/python-genai/tree/2d0f9476ae5c7a6d3c90f81b056fad0315be5b60/google/genai):
  `live.py` builds the upgrade URI from the provider base and copied headers;
  `_api_client.py` supplies `x-goog-api-key`; the receive path parses JSON
  without requiring a text-only frame. These are source facts, not a claim
  that this Rust adapter was exercised against the provider.
