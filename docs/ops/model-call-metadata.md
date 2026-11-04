# Model-call endpoint metadata

The existing model-call evidence records can retain the actual OpenAI Responses
call metadata. This does not enable replay or add another writer.

## Values retained

For a terminal on an OpenAI Responses socket:

- `endpoint` is `open_ai_responses_socket`.
- `response_id` is the terminal response object's `id`, when present. This also
  applies to an incomplete terminal that yields an answer.
- `previous_response_id` is the value sent on the frame that served that answer.
  If a missing previous response caused the existing whole-request retry, it is
  absent. The previous socket-chain cursor is never substituted for the answer's
  own response id.
- `store` is the bit on the sent turn, after the existing owner setting was applied.
  It is not a later read of that setting.

If that same Responses-capable provider takes its concrete chat HTTP fallback,
`endpoint` is `open_ai_chat_completions`. Its response, previous and store fields
stay unknown in this slice. Generic chat adapters and native EXL3 transports are
not labeled from their shared decoder or provider name.

Issuing account, organization, project, key identity and thread id remain unknown.
A local environment or secret binding name is not an upstream identity and is not
permission to replay anything.

## Transport and privacy

The call-local carrier is skipped by serde, JSON schema and the SDK field parser.
Public response, stream and usage shapes do not gain metadata keys. The socket
uses a typed internal terminal frame, not injected provider JSON or an async
thread-local lookup. Multi-call usage aggregates never inherit a single call's
metadata.

The existing raw/voice and workflow-final evidence writers copy the metadata only
behind their existing NoRecord/off-record gates. Missing metadata does not fail a
call. A record-write failure remains warn-only. The current-format erased form
clears endpoint, response id, previous id, store and any in-memory carrier along
with the existing private fields.

Request bytes, store controls, output, admission, budgets, counters, chain resume,
fallback, cancellation, receipts and replay behavior are unchanged. This slice
does not wire MESSAGE/chat conversation capture, add a Dreamer reader, export
reasoning, or settle the opaque-reasoning custody question.
