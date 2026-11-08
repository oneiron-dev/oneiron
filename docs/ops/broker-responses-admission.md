# Broker Responses admission and chat fallback

A `key_secret` OpenAI-compatible provider with `responses_socket` sends each
Responses turn through a one-use admission. Its digest covers the whole turn,
including a stored-chain turn whose transmitted create frame is a checked delta.
The broker can retry a missing chain with the same whole turn on that socket.

## A permit fixes the wire

Admission selects either the Responses digest or the buffered chat digest.
Dispatch checks that admitted digest and passes it to the adapter. The adapter
rebuilds and compares the selected wire's digest without consulting the mutable
provider-refusal latch. Another call's refusal therefore cannot switch an
already-admitted call to chat, before or after its gate opens.

## An upgrade failure gets a fresh admission

An unavailable broker or a provider connection refusal before upgrade is a
proved unsent attempt. Its gate clears the premature dispatch mark, emits no
Dispatched receipt, and settlement releases its reservation. A provider-answered
upgrade refusal, such as HTTP 404, keeps the existing started-failure reservation
and an unanswered Responses dispatch receipt. Neither case sent a model create
frame to the provider.

Only these pre-body failures expose the same offer's buffered chat adapter. The
ladder settles the first permit, admits the chat request's exact digest on a new
permit, and runs it through a new gate. Generate and stream calls retain their
world-route, source, cancellation and deadline checks. A stream may fall back only
before it has spoken. Anonymous chat uses the same fresh-admission rule without
retaining server receipts. An ambiguous send or a later stream cut never triggers
this wire fallback.

The existing 4xx latch (except HTTP 408 and 429) still selects chat for future
calls until restart. Transient connection failures do not latch the provider.
Buffered chat produces one terminal stream event; it does not add chat SSE.
There are no new configured rungs, limits, price rules or compatibility readers.

## Deployment

Ship the matching server and broker together for the Responses protocol version
in this change. A guest that uses the broker needs both binaries. This document
makes no claim that an image was built, pinned or deployed.
