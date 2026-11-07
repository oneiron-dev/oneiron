# Brokered inference observations

The OpenAI-compatible chat path of a configured `key_secret` provider keeps
native inference evidence on the admitted call's existing budget lease.
The observation begins at the broker's physical-send release point, after
connection and custody release, not at a ladder or HTTP wrapper. This adds
no physical-attempt counter update and changes no budget charge.

When a brokered error response carries native `inference_calls`, or native
llama.cpp timings that the existing receipt constructor can read, the
adapter publishes that receipt before classifying the HTTP error. Strict
OpenAI reply parsing can also fail after a response reported native work;
that evidence remains a partial observation. The admitted engine model,
not the worker's claimed model id, is stamped on the observation.

A successfully parsed answer finishes the observation with the same typed
receipt its returned usage carries, once. The existing lease collector and
settlement rules retain the latest observation without counting the final
receipt twice. Error classification, retry and fallback behavior, standard
token counters, request digests and broker credential stripping are unchanged.

An error does not establish a serving alias. Only native measurements already
carried in its body are used. A body with only generic vendor token counters
gets no invented inference receipt. A cancelled, timed-out or lost call with
no observed body likewise reports no inferred counts, times or zeroes. This
is not proof of complete cancellation coverage.

This slice covers buffered OpenAI-compatible broker chat only. Anthropic,
Gemini, native worker transports, mesh and broker media remain separate.
Brokered llama.cpp identity remains epoch-only, without a new verified-build
or manifest claim. No new setting, cap, timeout, format or worker update is
required; rebuild the matching engine/server normally.
