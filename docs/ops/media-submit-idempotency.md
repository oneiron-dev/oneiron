# Media submit keys and provider recovery

OpenAI-compatible video job submission forwards the engine's existing job ticket
as the `idempotency-key` request header. The ticket is minted before submission;
replay-backed tickets bind the request and its caller partition or durable step.
The raw caller replay key is not sent as this header.

The header travels through both direct HTTP and `key_secret` broker adapters.
JSON and multipart submission use the same ticket. The broker includes the final
headers in its existing signed request digest and applies its existing header,
model, origin and credential checks. No broker wire format or authentication
change is required.

A missing or empty submit key adds no header. Other media operations, response
parsing, release checks, accounting and caller-level singleflight keep their
existing behavior.

## Forwarding is not a deduplication guarantee

`MediaBackend::submit_dedupes()` remains false for this OpenAI-compatible wire.
Sending the header alone does not establish that a provider honors it. A kept
submission whose response was lost still follows the existing lost-job policy;
it is not automatically resubmitted based on header forwarding.

Enable provider-honored recovery only when the provider's actual contract and
behavior establish the guarantee required by `submit_dedupes()`. This change does
not supply that evidence or change the flag.
