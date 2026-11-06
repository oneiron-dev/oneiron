# MCP request message lifetime

The stdio MCP bridge moves the parsed request into a private, caller-owned
holder without cloning it or dropping its fields before transport admission.
Endpoint selection, the probe, holder proof and fallback keep their existing
order. The holder never enters the socket driver, outbound queue or pending map.

On the existing socket `Sent` event, the waiting caller moves the original `id`
out and drops the remaining parsed fields after the driver has released the
original fallback body.
This event follows the same successful socket send. It is not response-byte
activity and starts or resets no reply idle timer.

For HTTP, the holder releases those fields only after `send` returns response
headers and the content-length check passes. The existing first reply idle
anchor is set before that release, so the release spends the same idle and
absolute request time. Later chunk idle anchors and reply collection keep their
existing order. Compression retains its Some-only original-body release.

Before either release point, errors keep the parsed request until `post`
returns. The caller then extracts the original ID and drops the other fields,
including after an unsent request, a failed probe or a pre-send timeout. A
notification still reaches `post` before its missing ID suppresses stdout. An
explicit `null` or arbitrary JSON ID keeps its value; no ID is cloned.

Pending-call memory and initialize capabilities still use the owned values
captured before the post and update only from a matching server answer. Reply
decoding follows the same post-completion ID selection.

This shortens parsed-request retention during reply collection. It does not
bound transport queues or reply allocation, change input/reply byte limits,
skip an admitted request, or establish a total heap, runtime or full streaming
guarantee. The parsed request remains alive during probe, admission and send.
