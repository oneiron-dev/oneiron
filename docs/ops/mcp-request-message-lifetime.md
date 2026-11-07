# MCP request message lifetime

The stdio MCP bridge keeps the parsed request while `post` runs. Endpoint
selection, the probe, holder proof, transport admission, fallback, deadlines and
reply collection keep their existing order.

After `post` returns, the bridge moves the request's `id` out of that parsed
message and drops the remaining message before decoding the reply. It does not
clone the ID or retain the request's other parsed fields during reply decoding.
The moved ID keeps its original JSON value, including an explicit `null`.

A notification still reaches `post` before its missing ID suppresses the stdout
answer. Failed posts follow the same ID selection before reporting their
refusal. Pending-call memory and initialize capabilities still use the owned
values captured before the post and update only from a matching server answer.

This removes one request-ID clone and shortens parsed-request retention after
transport completion. It does not release the parsed request during the post,
bound transport queues or reply allocation, change the input/reply byte limits,
or establish a total heap, runtime or full streaming guarantee.
