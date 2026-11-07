# Generated dispatch stack frames

The SDK generator outlines each facade row's concrete future construction into a
private non-inlined function. Each helper returns a boxed `Send` future borrowing
the original server and call. The shared asynchronous match receives that boxed
handle and awaits it; it no longer constructs every concrete row future itself.
The row bodies and the surrounding restriction-clock scope are unchanged.

The generated core `invoke` match calls a private non-inlined function per verb.
Each function keeps the original decode, typed call and output codec. The original
anonymous-chat refusal remains before hooks, and the other verbs still cross the
same single verb-hook boundary. Input validation also uses a private non-inlined
function per row, including the original board/host alternative and validation
statements. Feature guards remain on both the match arms and their helpers.

The MCP gateway's generated row match (`execute_agent_verb_row_on`) is outlined
the same way. Each row's arm is its own async function, unchanged, over the row's
arguments moved whole in one `McpVerbRow` value. A non-inlined function per row
constructs and boxes it, and the match awaits only that box.

## Evidence and remaining confirmation

A prologue scan of every function in the old dev artifact (head 2d7a31b0f2, Build
ID 7be05911836b3be822994c65b45d8514e49d1337) finds three frames over 2 MiB:

| Function | Frame |
|---|---|
| facade `dispatch::call_verb_row` poll | 12,048,632 B (11.49 MiB) |
| MCP `agent_verb_dispatch::execute_agent_verb_row_on` poll | 11,073,016 B (10.56 MiB) |
| core `verbs::invoke` | 3,877,880 B (3.70 MiB) |

Core `verbs::validate_input` was 1,421,752 B (1.36 MiB).
FIX 19837 records the old dev artifact's measured 11.49 MiB server-dispatch poll
frame and 3.70 MiB core-invoke frame. Those are measurements of the old artifact,
not frame sizes of the outlined source. The existing 32 MiB engine-thread stack
mitigation remains unchanged.

New frame sizes require a production-only fleet build of the exact head, followed
by inspection of the generated dispatch poll, core invoke and input-validation
prologues in that artifact. Record its head and Build ID with those measurements.
Source outlining, formatting and SDK generation do not prove a stack bound or a
runtime result. No tests are needed or run for this source change.
