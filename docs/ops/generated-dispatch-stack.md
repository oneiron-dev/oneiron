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

## Evidence and remaining confirmation

FIX 19837 records the old dev artifact's measured 11.49 MiB server-dispatch poll
frame and 3.70 MiB core-invoke frame. Those are measurements of the old artifact,
not frame sizes of the outlined source. The existing 32 MiB engine-thread stack
mitigation remains unchanged.

New frame sizes require a production-only fleet build of the exact head, followed
by inspection of the generated dispatch poll, core invoke and input-validation
prologues in that artifact. Record its head and Build ID with those measurements.
Source outlining, formatting and SDK generation do not prove a stack bound or a
runtime result. No tests are needed or run for this source change.
