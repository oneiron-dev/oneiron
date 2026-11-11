# Interrupted code-run file outputs

A canonical normal-REPL file stream records its unfinished body occurrence before
its first frame. The occurrence is the existing ID derived from the run and the
final runtime output path. It has `Incomplete { retained: None }`: no body bytes,
content handle, preview, result binding or completed effect is invented.

The authenticated owner's `Memory::result_status_as_owner` view already includes
these descriptors in `bodies`. An interrupted stream is therefore visible as an
occurrence with `complete: false` and no retained body. Reading that status does
not enter the executor or invoke an effect. It does not recover the temporary
file's bytes or promise that a producer is still running.

The ordinary publication path remains responsible for finishing and measuring
the body. Only after the whole body is durable does its writer publish the raw
body row, sealed key and complete descriptor. It uses the same occurrence ID as
the unfinished descriptor. Existing complete or retained partial occurrences
are not replaced when another stream starts at the same path.

Actor response erasure and the late-write erase fence remove byte-free unfinished
occurrences in the same writer as the run's reply erasure. The existing owner
release path also removes them. No body key, digest or byte retirement is needed
for an unfinished occurrence with nothing retained.

This slice covers the normal REPL's canonical `JsCodeModeStream::File` outputs.
The same step number and first-frame file order name both the unfinished
occurrence and its completed publication. The run and its actual response owner
are committed before its first guest frame, including after a continuation fork.
Console, finish, stored-value and session streams keep their existing behavior;
their pre-publication progress remains open. Pinned-program and direct skill
entries keep their existing behavior too: they do not drain streamed files and
this slice does not add their missing file publication. Shadow replay writes no
live progress.
The descriptor uses the existing BODY metadata codec and adds no table, SDK
door, archive format, limit, deadline or retention policy. Result archives of
released output manifests do not gain unpublished occurrences in this slice.
