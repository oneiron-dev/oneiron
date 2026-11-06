# Large verb-write replies

A durable canonical host verb write stores an output whose JSON is larger
than the existing 512 KiB inline boundary before it records the write's
answer. Encoding streams into the existing admitted reply spool. The write
receipt keeps the compact result card and the body's existing output
manifest, not a second full JSON encoding.

The body's occurrence belongs to the executing code run. Its path contains
the stable write-receipt identity, so moving reads before a write on replay
does not change that occurrence. The receipt id is not the body owner.
Actor erasure and source withdrawal resolve the receipt's stored response
owner before releasing or retiring its output occurrences. Body publication
and the receipt's output manifest commit in the same writer, with the
receipt generation checked there. A crash before the later answer row is
saved therefore leaves the manifest discoverable for erasure; it does not
make the unfinished write replayable. This also covers a crash after the
answer is saved but before the executing run checkpoints. Later replay
writes use the same owner when checking withdrawn occurrences.

The recording host imports the native manifest, assigns its normal result
name and binds it to the run. It does not publish the body again. Immediate
result reads and later committed reads use the existing result resolver,
row-release checks, occurrence taint and secret checks. The output manifest
passes between the dispatcher and host as private transient state; JSON in
a card cannot create that state or grant access to another result.

A resumed write still passes the existing recorded-output admission, call
identity and standing checks before its receipt answers. It restores the
manifest from that receipt instead of executing the write again. Write
reservation, program settlement and answer-recorded release ordering stay
unchanged. Rows, observations and hook dispositions remain beside the
compact output. Unplaceable replies keep the existing typed unavailable
answer and publish no body.

This covers the canonical host-door write receipt. Session writes, scoped
ports and other typed outcome families keep their existing behavior. It is
not a claim that every large outcome or every replay path is now stored.
Deploy the matching ordinary engine build. No new SDK verb, configuration,
artifact protocol or migration is required.
