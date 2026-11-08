# Organ mesh reply memory

A serving organ host returns an `OrganOutcome`. Its existing frame lease covers
the whole decoded proposal, including its body, report and inline output byte
buffers. The receiver books the decoded-value estimate before typed decoding.
That estimate includes encoded string, binary and extension payload lengths;
it does not establish the exact capacity of every typed allocation. Releasing
the encoded body returns its budget bytes, but the machine-floor lease keeps
the encoded-plus-decoded peak until the frame holder drops. Moving decoded
values into a mesh `PeerResult` must not drop that lease before the result is
encoded.

`mesh/serve.rs` keeps the result and its original frame lease in one private
`CallReply`. For an owned inline output at or below the existing inline
threshold, it moves the original byte vector into the reply instead of cloning
it. The output's original budget reservation and any machine-floor lease move
into the same holder. Names, media types, content hashes, byte order and wire
shapes do not change. Larger owned outputs and mapped outputs still use the
existing staging path; their source buffers are not held for the connection.

The result is declared before its output guards and frame lease, so its values
drop first. The holder survives result encoding and staging on both successful
and failed paths. Only the `PeerResult` is serialized; the holder is not a wire
type.

The source-value holder does not create a reservation or change any admission
decision. It keeps an existing reservation through the existing values' last
use. A host without a frame lease still uses the same path with `None`. Inputs,
forwarded asks, client reassembly, staged-file retention and disk-floor
accounting are unchanged.

If staging an output fails after the organ has run, the existing failed reply
keeps the ask receipts collected by that run. If staging the encoded result
fails instead, the host sends an inline failed result with those same receipts;
it does not need the refusing spool to deliver them. The ordinary transport
bounds still apply. The original result's guards stay through failure encoding,
and the failure bytes keep their own actual-capacity record through send.
Failures before a run still carry no ask receipts. Keeping these receipts does
not retain or replay the completed outcome.

Outgoing physical reply copies also record their actual vector capacity on
this host's machine-memory line when it has one. The narrow
`MachineFloor::track_allocated` adapter uses an empty native lease followed by
`materialized(0, capacity)`. It records bytes already allocated: it neither
admits an allocation nor waits or refuses. Existing admission arithmetic is
unchanged.

Each mapped inline output copy stays recorded while its `PeerResult` owns it.
The encoded result, its separate inline staging copy when small, the encoded
reply and each `Get` piece have independent records. Their buffers drop before
their records, on success and error paths, and the records survive each
buffer's last encoding, staging or send use. A move from `Vec` to `ByteBuf`
keeps the same backing allocation. The original owned inline outputs are not
charged again, and staged files remain disk rather than full-file payload RAM.
Inputs, forwarded asks and the asking client's copies are unchanged.

For a locally returned mapped output, `host/outputs.rs` reads the sealed length,
holds that many bytes in `CallRoom` before mapping, and moves the budget bytes
into the output's `Kept` guard. That guard stays live when `native_outputs`
borrows the output to make a separate byte-vector copy. `hold` and `keep` track
the call budget; they do not themselves acquire a machine-floor lease. The
absence of a separate lease field on that copy does not establish zero floor
coverage or show that the retained frame peak is sufficient. Budget bytes,
machine-floor reservations and actual vector capacities are distinct values.

This is not complete mesh-copy memory accounting. Recording capacity after an
allocation does not establish admission before that allocation. Codec scratch,
allocator overhead, container metadata such as the output-guard vectors and
the original source capacities still need their own accounting. Keeping a
source output's existing budget reservation does not establish a new
machine-floor reservation or prove its original capacity was fully accounted.
No new memory failure, wait, deadline, cap or full-file RAM reservation is
introduced here.
