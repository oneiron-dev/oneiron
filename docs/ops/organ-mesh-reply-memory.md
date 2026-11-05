# Organ mesh reply memory

A serving organ host returns an `OrganOutcome`. Its existing frame lease covers
its decoded body and report while those values live. Moving these values into
a mesh `PeerResult` must not drop that lease before the result is encoded.

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

This does not create a reservation or change any admission decision. It keeps
an existing reservation through the existing values' last use. A host without
a frame lease still uses the same path with `None`. Inputs, forwarded asks,
client reassembly, staged-file retention and disk-floor accounting are unchanged.

If staging an output fails after the organ has run, the existing failed reply
keeps the ask receipts collected by that run. Failures before a run still carry
no ask receipts. The failure kind and detail do not change. Keeping these
receipts does not retain or replay the completed outcome.

This is not complete mesh-copy memory accounting. Inline copies from mapped
outputs, encoded-result copies, reply encoding, the output-guard vector and
`Get` piece buffers still need their own exact allocation and last-use
accounting. Keeping a source output's existing budget reservation does not
establish a new machine-floor reservation or prove its original capacity was
fully accounted. Spilled files are disk, not retained payload RAM. No full-file
RAM reservation is added here.
