# Organ mesh reply memory

A serving organ host returns an `OrganOutcome`. Its existing frame lease covers
its decoded body and report while those values live. Moving these values into
a mesh `PeerResult` must not drop that lease before the result is encoded.

`mesh/serve.rs` keeps the result and its original frame lease in one private
`CallReply`. The result is declared first, so its values drop before the lease.
The holder survives result encoding and staging on both successful and failed
paths. Only the `PeerResult` is serialized; the holder is not a wire type.

This does not create a reservation or change any admission decision. It keeps
an existing reservation through the existing values' last use. A host without
a frame lease still uses the same path with `None`. Inputs, forwarded asks,
client reassembly, staged-file retention and disk-floor accounting are unchanged.

This is not complete mesh-copy memory accounting. Per-output inline copies,
encoded-result copies, reply encoding and `Get` piece buffers still need their
own exact allocation and last-use accounting. Spilled files are disk, not
retained payload RAM. No full-file RAM reservation is added here.
