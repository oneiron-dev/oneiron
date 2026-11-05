# Guest callable failure codes

The in-process code runtime returns host-call failures through its existing
`{failed: true, error?: string}` reply. The typed guest import throws the whole
reply as JSON text. A guest caller can inspect the `error` string on that reply.

The host uses a recorded native failure code when it is in
`GUEST_FAILURE_CODES`. Otherwise it uses an existing allowed diagnostic word,
or returns `{failed: true}` as before. Internal diagnostic messages are not
classified or released by this projection.

For a callable skill whose native proposal spool hits its disk floor, `error`
is the existing `SANDBOX_PROPOSAL_DISK_FLOOR` code. The original diagnostic stays
in the host outcome. This uses the code recorded by the native failure arm,
not a match on the diagnostic sentence or replacement byte counts.

The WIT reply is still a string. Existing guest JSON decoding and thrown-reply
handling need no component rebuild for this host projection. Old allowed error
words, failure-only replies, budget handling and successful outputs are unchanged.

This covers in-process `self.skills.call` replies only. A foreign microVM guest
whose proposal channel or name-gated network stream closes uses a different
transport. This change does not deliver a refusal reason on either of those
transports and does not close FIX 8994. It changes no guest image, wire frame,
retry rule, permission, disk reserve or numeric limit.
