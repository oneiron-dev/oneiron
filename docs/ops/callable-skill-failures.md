# Callable-skill failures

The host projection of `self.skills.call` keeps a native proposal-spool disk-floor
failure as `SANDBOX_PROPOSAL_DISK_FLOOR`. It does not classify diagnostic text.
The existing facade and MCP adapters can therefore report the storage refusal
rather than `INTERNAL_SERVER_ERROR`.

`RecordingJsHost::call_skill` records this code beside the failure's original
message and its measured `needed`, `available` and `reserve` byte counts.
Callable-depth cleanup, type feedback, post hooks and bridge recording still run.
The live callable adapter saves nested calls, outputs and bindings before it
returns the recorded failure to the caller. A failure without an explicit native
code keeps its existing internal-error projection.

The internal failed-outcome MessagePack map always contains `code`: a string
when a native producer recorded one, otherwise nil. It also always contains
`disk_floor`: a map of the three unsigned byte counts for the native floor code,
otherwise nil. The decoder requires both fields and rejects a floor code without
its facts or facts under a different code. Erasure replacements contain nil for
both, not the original failure code or measurements.

Failed-trap replay reconstructs the existing native
`CodeError::SandboxProposalDiskFloor` from those exact recorded counts. It never
parses the message or supplies replacement numbers. Erased replies still raise
`ResponseErased`; other generic failures keep their existing replay error.

This does not change the guest failure allowlist. It adds no disk floor, retry
policy or client error code.
