# Callable-skill failures

The host projection of `self.skills.call` keeps a native proposal-spool disk-floor
failure as `SANDBOX_PROPOSAL_DISK_FLOOR`. It does not classify diagnostic text.
The existing facade and MCP adapters can therefore report the storage refusal
rather than `INTERNAL_SERVER_ERROR`.

`RecordingJsHost::call_skill` records this code beside the failure's original
message. Callable-depth cleanup, type feedback, post hooks and bridge recording
still run. The live callable adapter saves nested calls, outputs and bindings
before it returns the recorded failure to the caller. A failure without an
explicit native code keeps its existing internal-error projection.

The internal failed-outcome MessagePack map always contains `code`: a string
when a native producer recorded one, otherwise nil. The decoder requires the
field. Erasure replacements contain nil, not the original failure code.

This does not change the guest failure allowlist or the generic failed-trap
replay behavior. It adds no disk floor, retry policy or client error code.
