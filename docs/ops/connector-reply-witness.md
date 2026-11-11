# Connector reply witnesses

The served reply worker keeps each agent's reply to one connector event before
sending it through the recorded outbound pipeline. A completed reply job retains
its original event, agent and kept body. Witness repair uses that same context;
it never drafts, dispatches or charges another reply.

A delivered reply is witnessed immediately. A reply accepted as a remote task
keeps its original `deferred` dispatch outcome and an owed reply witness. Its job
completes without resending. Inbound witness repair still runs while delivery is
pending. An unchanged repair result does not append another artifact version.

For a deferred reply, repair rebuilds the original connector reply request and
looks up its native logical send. The index is only a lookup: the frozen intent,
agent, counterparty and other native binding fields must match. Only the ledger's
`Delivered` resolution proves the kept reply reached the channel. A missing,
erased, pending, deferred or abandoned row does not. Repair checks delivery again
inside the reply-witness writer and the result writer, alongside the existing
source, erase and read-grant checks. The original dispatch outcome stays
`deferred`; the new witness records the later delivery, not a second send.

The current served channel sink does not return remote tasks. This repair path
supports a transport that does, without adding one or claiming that such a
transport is active. The MCP remote-task poller is separate from the reply
worker; its provider status settles the ledger, never supplies a guessed agent,
event or reply text.
