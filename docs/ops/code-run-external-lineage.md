# Code-run external reply lineage

A code run keeps `Generated` as its claim source. After an observed external
reply, later claim, edge, SDK-verb, team and repository write envelopes also
carry `ToolOutput` in their source lineage. The dispatcher reconstructs this
from its recorded bridge history, so reopening a recorded step uses the same
reply evidence.

For SDK `AgentVerb` rows, the classifier reads the actual recorded verb and
returned typed reply. `connector.call` adds lineage for a delivered tool result
or connector questions (`awaiting_input`). A connector-backed `self.use` does
the same only when its actual use receipt names `connector.call` and its
returned result contains that connector reply. A use with no returned result
adds nothing. The current secret-use producer withholds connector questions
and returns no result for that case; the classifier does not reconstruct them.

Other SDK verbs, refusals, failures, held calls, pending deliveries and delivered
answers without a tool result add nothing. In particular a pending hook ask is
not evidence that an external reply was observed. No grant or admission decision
changes, and no replay field, public DTO or stored format is added.

This slice covers actual replies recorded in bridge rows. A reply delivered
later to a durable connector wait is stored separately as a `wait<N>` result,
not as an answered bridge row. Its lineage still needs actual settlement
provenance; FIX 9699 remains partial for that path. The classifier does not guess
that a parked call must have returned foreign data.
