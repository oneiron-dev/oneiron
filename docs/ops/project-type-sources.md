# Project task-type source rows

`agent_dispatch::load_vault_type_tree_sourced` returns the vault tree and each
requested project's selected team-shape head. A project's source list names the
stored entity rows behind the same snapshot's project visibility and skill
selection. The crate-private `load_vault_type_tree_sourced_in_txn` runs that same
selection in a caller's existing snapshot or writer; the public wrapper still
opens one read transaction. Neither grants access or replaces visibility checks.

The crate-private `load_team_type_tree_with_sources_in_txn` instead returns the
actual tree selected for one project (or the vault), its entity-row inventory and
the root lookup's audit metadata. It resolves the root once and reads that tree
once in the caller's snapshot or writer. A consulted default-hub alias/pin makes
the whole entity-source inventory unknown; the `HubRef` remains audit metadata,
not a substitute entity ID. Other unknown source cohorts stay unknown. The old
audit-only `load_team_type_tree_sourced_in_txn` is unchanged.

The project reader records every stored project row and indexed revision
companion its component, parent and witness decisions read. Its authority fold
keeps the actual stored log row IDs from its existing scan.
A cache hit shares that inventory with the same immutable authority view,
except that agent-carried Grant inputs remain unknown on cache hits. A
store-order resume includes its guarded baseline and actual tail row IDs. The
fork and lineage walk also records the skill rows it consults. The selected
head, first-loadable-fork order, errors and ordinary unsourced reads are unchanged.

`None` means that the complete entity-row inventory is not known. An adopted
authority image, an unstored arriving operation, untracked agent-carried Grant
reads or peer-consent inputs do not become a partial known list. Missing project
rows and a trial's uncommitted project overlay also remain unknown. A caller must
keep this distinction from an empty, known source list.

The list covers entity rows. Clock, policy, index and hash-keyed history metadata
are not entity IDs. Source rows are evidence data, never a credential, Grant,
new read scope or proof of a different caller's access. No new admission rule,
refusal, configuration value or persisted format is introduced.

FIX 7267 remains partial for the unknown source cohorts. Broader team dispatch,
input and receipt capture (FIX 7264/7289) is separate and must compose the complete
source bank, not treat pending source as main.

## Agent-carried Grant rows

When an uncached read-only authority view already has a complete stored-entity
source inventory, its agent-carried Grant check adds the exact live Grant rows
read in that same transaction. The standing decision uses those same bytes once; a live
row of another type or an invalid Grant body still contributes its entity id.
This does not change which acts stand or are held back.

A missing or deleted Grant, a positive withdrawal marker, a marker read fault, or
another Grant read fault keeps the whole source inventory unknown. Marker faults
still take the existing standing path, and Grant read faults still warn and trust
the carrier. Prior-standing WorldPrivacy evaluation also keeps sources unknown:
its adopted history and causal-point caches do not yet carry a complete same-view
entity inventory. An authority cache hit with agent-carried acts likewise
keeps sources unknown: its key alone does not certify the caller's Grant reads.
The cached decision, key and continuation stay unchanged. No Grant overlay
upgrades an already-unknown base inventory. Withdrawal markers and missing-row
metadata are not negative-proof entity rows.
