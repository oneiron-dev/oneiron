# Shared-vault owner-change defaults

The shipped shared-vault policies for `transfer_ownership` and `remove_owner`
have `wait_secs: 0` and no objector roles. This follows the D1=B ownership ruling
of 2026-11-03. There is no mandatory objection window for these two operations
when their shipped defaults apply.

The existing flow still has two operations:

1. Propose the transfer or removal with the authenticated owner door.
2. Execute the completed act with `Vault::execute_completed_shared_act` (or the
   corresponding `vault.shared.execute` door).

A zero-wait proposal is completed immediately; it does not execute the mutation
by itself. Execution still revalidates the live owners, keeps at least one live
owner, applies the native handover, and records the receipt and owner notices.

`SharedActPolicy` remains the per-act policy surface. A stored policy can opt
into a wait with `wait_secs` and objector roles. Existing stored policies,
host/holder selections, and pending acts keep their existing behavior. Changing
a policy affects new acts, not the snapshotted window of an existing act.

The shipped `delete_vault` and `erase` policy rows still specify 604800 seconds
and owner objectors. This change does not alter their existing execution or
sole-owner rules.

This slice does not add steady-state owner creation, automatic proposal
execution, a common wait-in-days setting, property detachment, or trusted-contact
recovery. It needs no migration or manual policy rewrite.
