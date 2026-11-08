# Native shared-vault Owner addition

`Vault::propose_add_owner(starter, vault_id, owner)` starts an `add_owner`
act for an existing live PERSON who is not already an Owner. The starter
must be a current Owner. The shipped policy has a zero-second wait and no
objectors. As with other shared acts, proposal does not change the roster:
call `Vault::execute_completed_shared_act` explicitly to apply the act.
An explicitly configured act policy is snapshotted and remains effective.

Execution rechecks the starter, executor and target in the same writer that
sets the target's Owner membership. Existing Owners keep their roles,
grants and slips. The target receives the normal Owner defaults and the
existing own-device grant handling. The receipt lists the membership grant
IDs returned by that mutation; it does not invent an own-device grant ID.

The receipt and durable outcome notices commit with the membership change.
Every current Owner and the added Owner receive a notice, including an
Owner who does not hold the act's execution verb. Re-running the executed
act returns the same receipt only to a recipient entitled to read it.
When a host issuer is supplied or available through the existing live-host
fallback, the same writer appends an `OwnerHandover` with cause `addition`,
the actual starter as `from`, the new Owner as `to`, and `from_keeps: owner`.
This is an audit record, not an independent source of Owner authority.
An addition retires no existing Owner's own-device grants.

This native slice does not add an HTTP, MCP or SDK proposal door. It does
not implement the common "owner changes wait N days" setting, trusted-contact
recovery, or property detachment. Transfer, removal, last-Owner protection,
ordinary member invitations, and vault delete/erase policies are unchanged.
A matching engine must understand the new `addition` cause and `owner_added`
receipt variant; no old-format reader or migration is provided.
