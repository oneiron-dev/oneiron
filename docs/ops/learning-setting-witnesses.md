# Numeric owner-setting witnesses

A successful numeric owner seed or pin writes one native CLAIM with predicate
`vault.learning_setting.put`. The CLAIM and the authoritative setting row commit
in the same owner-verified transaction. Failed writes leave neither behind.

The claim records the actual owner's put act. Its value contains only the setting
key, seed or pin mode, and scope tag (`vault`, `goal`, `project`, or `type`). It does
not copy the reason, numeric value, scope ID, or task-type node. The native write
envelope records the verified human owner, `UserStated` source, and `Approved`
status. The setting row remains the only authority for the numeric value.

A sourced setting read carries the witness from the exact seed or pin row that
won the normal scope walk, in the same snapshot. A live, active witness returns
its actual CLAIM ID. A missing, erased, or closed witness returns unknown
provenance without changing the setting value. Catalog and fitted-value source
rules do not change.

Replacing or clearing a setting does not retract its earlier put acts. They are
historical records, not claims that an old value is still in force. Scope erasure
deletes its setting rows as before; the act contains no scope ID. Actor erasure
clears the setting's witness pointer alongside its setter identity and preserves
the existing numeric value and other row terms. This does not claim to erase all
actor references in historical claims.

Numeric setting rows use format version 2, with a witness field. There is no
version-1 reader or migration. Owner inputs, list responses, typed spawn-choice
rows, fit learning, and clear semantics are unchanged.
