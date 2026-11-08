# Effector usage reservations and settlement

Each live effector usage entry has a native `entry_id`, accounting time, amount,
and outbound reservation state. The ID is allocated by the store clock and its
allocation floor commits with the usage write. It is not an intent ID, a grant,
a timestamp, or a permission. Separate debits in the same second remain distinct.

## Read fields

Every `EffectorBudgetRowRead`, including a catalog-pool row, reports:

- `used`: combined live usage held against admission capacity, saturating at u64.
- `reserved`: live usage held by a pending outbound reservation.
- `settled`: live usage not held by an outbound reservation, including direct
  gate, wake, logical-send, batch, and spend-settlement charges.

These are accounting states, not universal provider-delivery proof. A direct
charge without an intent reservation is settled here; the field does not claim
that an external provider acknowledged it. `remaining`, `percent_used`, pacing,
suspension, and `fired_thresholds` continue to use combined usage. No existing
limit or admission policy changes.

## Native lifecycle

A new charge creates a settled entry. Outbound admission marks the exact returned
debit IDs reserved in the SAME writer that inserts Pending and its reservation.
The carried charge read is refreshed after those marks in that writer. It is the
admission snapshot, not a later read after transport completes.

Done marks the same surviving IDs settled in its terminal writer. If the
provider reports actual spend, native reconciliation removes the exact estimate
entry and writes a fresh settled actual-cost entry before marking the surviving
reservation set. Zero estimates and unpriced targets have no estimate entry to
mark. Other actual-cost and approval checks stay unchanged.

A certain release removes only its exact IDs. Key, charter, and mixed
non-delivery retries restore the original ID, amount, and accounting time as
reserved, only after the existing all-row capacity preflight. Each charter
debit's original approval must still match before it joins that preflight;
obsolete approvals cannot recreate usage in a newly approved positional row.
Uncertain delivery retains its reservation. Original zero and unpriced spend
targets remain available for the same approval-checked actual-cost settlement.

Both states expire under the same rolling or calendar window rules. Missing or
reset entries are not recreated by marking or release. The raw usage codec
requires the new four-field entry `[id, at, amount, reserved]`; reservation debits
require `entry_id`. There is no old-format reader or migration.

## Confirmed-delivery warnings

Admission keeps its existing early warnings. Confirmed Done also checks the
send's own surviving non-Spend entries after settlement, in that SAME terminal
writer. It uses each original charter approval, actual entry ID, amount and time,
and the current row's native window. Expired, missing, reset and obsolete-approval
entries emit nothing. Spend remains outside incremental ladder delivery (M3b).

Both paths use combined live usage and ONE per-window `fired` memory. Done emits
only crossed thresholds not already fired: it never repeats an admission warning.
For example, a certain non-delivery releases an entry, a later rolling-window
touch re-arms a threshold, and the retry restores that original entry without
firing. Its confirmed Done can now emit the still-unfired threshold once. This is
not a settled-only capacity or warning percentage.

Events leave the terminal transaction only after commit and force-sync, beside
the record. Synchronous New and Resume carry them separately from the admission
charge, so a charge-less resume needs no invented charge or meter snapshot.
`OutboundDispatchResult` and `ScopedMcpDispatchResult` expose the key-owned events
and `steering_messages()`. A scoped call includes those messages in its existing
`budget_steering` reply on both Delivered and AwaitingInput. Status and audit
replay emit no messages.

`Vault::settle_remote_outbound_task` returns `RemoteTaskSettlement`, not just an
`IntentState`: its state, key-owned budget events and `steering_messages()` belong
to that committed observation. The trusted status caller forwards them to its
existing next-turn steering queue. No second ledger, durable warning queue or
background publisher is added. A process failure after commit can still lose the
reply; a replay does not re-emit a fired event.

## Remaining scope

FIX11027 remains PART for host-side consumption beyond these native return
contracts; the ordinary dispatch's existing raw ladder-event field has no
in-repository reader. No universal next-turn injection, crash-replay delivery,
compile, runtime, delivery or timing result is claimed here. Charter
non-delivery retry release and restoration retain the original approval binding.
