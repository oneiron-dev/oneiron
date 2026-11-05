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

A certain release removes only its exact IDs. The existing key-only interim
non-delivery retry restores the original ID, amount, and accounting time as
reserved, only after the existing all-row capacity preflight. Uncertain, mixed,
and charter-backed retry behavior is unchanged. Charter approval guards still
protect current counters.

Both states expire under the same rolling or calendar window rules. Missing or
reset entries are not recreated by marking or release. The raw usage codec
requires the new four-field entry `[id, at, amount, reserved]`; reservation debits
require `entry_id`. There is no old-format reader or migration.

## Remaining scope

FIX11027 remains PART. Ladder signals still fire from combined charge-time usage;
no Done-time steering channel or settled-only ladder policy is added. Charter
non-delivery retry release remains separate. This document states the source
contract, not a compile, runtime, delivery, or timing result.
