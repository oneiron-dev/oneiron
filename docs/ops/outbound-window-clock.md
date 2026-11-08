# Outbound delivery-window clock

How a drained connector send picks the local minute its delivery-window
claims evaluate against.

## Frozen TASK clock

The schedule chokepoint freezes the host clock authority on the TASK:
`utc_offset_minutes` and the `iana_timezone` label. The drain seeder
replays both onto the dispatch request: the frozen offset seeds the
initial local minute and the drain clock, and the frozen IANA label rides
alongside for delivery-time resolution.

## Delivery-time resolution

The window door reads the vault clock again for the send and evaluates
at the same recorded-clock `evaluated_at` as before. At that instant it
resolves the carried IANA label to its offset; the chosen offset feeds
the local minute. This keeps the evaluation on daylight-saving-correct
civil time when the label resolves.

## Future retry edges

For a clocked send with a known frozen IANA label, each matched quiet or
channel window finds its first future UTC minute boundary outside that
window under the same native zone offsets. It does not treat a civil-minute
difference as elapsed UTC time. This keeps a retry on the correct side of a
spring-forward gap or a repeated fall-back hour. A fold can open a window
before its nominal wall-clock end; that first opening is the retry edge.

The zone is resolved once per window against the existing embedded 2026c
database. The matched evidence, observed hold and effective hold receive the
same retry time. Named-zone retry edges now land on the actual minute
boundary instead of carrying the send's seconds past it.

## Unchanged fallbacks

- No carried zone, or a zone the embedded database does not know, keeps
  the exact frozen-offset path.
- A send with no frozen offset keeps the caller-frozen minute path and
  the same fail-closed hold for unevaluable interrupt claims.
- No usable zone, an out-of-range conversion, and previews that carry only
  an epoch and local minute retain the original nominal retry arithmetic.
- Recorded-clock advance, `spent` math, and `occurred_at` handling are
  unchanged.

## Unchanged policy

- User quiet hours, window predicates and policy applicability are
  unchanged. Future retry edges now use the frozen zone's offsets.
- Human-explicit instants keep their exemption and lift.
- Seed merge (`most_restrictive`), gates, subjects, and explicit-instant
  handling are unchanged. No timer, default, cap or delivery policy is added.

## Boundary

This covers the daylight-saving slice only. Travel or current-route zone
changes without a host signal are not closed here: the TASK keeps its
frozen label until a host zone refresh replaces it.
