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

## Unchanged fallbacks

- No carried zone, or a zone the embedded database does not know, keeps
  the exact frozen-offset path.
- A send with no frozen offset keeps the caller-frozen minute path and
  the same fail-closed hold for unevaluable interrupt claims.
- Recorded-clock advance, `spent` math, and `occurred_at` handling are
  unchanged.

## Unchanged policy

- User quiet hours and allowed windows evaluate as before; only the
  offset input at the same instant can differ.
- Human-explicit instants keep their exemption and lift.
- Seed merge (`most_restrictive`), gates, retry edges, subjects, and
  explicit-instant handling are unchanged.

## Boundary

This covers the daylight-saving slice only. Travel or current-route zone
changes without a host signal are not closed here: the TASK keeps its
frozen label until a host zone refresh replaces it.
