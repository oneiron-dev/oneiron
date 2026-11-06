# Machine-history pin freshness

Own-device sync uses the existing machine-history round to ask the home to prove
whether a local trusted handoff pin matches the home's pin. The round also runs
this optional exchange when no history is owed, or when local rows settled every
debt before a fetch was needed. No new timer or polling interval is added.

Only locally pinned targets without a `Latest` proof are candidates. Pin keys
are discovery hints, not authority. Before sending a target id, the client reads
its current claim and indexed history controls and checks the home against every
actual residence window, using the same home-world authorization as history
fetches. Missing, malformed or unreadable local metadata omits that optional
request. Federation peers do not enter this own-device path.

The server still checks the proven machine, residence selector and target
admission. Answers still use the existing vault-, machine-, target- and
nonce-bound signed transcript, trusted owner root and authority-head validation.
A freshness answer does not install a pin or fetch missing history. `Latest`
records the accepted signed observation, not a promise that the home can never
advance afterward.

The exchange is best-effort. An unavailable home, failed scan, refused request
or invalid proof leaves the original empty history round successful and its pin
unchanged. A pin already proven `Latest` causes no additional call, matching the
existing quiet-round behavior. There is no new storage schema, migration,
configuration, signing format or operational default.
