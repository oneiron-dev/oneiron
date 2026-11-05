# Coach pilot answer release

Coach pilot `complete` and `get` forward the source rows already frozen in the
pilot to the facade's existing answer-release and invocation-replay checks.
The response DTO, pilot measurement and completion effect do not change.

- Before a measurement, the answer lists `release_source_rows`.
- Once measured, it lists `measurement_source_rows`.
- An unknown set stays `None`; it is not changed into a known empty set.
- A missing pilot and an unsuccessful call keep their known empty listing.

For an off-device destination, the existing release check replaces details with
`{"details_on_device": true}` only for a known recipient or placement hold.
Unknown provenance and failed hold checks still pass. Initial answers on this
device keep their existing release behavior. A completion stays committed even
when its reply's details stay on the device.

A waiter replay uses the same frozen rows with the existing current-read and
erasure checks before re-releasing the saved answer. It does not rerun the pilot
or undo its completion. These replay checks also apply on this device.

`PILOT_ROWS_NARROW_ANSWERS` in the server's `coach_offer_doors.rs` is now `true`
(previously `false`). Prepare already forwards its release's source rows and is
unchanged. No new source collection, storage format, configuration key, timeout,
cap, migration or deployment action is added.
