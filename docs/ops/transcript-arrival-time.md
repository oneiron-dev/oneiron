# File-drop transcript NOTE time

A nonempty transcript with no usable turns lands as an attributed NOTE.
Both the host helper and `vault.calendar.transcript.ingest` use the supplied
`arrived_at_ms`, converted to whole seconds by integer division by 1,000,
for the NOTE's occurrence range and learning time. The supplied arrival is
channel metadata, not an engine verification of when the recording occurred.
A delayed import does not replace that arrival with its later processing time.

The write still uses the native NOTE writer. The bound actor, source-world
placement, target check, prose admission, attribution edges and receipts are
unchanged. The store's mutation and edge recorded times still use its own clock.
Ordinary takes, notes and dissent notes continue to use their observation time.

No new input field, public clock override, time clamp or refusal is added.
SESSION and TURN timing is unchanged. Existing notes are not backfilled.
This does not add recording-time inference, transcript revisions or verified
speaker identity. Source-version pins are a separate transcript feature.
