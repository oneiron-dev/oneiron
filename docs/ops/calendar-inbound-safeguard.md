# Calendar inbound safeguard

The owner's keyed value `calendar.inbound_safeguard.enabled` selects the
inbound calendar body screen. It is off unless the value is exactly `true`.

Served ICS feed polls, uploaded ICS imports (`vault.calendar.ics.import`), and
uploaded instance moves (`vault.calendar.instances.move`) use this same dial
and the host's installed calendar body screener. Native upload callers pass
that screener explicitly. Screening receives the event description and
available attachment text through the existing imported-claim admission path.

With the dial off, the receipt reports `skipped`. With the dial on and no
installed screener, it reports `indeterminate`, and admission evidence records
`calendar.safeguard.screener_absent`. An installed screener supplies its actual
verdict. A flagged or indeterminate verdict does not block admission, grant
approval, or turn imported body text into instructions.

The server exposes `install_calendar_label_head` for a host-supplied
`LabelClassifier`. This change does not load or install a production classifier.
Turning on the dial alone is not proof that a classifier examined the body.
Existing source custody, owner checks, passport comparisons, instance identity,
and imported trust rules still decide the import.
