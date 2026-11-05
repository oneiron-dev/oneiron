# Charter approval and reserved budget

A connector charter approval resets its compiled-cap usage rows in the same
transaction that applies the reviewed charter. The reset applies even when the
owner approves identical text and compiled policy again.

Each approval has a fresh `approval_id`. The text/compiled aggregate remains the
reviewed-policy binding; the ID distinguishes approval acts, not permissions.
Connector-key body schema 5 requires this ID in an approved charter. There is no
old-format reader or migration.

## Reservation and settlement

The original admission records the approval on each charter debit and on every
preauthorizing spend target. The latter includes zero estimates and unpriced
rows, which can have no estimate debit. Per-key rows and catalog-pool rows keep
their own original approval binding.

When a send certainly stops without delivery, release checks the current
same-key approval in the consuming writer before touching charter usage. If the
approval changed, the old reservation no longer names the current counter and
leaves it untouched. Key-row release names the original native debit ID rather
than choosing a timestamp/amount occurrence.

When a delivered send reports actual cost, reconciliation performs the same
check separately for each original spend target, before removing an estimate,
touching a window, writing actual usage, or suspending the key. An obsolete
charter target cannot charge a newly approved positional cap. Other matching
key or charter targets still reconcile normally. The reservation and reported
cost remain attached to their original send.

Approval, usage reset, operation receipt, and the existing ID floor commit in
one writer. Reopening the vault therefore does not turn a body-only approval ID
into a reusable allocation. No second accounting ledger or clock is added.

## Scope

This fixes current terminal release and Done-time spend reconciliation. It does
not enable charter-backed non-delivery retry release or change uncertain or
mixed retry behavior. [Reserved-versus-settled budget projections](effector-usage-lifecycle.md)
now use those same native debit identities. The timing of budget ladder signals
is separate work. Existing admission, limits, pricing, owner checks, and the
text/compiled approval checks remain unchanged.

This is a source contract, not a runtime or timing measurement.
