# Entity-resolution routing bands

The evidence-backed entity-resolution waterfall reads `entity_resolution_bands`
from the trusted policy-manifest fold in the same write transaction that scores
its candidates. Candidate confidence still includes the provider's active prior.
No caller-supplied threshold replaces the manifest.

## Row and defaults

```json
{
  "entity_resolution_bands": {
    "provisional_below": 0.50,
    "soft_link_low_below": 0.70,
    "soft_link_below": 0.90
  }
}
```

These are finite `f32` values. All three fields are required when the row is
present. Missing, duplicate, unknown or nonnumeric fields make the row malformed
under the existing manifest decoder. There is no `[0, 1]` constraint or strict
ordering constraint. Equal or reversed cutoffs can leave an intermediate band
empty. A boundary above one can intentionally keep candidates out of a higher
band.

The existing cascade remains, in this order:

1. No candidates, or top effective confidence below `provisional_below`:
   `ProvisionalEntity`, no selected subject.
2. Otherwise, below `soft_link_low_below`: `SoftLinkLow`.
3. Otherwise, below `soft_link_below`: `SoftLink`.
4. Otherwise: `HardLink`.

Both soft routes request asynchronous verification. A hard link requests it only
for a high-collision mention. The waterfall itself mints nothing; its existing
ingest caller decides whether to mint after a provisional result. Existing
archive and task-attempt restoration stays in the original resolution path.

When no trusted row is present, the exact existing `f32` defaults remain
`0.50`, `0.70`, `0.90`. The shipped manifest need not be rewritten.

## Trusted manifest composition

Quarantined and untrusted packs do not contribute routing bands. The native
manifest-origin classification separates untouched seeds, authenticated authored
rows and other trusted narrowing contributions. Authored rows replace seeds.
Within each group, each boundary is the maximum of the contributed values. The
selected authored-or-seeded result then combines with narrowing contributions by
the same component-wise maximum. With only narrowing contributions, those values
are the result. Compiled defaults participate only when every group is absent;
they never cap an explicit owner setting.

A present resolved row contributes its three `f32` bit patterns to the policy
frontier. An absent row adds no hash material. An owner edit uses the existing
policy writer, receipt ledger and post-commit rebind path.

## Native owner API

The public `oneiron::policy_manifest_doors` namespace exports:

- `EntityResolutionBands`
- `entity_resolution_bands_as_owner(vault, owner)`
- `configure_entity_resolution_bands_as_owner(vault, owner, request)`
- `EntityResolutionBandsConfigureRequest`, `EntityResolutionBandsView` and
  `EntityResolutionBandsReceipt`

Read first. The view returns the trusted default manifest's `manifest_ref` and
`body_hash`, plus the **effective** folded bands. Configure with that
`expected_body_hash` and a complete `bands` value. The owner proof and hash are
checked inside the same write transaction. Only this field is replaced, through
the existing owner manifest writer. The receipt reports the post-write effective
bands, so a separate installed trusted contribution is not hidden by the value
written to the default manifest.

This change adds no HTTP, MCP or generated SDK door. A host can use the native
API. No configuration-file, dependency, storage-version or migration change is
required. Existing mention requests and caller signatures are unchanged.
