# Judge projection of captured learning priors

A borrowed learning prior is a frozen snapshot. It does not follow later donor
outcomes, withdrawals, or window changes. Its borrowed weight and the configured
cap stay fixed at capture.

Judge score maps are the exception: they are projections over the original
judgments. Recording, replacing, or withdrawing a conversion projects captured
Beta and Mean priors without rewriting their source facts or evidence receipts.

## Stored numeric inputs

The internal learning-prior row holds the public prior and an optional frozen
fold. The public `Prior`, `Estimate`, and SDK shapes do not change. A projected
learning head carries its frozen fold beside its existing donor tally.

A fold contains the base prior and the raw numeric observations used by that
head. Each observation keeps its actual judge revision, when known, and its
capture-time effective weight. Form and measurement-version filters, window
fading, and audit weighting run before capture. Score conversion runs after it.
A conversion cycle omits the affected numeric observation from the value; a
withdrawal that heals the cycle can restore that frozen observation.

Projection uses the same conversion chain, numerical tally, and final fold as
ordinary learning evidence. It converts observations before pooling them. It
never converts an aggregate mean or guesses how to map a spread. Mean spread is
recomputed from projected second moments.

Nested borrowed priors retain their fold boundaries and their own fixed weights.
The borrowed cap is not applied by rescaling individual observations. No window
fading runs a second time. Supplied model, provenance, shipped, and owner-seed
base values with no judge provenance stay unchanged. Counts and count-only
labels are not numeric judge scores and need no conversion snapshot.

## Capture and lifecycle

Capture copies the selected stored head's fold in the caller's transaction. It
never reconstructs a frozen head by reading the donor's current evidence. The
vault-twin stored-prior path uses the same owner-seed precedence as its read.
Both generic learning capture and skill-reliability capture keep these inputs.

Frozen folds carry no donor-cell references, receipt references, outcome text,
or pack context. Nested base priors omit display provenance. The top-level
prior keeps the existing display provenance and scope-erase behavior. Numeric
inputs live in the original prior or head row and share that row's erase and
restore lifecycle. Judge changes do not rewrite the stored prior.

Conversion changes reproject cells with judged evidence and cells whose captured
prior contains a judge at any depth. Borrowed runs remain prior weight, never
own runs, labels, or citations. The frozen donor tally used for measured outcomes
is unchanged.

## Subject erasure

Hard-erasing a subject removes its registered learning cells, evidence, stored
priors, and subject-index rows in every scope. The same rule covers person and
skill subjects. Active, automatically approved observed learning heads retract
in place; their measurements and frozen folds stay as closed history. Existing
project rescoping and borrowed-provenance cleanup still apply.

The erase and restore re-scrub can close a head even when its subject row is
already absent. They do not create a replacement subject or a new claim edge.
The nightly projection sweep skips a registered cell whose subject is missing,
so that cell does not stop later cells from being projected.
