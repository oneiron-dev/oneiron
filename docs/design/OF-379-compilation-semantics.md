# OF-379: compilation semantics for measured corrections

This is the bounded compilation rule for ONE-2073, extending ARCH-0056 §4 and the
OF-332 expression-preference claim family. It classifies *proposals*, not installed
policy or edits. A host-supplied `CompilationTarget` remains authoritative when
present; the automatic path runs only for `Fallback` and only for a correction
bound to an authenticated human principal. Unbound/historical evidence remains
audit-only. Neither generated text nor a scope alone is a grant of authority.

At ≥K distinct, live, judged amendment receipts in the same principal, scope,
actor and normalized substitution, evaluate the validated `compilation_policy`
rows in trusted policy manifests against the changed run (`from` → `to`).
The same applies to principal-bound inbox amendments. No row means no inferred
family, but ordinary fallback mining still runs. The shipped default manifest
carries the following *editable data*, not a fixed engine grammar. Its `order`
row lists precedence; its `routes` carry scope and text selectors, enabled
family choices and the optional OF-332 style-atom constraint:

1. A scope `expression.style:<subject>` and an OF-332-valid lowercase style
   token as the entire replacement → `preference.style_rule` with that token.
2. A scope `charter:<subject>` → `charter.line` with the corrected run as text.
3. A scope `brief:<subject>` → `brief.preference` with the corrected run as text.
4. Outside those typed scopes, a replacement beginning `never `, with the
   removed run not beginning `never ` → `preference.ban` with the entire
   corrected run as text. This is a narrow, affirmative prohibition signal,
   not a general-purpose intent classifier.
5. Otherwise preserve ARCH-0056 §4: tone-lexicon substitutions propose
   `preference.phrasing`; content substitutions propose a skill edit if a
   common skill is named. No skill means no content proposal.

The shipped selectors require a nonempty subject after each typed scope colon.
A holder row may narrow the vault row through `parent` holder rows; all matching
rows must permit the same family and correction. The validated precedence is
`nested_narrowing_holder_capped_at_vault`; holder rows cannot bypass the vault
row even if their selectors are broader. Trusted packs also intersect. Every
matching route must still pass the claim-shape validator. Changing, disabling,
or reordering the selectors is manifest authoring, not a Rust edit. The route and text
are derived from the *actual corrected run*, never from a model suggestion,
freestanding scope, or generated proposal. Normalization (case folding and
whitespace collapse) and the existing short substitution bound apply before
classification. A pure insertion, deletion, large rewrite, or unresolvable Δ
never becomes an automatic target. This intentionally leaves ambiguous
corrections in the old arms. This is not an NLP interpretation of arbitrary
instructions; widening the grammar requires another documented ruling.

Every emitted claim remains `Proposed`, principal-scoped, bitemporal, and
Dreamer-authored through the ordinary write gate. Its evidence entity holds
its class, target, exact normalized pair, distinct receipt ids and time. The
claim's candidate evidence references that entity with `Inferred` source;
its write envelope carries the Dreamer run, session and cluster provenance.
The decider must still approve a claim; a style proposal cannot directly
supersede the acting OF-332 expression head, and charter/brief proposals do
not mutate those documents. Existing evidence age/decay and rejection cooldown
apply to all four families; the mint-mark prevents repeated live proposals.
Unknown deltas retain the existing phrasing/skill-edit behavior.
