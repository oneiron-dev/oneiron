# Hosted policy row references

A host registering `HostedLegalPolicy` supplies an actual external basis for
**every** `HostedLegalRow`. The engine does not supply a law, provider term,
capacity policy, category vocabulary, or policy document.

Each row's `basis` has three fields:

- `kind`: `law`, `provider_terms`, or `capacity`.
- `subject`: the jurisdiction, provider, or resource the bound concerns.
- `reference`: the actual law, provider term, or capacity reference. This can
  be a human-readable citation or resource identifier; it need not be a URL.

The subject and reference must not be blank. Registration checks their shape,
not whether a law applies or a provider term is correct. The host remains
responsible for that content. Do not put candidate content or a classifier's
rationale in these fields. The row text, action, category resolution and policy
output contract still govern classification as before.

The derived policy hash covers every row's basis, including its kind, subject
and reference. The hash domain is `oneiron.policy_model.hosted_legal.policy.v3`.
Changing a reference changes the policy identity that a receipt attests.

A selected hosted verdict carries the actual registered row's `basis`.
The hosted relay door adds `policy_hosted_bound_selected` reader notices
with that basis. Its existing decision notice and self-host/BYO affordance
remain in place.

An outage is not a selected policy violation. Its verdict still has no selected
row. `HostedRelayDecision.outage_bounds` lists the configured rows and their
bases as unresolved checks. The door emits `policy_hosted_bound_configured`
notices for those rows, not selected-row notices. The outage notice names the
actual `RelayBoundaryDegrade` code. A halt also retains the host's configured
unavailability text and self-host/BYO affordance; a receipted proceed does not
claim that content was withheld.

Notices go to the person and model with the same body. Long reference bodies
are kept whole across ordered notices using the ledger's existing per-notice
body limit. No additional row count or reference length cap is introduced.
Consumers that show the full explanation should render `system_notices`, not
only the first-body convenience field `system_notice`.

`HostedOutagePolicy`, its default, the row actions, owner-plane policy, local
execution and self-host/BYO routing are unchanged. Reference metadata is not
an authority credential or proof that an obligation applies.

This mechanism does not install a concrete hosted policy. The hosting operator
must supply its real references and applicable row text at registration.
