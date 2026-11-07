# MCP verb-hook resume ceilings

A tool-first MCP call paused by a verb hook records the registration that admitted
it: the actor, world, read facets, write facet and bound tool names. It records no
credential token. Settlement still verifies the original instrument, resolves the
live registration, and proves that full live registration against the credential.

The resumed call then uses the intersection of its original and live registration.
A changed actor, disjoint worlds or disjoint facets do not acquire authority from
the saved record. Tool names remain capped by both registrations. Write placement
uses the existing facet placement rule within the intersected read facets. The
normal door admission and each rewrite's admission still run on that context.
An unchanged registration follows the existing path without normalization.

The drain also carries the original door as identity metadata for its own
invocation. The resumed hook boundary uses that door for the existing exact
saved-caller check, while execution still uses the capped live context. A normal
retry receives no such override. Credential and paced drains attach the metadata
only after their existing witness checks; the caller/outcome matching rules stay
unchanged.

This covers MCP registration changes, including a narrower registration of the
same credential. It does not replace the original instrument with a successor,
change the instrument's own ceiling check, or change code-job admission: a saved
code job still requires its exact original registration. Managed-owner streams
keep their existing live-owner path. The full credential-resume row remains PART.
