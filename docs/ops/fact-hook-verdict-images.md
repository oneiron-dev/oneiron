# Fact-hook verdict images

A generative fact hook can pass an ASSET image handle to `ai.verdict`. The
host resolves it under the actual hook binding's grant reader and actor
class. It does not borrow a caller credential, owner authority, or a
browser screenshot.

Image reads follow the same non-claim-row rule as the hook's evidence:
ASSET rows carry neither a claim predicate nor a world, so a grant that
names any predicate or world does not show an image. An unrestricted
predicate/world list still requires the grant reader's ordinary scoped
read to admit the ASSET. A restricted hook can continue asking text-only
verdicts and reading the claims its grant shows.

The ordinary image pull checks the handle's content hash, reads the
admitted ASSET bytes, applies the existing secret-sight masking, and
records the served-form receipt before pixels reach the model. The image
keeps its ASSET id and body version in the verdict's evidence. Missing,
withheld, changed, or non-image assets are not replaced by thumbnails or
text.

The verdict uses the existing Local-vision rung and the hook's pack
budget line. Its payer, deadline, settlement capture, and evidence grant
filter are unchanged. Ordinary SDK image lanes and held browser images
keep their existing paths.

This image path implements the image-read residue of FIX 1656 / OF-580. It does
not change hook grant storage, evidence predicate/world matching, session
hook resumptions, or transcript-import hook behavior. No new configuration,
credential setup, timer, or operating limit is required.

## Evidence revision and grant

For text evidence, the hook's predicate and world lists are checked against
the exact raw CLAIM revision that the reader projects to the verdict. A
pinned ref is judged at its retained revision, not against the current live
body. A concurrent claim update cannot make a previously hydrated body pass
a different revision's predicate or world check.

Ordinary reader admission, legal-order refusals, secret masking, provenance
and served-form receipts still use the native hydration path. Absent or
reader-withheld refs keep their ordinary errors; additional hook-grant
denials are returned by id to the host log without their bodies.
Unrestricted grants and non-hook verdicts keep ordinary hydration. No new
refusal policy, timer, limit, configuration or credential is introduced.
