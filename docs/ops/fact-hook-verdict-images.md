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

This implements only the image-read residue of FIX 1656 / OF-580. It does
not change hook grant storage, evidence predicate/world matching, session
hook resumptions, or transcript-import hook behavior. No new configuration,
credential setup, timer, or operating limit is required.
