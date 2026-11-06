# Shared-vault member credentials

A member credential is bound to the exact live `FEDERATION_GRANT` named by
its signed `grant_ref` and to that grant's live PERSON holder. Ordinary
membership excludes delegated grants; delegated credentials keep their
existing parent and issuer checks. Own-device, Ask and Connect credentials
keep their existing admission paths.

Verification meets an ordinary member's authenticated effective Scope with
the current membership grant on all six axes: worlds, facets, bands,
audience, verbs and sensitivity. This changes only the verifier's effective
view, not the signed token, holder transfers, record bounds or channel bounds.
The current member bound recognizes `read` and `core:read` as the same read
permission for both the meet and cached-scope comparison. The effective view
keeps the authenticated request's spelling; other verbs are unchanged.
A role change that rewrites the same grant id therefore cannot leave fresh
requests carrying the old role's authority.

Proof-backed read keys take that current member bound in their own snapshot.
A cached proof whose Scope exceeds any current membership axis is no longer
live for a writer or cached read. A new holder-signed request can obtain the
narrowed view. Slip-id-only sessions cannot express a narrower effective view;
if the original mint exceeds the current membership Scope, their liveness
check fails rather than continuing with the old Scope.

This is the native verification and scope repair. Credential issuance at
invitation acceptance and dedicated environment enrollment are separate host
operations; this repair alone does not provide those operations.
