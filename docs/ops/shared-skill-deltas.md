# Shared skill delta roles

`Vault::submit_shared_skill_delta` derives the candidate from the submitted
package files. It does not read the source vault. The receiving base must be an
active skill with the same skill identity and a different version and content.

For a Callable base, an edit with neither a declared role nor a declared call
keeps the base's role and call contract only when the retained call reference
names an exact UTF-8 file in the submitted tree. The inherited contract is
candidate metadata, not a declaration added to `SKILL.md`. The package keeps its
Folder representation; it does not pass through Native frontmatter hydration.
A declared role or call disables this Callable inheritance.

If the retained reference is absent or non-UTF-8, submission keeps its existing
parsed Knowledge/None behavior. This change does not add a refusal or claim to
resolve that remaining case. The existing non-Callable role inheritance is
unchanged.

Submission still creates a Candidate. The base binding, exact submitted bytes,
capability checks, import scan, useful-upstream question and held-out replay
remain in place. An accepted merge activates the candidate with its retained
role and call contract, then supersedes the base. No new owner-consent rule or
permission is added.
