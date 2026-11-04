# Provider reasoning terminals

Reasoning can carry an opaque signature without visible text or separate data.
Signature presence counts as content, matching the owned stream's existing
ordered-part comparison. The signature is preserved unchanged; it is not parsed,
verified, rewritten, or promoted to text.

This applies to shared stream assembly, deterministic fallback terminal checks,
and owned-server generation and stream terminal checks. Existing text whitespace
rules, cancellation handling, invalid-content checks, and stream disagreement
handling stay in place. A reasoning part with empty text and neither signature
nor data remains empty.

This is terminal acceptance, not MESSAGE storage, custody authorization, replay
permission, or proof of an issuing login. It does not enable thinking or change
its effort, budget, wire shape, or capability declarations.
