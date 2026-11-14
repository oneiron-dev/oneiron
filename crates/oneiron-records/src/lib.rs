//! Engine-internal, not a public interface: the stored record types below `oneiron` (lib split, stage A), the serde
//! types no verb exposes with a schema: side-table payloads, receipts, queue rows and checkpoint parts. The module
//! tree mirrors the engine's, so a moved type keeps its relative path, and `oneiron` re-exports every item at its old
//! path.
#![deny(ambiguous_glob_reexports)]
