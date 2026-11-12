//! The wire types of the engine's public verbs below `oneiron` (lib split, stage A): every request, response and
//! value type that carries a JSON schema. The module tree mirrors the engine's, so a moved type keeps its relative
//! path, and `oneiron` re-exports every item at its old path.
#![deny(ambiguous_glob_reexports)]
