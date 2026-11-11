//! Consent state below core (core split slice 2): the consent grant, marker, bypass, effect and
//! tool-scope state, the code-wait state enums, call site and answers, and voice consent.
//! `oneiron` re-exports every item at its old path.
#![deny(ambiguous_glob_reexports)]

pub mod code_run;
pub mod connector_key;
pub mod consent;
pub mod gate;
pub mod llm;
pub mod memory;
pub mod runtime_hooks;
pub mod verbs;
