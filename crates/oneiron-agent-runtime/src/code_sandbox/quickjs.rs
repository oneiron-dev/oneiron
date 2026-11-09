//! Hash-pinned, readiness-checked QuickJS artifact factory.
//!
//! The deployer supplies a component built by `components/code-run-quickjs/build.py`
//! and its SHA-256 from the reviewed manifest. No source runs in a native JS engine.
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::quickjs::*;

