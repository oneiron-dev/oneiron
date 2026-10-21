//! The answering house llama.cpp process's launch alias (FIX 7895, 6567
//! PR1b): which incarnation answered a call, as the call's own reply names
//! it, never as a label the engine configured.
//!
//! The house launcher mints one random epoch per llama.cpp launch, writes an
//! immutable identity manifest for it, and starts the server under exactly
//! one alias, `oneiron-llama/<epoch>/<manifest digest>`. llama.cpp returns
//! that alias as the `model` of every answer and as its model-list id.
//!
//! The alias names no model: every valid alias on a route is that route's
//! one configured model. [`returned_model_wire_id`] maps it to the route's
//! configured wire id for model comparisons and labels; the epoch and the
//! manifest digest are the cache evidence's, not a model key. This is the
//! one parser: a reader that sees the namespace calls it, never a second
//! split or hex check of its own.
use super::cache::{CacheDigest, CacheEpoch};

/// The namespace every house llama.cpp launch alias opens with.
const LLAMA_ALIAS_PREFIX: &str = "oneiron-llama/";

/// A house llama.cpp launch alias, read: the launch's epoch and the SHA-256
/// of its identity manifest's exact bytes. It references the manifest; it
/// holds none of the digests the manifest lists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LlamaAlias {
    pub epoch: CacheEpoch,
    pub manifest: CacheDigest,
}

/// `value` read as a launch alias: exactly `oneiron-llama/`, 32 lowercase
/// hex digits, `/`, 64 lowercase hex digits. No trailing slash, suffix,
/// revision, whitespace, decoding or extra segment. `None` for anything
/// else, which is some other model's name, never an error.
#[must_use]
pub fn parse_llama_alias(value: &str) -> Option<LlamaAlias> {
    let (epoch, manifest) = value.strip_prefix(LLAMA_ALIAS_PREFIX)?.split_once('/')?;
    Some(LlamaAlias {
        epoch: CacheEpoch::new(epoch).ok()?,
        manifest: CacheDigest::new(manifest).ok()?,
    })
}

/// The wire id a reply's `returned` model stands for on a route whose
/// independently configured target is `configured_target`: that target
/// when `returned` is a launch alias, else `returned` as it came.
#[must_use]
pub fn returned_model_wire_id<'a>(returned: &'a str, configured_target: &'a str) -> &'a str {
    if parse_llama_alias(returned).is_some() {
        configured_target
    } else {
        returned
    }
}
