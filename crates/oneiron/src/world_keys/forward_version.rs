//! Version of the materialized content forward pass.

/// The forward pass's version, which a sealed window's landed mark names
/// beside the mirror's (FIX 6509): bump it whenever a change to the pass
/// changes which rows it lands or drops, so every window lands again once.
///
/// 2: the pass lands each row's carried source audience binding and policy
/// closure (Engine A, 6 Nov 03:46).
pub(crate) const FORWARD_PASS_VERSION: u64 = 2;
