//! Generation membership policy named by a pad-object install.

/// What an install does with the generations a store and a capture do not
/// both keep (CALLS: PAD-1 generation membership).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PadObjectMembership {
    /// A source's capture over a restored copy or an activated archive: each
    /// generation only the source keeps is adopted when the capture carries
    /// its bundle and its pad object whole, else it stays not carried. Each
    /// generation only the copy keeps is retired, bundle, pad object and
    /// grants, only when the source's own keep and age rule, run over the
    /// generations its same read keeps with that one placed among them by
    /// commit order, retires it; else it keeps its bytes.
    SourceKeepRuleProvesRetired,
    /// A store's own objects put back over an install that did not read
    /// back: every generation they keep comes back as they held it, whole or
    /// not, its grants and the admission outbox too (FIX 12142), and each
    /// the install brought that they do not keep goes.
    StoreOwnPutBack,
}
