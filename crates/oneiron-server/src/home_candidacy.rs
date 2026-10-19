//! This host's MACRO home candidacy (FIX 4898; ARCH-0026: "Election order
//! is cloud node when attached, then an always-on local node, then the
//! primary device"): the facts it declares of its own machine, signed into
//! the vault's authority log so every linked machine's election sees it.
//!
//! A served host declares itself always on, and able to run MACRO while its
//! Dreamer runs; on a managed host's hosted node the engine adds that it is
//! the cloud node. A device of another home declares what its
//! `[device_sync]` section says (`always_on`, `primary`), and whether its
//! Dreamer runs. A declaration is written only when it differs from the
//! newest one the vault holds for this machine, so a restart writes none.

/// Declares this install's own candidacy. Never fails its caller: an
/// install that cannot sign one (no live machine profile under its key) or
/// a write that fails is logged, and this host's own election still counts
/// the candidacy it keeps for itself.
pub(crate) fn declare(vault: &oneiron::Vault, always_on: bool, primary: bool, macro_ready: bool) {
    match vault.declare_home_candidacy(always_on, primary, macro_ready) {
        Ok(Some(_)) => tracing::info!(
            always_on,
            primary,
            macro_ready,
            "MACRO home candidacy declared"
        ),
        Ok(None) => {}
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            "MACRO home candidacy not declared; the vault's other machines do not count this one"
        ),
    }
}
