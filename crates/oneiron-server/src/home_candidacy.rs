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

/// Marks this served home's own copy as a full copy (L7-47;
/// HOME-ELECTION-NEEDS-FULL-COPY; CROSS-ARCH-0024 `#my-network` item 04:
/// "Only a full copy can become home"). A served host that is no device of
/// another home holds its vault, the copy its devices sync from, and runs no
/// home session that would mark it, while the election ranks a declaration
/// only while its machine holds a full copy, once one it ranks does. So the
/// home writes its mark beside its candidacy. Written only when it differs
/// from the newest one the vault holds, so a restart writes none. Never fails
/// its caller: an install that cannot sign one, or a write that fails, is
/// logged.
pub(crate) fn declare_home_full_copy(vault: &oneiron::Vault) {
    match vault.declare_full_copy(true) {
        Ok(Some(_)) => tracing::info!("this home's full-copy mark declared"),
        Ok(None) => {}
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            "this home's full-copy mark not declared; the vault's elections rank a marked \
             machine before this home"
        ),
    }
}
