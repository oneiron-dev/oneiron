//! The served host of code consent waits (DOOR-079 1a): it drives an
//! answered wait's held `connector.call` on this server's connector
//! transport.
//!
//! It is no second authoriser. The owner's answer is the engine's, made and
//! checked there; this host cannot make, change or replace it. Before it
//! drives, it checks the original caller's kept instrument the way only a
//! served host can: the same slip, live now, whose current scope meets the
//! scope its request was admitted under. A caller that kept no instrument
//! (an embedded or host surface) has only its grant to limit it, and the
//! effect's own gate reads that grant. Where the caller sits never decides
//! it, and the caller need not be online: the server drives the settle.
//! The engine then runs the effect once, under its own current gate.
//!
//! Serve installs it whatever hooks or models it serves, before the
//! connector settler starts; the settler drives an answered wait the
//! answer's own pass left settling.
//!
//! A held browser act (FIX 10423) is driven on the run's own live browser
//! instead, once (`browser`): the same original caller check first, then
//! the exact act its press held, under one press armed for it alone. A
//! held desktop act (FIX 11499) is driven the same way on the run's own
//! live desktop (`desktop`).

mod browser;
mod desktop;

use std::sync::{Arc, Weak};

use oneiron::authority::{InvocationSlipBinding, VerifiedSlip};
use oneiron::code_run::CodeConsentEffectHost;
use oneiron::outbound_intent_ledger::IntentLedgerError;
use oneiron::runtime_hooks::verb::{VerbAskCredentialSource, VerbAskInstrument, VerbAskRefusal};
use oneiron::{EntityId, Vault};

use crate::auth::CoreAuth;
use crate::connector_call_host::ServedConnectorCallHost;
use crate::error::ApiError;
use crate::server::SyncServer;

/// This server's code consent host. It holds the server weakly, as the
/// verb-ask credential check does.
pub(crate) struct ServerCodeConsentHost {
    server: Weak<SyncServer>,
}

impl ServerCodeConsentHost {
    /// Installs this server's host on its vault. A second install does
    /// nothing.
    pub(crate) fn install(server: &Arc<SyncServer>) {
        server
            .vault()
            .install_code_consent_effect_host(Arc::new(Self {
                server: Arc::downgrade(server),
            }));
    }
}

impl CodeConsentEffectHost for ServerCodeConsentHost {
    fn resume_answered(&self, vault: &Vault, wait_id: EntityId) -> oneiron::Result<()> {
        let server = self.server.upgrade().ok_or_else(|| {
            oneiron::Error::InvalidConfig(
                "the server is stopping; the code consent wait stays settling".to_owned(),
            )
        })?;
        resume_answered(&server, vault, wait_id)
    }
}

/// Drives one answered code consent wait's effect on this server: the
/// original caller's kept instrument checked first, then the effect through
/// the engine's own gate on this server's connector transport, or, for a
/// held browser act, on the run's own browser (FIX 10423). An instrument
/// that no longer stands settles the wait refused; one this host could not
/// check leaves it settling. Blocking: it sends, so call it on a blocking
/// worker, never under a writer.
pub(crate) fn resume_answered(
    server: &SyncServer,
    vault: &Vault,
    wait_id: EntityId,
) -> oneiron::Result<()> {
    if let Some(saved) = vault.code_consent_wait_credential(wait_id)?
        && let Some(instrument) = saved.instrument.as_ref()
        && let Err(refusal) = kept_instrument_auth(server, instrument, Some(&saved.witness), None)
    {
        vault
            .refuse_answered_code_consent_wait(wait_id, refusal)
            .map_err(ledger_error)?;
        return Ok(());
    }
    if let Some(action) = vault.code_consent_held_browser_action(wait_id)? {
        if action.act.starts_with("self.desktop.") {
            return desktop::resume_answered_desktop(server, vault, wait_id);
        }
        return browser::resume_answered_browser(server, vault, wait_id);
    }
    let mut host = ServedConnectorCallHost::new(server)?;
    vault
        .resume_answered_code_consent_wait(wait_id, &mut host)
        .map_err(ledger_error)?;
    Ok(())
}

/// A connector ledger error as the engine's own error.
fn ledger_error(error: IntentLedgerError) -> oneiron::Error {
    match error {
        IntentLedgerError::Engine(error) => error,
        other => oneiron::Error::InvalidConfig(other.to_string()),
    }
}

/// The authority a kept instrument establishes now, from it and its witness
/// alone: the witness verified again in a current snapshot, the same slip in
/// the same vault, and the same authority projected from it as the ceiling
/// it was admitted under. It reads nothing of where the caller sat: that
/// places a caller's reads, never its authority. A code consent wait's host
/// checks its original caller with it (DOOR-079 1a), for every caller shape
/// that kept an instrument. A managed vault's attested owner kept no slip
/// witness: he stands as [`attested_owner_auth`] finds him.
pub(crate) fn kept_instrument_auth(
    server: &SyncServer,
    instrument: &VerbAskInstrument,
    witness: Option<&InvocationSlipBinding>,
    door: Option<&str>,
) -> Result<CoreAuth, VerbAskRefusal> {
    let (slip, fingerprint) = match instrument.source {
        VerbAskCredentialSource::Slip { slip, fingerprint } => (slip, fingerprint),
        // A slip's witness beside the owner's instrument is no witness of his.
        VerbAskCredentialSource::AttestedOwner { .. } if witness.is_some() => {
            return Err(VerbAskRefusal::CredentialChanged);
        }
        VerbAskCredentialSource::AttestedOwner { holder } => {
            return attested_owner_auth(server, instrument, holder);
        }
    };
    let witness = witness.ok_or(VerbAskRefusal::CredentialMissing)?;
    let verified = server
        .vault
        .verify_invocation_slip(witness)
        .map_err(|_| standing(&server.vault, &slip))?;
    if !same_instrument(instrument, &verified) {
        return Err(VerbAskRefusal::CredentialChanged);
    }
    let auth = CoreAuth::from_kept_slip(
        verified,
        witness.clone(),
        fingerprint,
        door,
        server.vault.as_ref(),
    )
    .map_err(|_| VerbAskRefusal::CredentialChanged)?;
    if !ceiling_holds(&instrument.ceiling, &auth.authority_ceiling()) {
        return Err(VerbAskRefusal::ScopeRefused);
    }
    Ok(auth)
}

/// No substitution (OF-580 defaults): only the saved instrument resumes its
/// call. The witness must verify as the very slip the reference names, in the
/// vault it was minted for; a renewed or re-minted credential of the same
/// actor never stands in.
fn same_instrument(saved: &VerbAskInstrument, verified: &VerifiedSlip) -> bool {
    saved.slip() == Some(verified.claims().slip_id) && verified.claims().vault_id == saved.vault
}

/// The attested owner `holder` a kept instrument names, as he stands now
/// (FIX 11063): in the vault whose authority he was admitted in, while it
/// records him as its live owner ([`attested_owner_standing`]). No slip,
/// ceiling or lifetime is his, so nothing of his is compared, expired or
/// revoked: the vault's live owner record alone decides.
fn attested_owner_auth(
    server: &SyncServer,
    instrument: &VerbAskInstrument,
    holder: EntityId,
) -> Result<CoreAuth, VerbAskRefusal> {
    match server.vault.authority_vault_id() {
        Ok(Some(vault)) if vault == instrument.vault => attested_owner_standing(server, holder),
        Ok(_) => Err(VerbAskRefusal::CredentialChanged),
        Err(_) => Err(VerbAskRefusal::CredentialUnavailable),
    }
}

/// `holder` as a managed vault's attested owner now
/// ([`CoreAuth::for_attested_owner`]): refused as no longer its live owner
/// only when the vault reads and records someone else, or no one, as its
/// live owner. Standing this host could not read, or a vault no supervisor
/// manages now, is unavailable.
pub(crate) fn attested_owner_standing(
    server: &SyncServer,
    holder: EntityId,
) -> Result<CoreAuth, VerbAskRefusal> {
    CoreAuth::for_attested_owner(holder, server).map_err(|refused| {
        if refused == ApiError::managed_owner_not_live() {
            VerbAskRefusal::OwnerNotLive
        } else {
            VerbAskRefusal::CredentialUnavailable
        }
    })
}

/// The current scopes meet the original ceiling (OF-580 defaults): what a
/// credential, or its connector's registration, projects now must be what
/// the call was admitted under. A wider one never widens the saved call; a
/// narrower one refuses it rather than shrink it unseen.
pub(crate) fn ceiling_holds(saved: &[u8; 32], now: &[u8; 32]) -> bool {
    saved == now
}

/// Why a kept slip no longer verifies, as far as the current fold proves it
/// (OF-580 defaults, each terminal): its mint gone, it or an ancestor
/// revoked, its lifetime past. Anything else is a changed credential, never
/// called revoked; a fold that does not read is unavailable (fail closed).
fn standing(vault: &oneiron::Vault, slip: &[u8; 32]) -> VerbAskRefusal {
    let (Ok(fold), Ok(now)) = (vault.authority_fold(), vault.capability_slip_now()) else {
        return VerbAskRefusal::CredentialUnavailable;
    };
    let Some(mint) = fold.slips.mints.get(slip) else {
        return VerbAskRefusal::CredentialMissing;
    };
    if fold.slips.is_revoked(slip) {
        VerbAskRefusal::CredentialRevoked
    } else if now >= mint.action.claims.expires_at {
        VerbAskRefusal::CredentialExpired
    } else {
        VerbAskRefusal::CredentialChanged
    }
}
