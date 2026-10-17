//! The owner's residence directives to one of their machines (OF-534):
//! owner-vault acts that name a machine, which that machine's own-device sync
//! connection applies. A directive is a host-signed AUTHORITY_LOG entry, so it
//! reaches each of the owner's machines with the rest of the signed history
//! (window sync, or the home's authority tail on a machine that syncs what it
//! opened), however long the machine was offline, and only the machine it
//! names acts on it. That machine answers with a result signed by its own
//! install key, which names the directive's entry and travels back the same
//! way, so the owner reads it on any replica that holds both.
//!
//! The result is the directive's journal: a directive with no accepted result
//! from its machine is pending there. A local act (a prune, the mode choice)
//! commits in the same transaction as its result, so it lands once. An act
//! that asks the home (an open, the index, the grants a switch to opened
//! needs) commits its own rows first; each is safe to run again, so a crash
//! before the result only repeats it. Neither entry carries content.

use std::collections::BTreeMap;

use crate::authority::{
    AuthorityEntryHash, AuthorityKey, AuthorityOp, HostSlipIssuer, RESIDENCE_REASON_MAX,
    ResidenceAct, ResidenceDirective, ResidenceResult, ResidenceResultStatus, authority_entry_hash,
    decode_authority_log_entry_body, invalid_authority, next_sequence, sign_side_entry,
    standing_rows,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::sync::WindowKey;
use crate::{EntityId, TimeRange, Vault};

/// Both residence op kinds start so; only a row whose body holds it is
/// decoded when the log is read for directives.
const RESIDENCE_KIND_PREFIX: &[u8] = b"residence_";

/// One directive and, once its machine reported, the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidenceDirectiveState {
    pub directive: ResidenceDirective,
    /// The directive's signed entry.
    pub entry: AuthorityEntryHash,
    /// The named machine's result, once it reached this replica; `None` while
    /// the directive is pending.
    pub result: Option<ResidenceResult>,
}

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

impl Vault {
    /// Issues one residence directive to one of the owner's machines (FIX
    /// 531): the seam the owner-vault residence verbs call. The owner is
    /// revalidated in the writing transaction and the host signs the
    /// directive, as any owner act through it. The machine applies it on its
    /// next own-device sync and its result comes back the same way, so the
    /// answer here is pending. `id` names the directive: the same id with the
    /// same machine and act answers the directive already issued; with
    /// anything else it is refused.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] when `machine` is not one of the owner's
    /// machines here, when it is this install and this install is the elected
    /// home (which always syncs every window it may read), when an open names
    /// a window key that does not parse, or when `id` names another
    /// directive; an owner who no longer stands; an issuer that is not this
    /// vault's host.
    pub fn issue_residence_directive_as(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        id: EntityId,
        machine: EntityId,
        act: ResidenceAct,
    ) -> Result<ResidenceDirectiveState> {
        if let ResidenceAct::Open { window, .. } = &act
            && WindowKey::try_new(window.as_str()).is_none()
        {
            return Err(refused("a residence open names a window key that parses"));
        }
        // Read before the writer: the election check may mint this install's
        // sync id.
        let home_here = super::local_is_elected_home(self)?;
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        if self
            .authority_view_readonly_in_txn(&txn)?
            .trusted_machine(machine)
            .is_none()
        {
            return Err(refused(
                "a residence directive names one of the owner's machines",
            ));
        }
        if home_here && crate::identity::read_machine_id_in_txn(self, &txn)? == Some(machine) {
            return Err(refused(
                "the elected home always syncs every window it may read",
            ));
        }
        if let Some(state) = directive_states_in_txn(self, &txn)?
            .into_iter()
            .find(|state| state.directive.id == id)
        {
            return if state.directive.machine == machine && state.directive.act == act {
                Ok(state)
            } else {
                Err(refused("the directive id names another directive"))
            };
        }
        let directive = ResidenceDirective {
            id,
            machine,
            owner: actor,
            issued_at: self.instant_in_txn(&txn)?.secs(),
            act,
        };
        let entry = self.append_residence_directive_in_txn(&mut txn, issuer, directive.clone())?;
        txn.commit()?;
        Ok(ResidenceDirectiveState {
            directive,
            entry,
            result: None,
        })
    }

    /// One residence directive and its machine's result, for the owner.
    ///
    /// # Errors
    /// An owner who no longer stands; storage errors.
    pub fn residence_directive_as(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
    ) -> Result<Option<ResidenceDirectiveState>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        Ok(directive_states_in_txn(self, &txn)?
            .into_iter()
            .find(|state| state.directive.id == id))
    }

    /// The residence directives this replica holds and their machines'
    /// results, for the owner, oldest first: those naming `machine`, or every
    /// machine's.
    ///
    /// # Errors
    /// An owner who no longer stands; storage errors.
    pub fn residence_directives_as(
        &self,
        owner: &AuthenticatedOwner,
        machine: Option<EntityId>,
    ) -> Result<Vec<ResidenceDirectiveState>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let mut states = directive_states_in_txn(self, &txn)?;
        states.retain(|state| machine.is_none_or(|machine| state.directive.machine == machine));
        Ok(states)
    }
}

/// Every directive this replica's fold accepts, oldest first, each with the
/// earliest accepted result its machine signed for it. The fold accepts a
/// result only under the install key of the machine it names.
fn directive_states_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<ResidenceDirectiveState>> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let mut directives = Vec::new();
    let mut results: BTreeMap<AuthorityEntryHash, ResidenceResult> = BTreeMap::new();
    for id in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)?
    {
        let Some(raw) = vault.store.port_entity_raw(txn, &id?)? else {
            continue;
        };
        let body = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("authority row header"))?;
        if !body
            .windows(RESIDENCE_KIND_PREFIX.len())
            .any(|bytes| bytes == RESIDENCE_KIND_PREFIX)
        {
            continue;
        }
        let entry = decode_authority_log_entry_body(body)?;
        let hash = authority_entry_hash(&entry)?;
        if !fold.valid_entries.contains(&hash) {
            continue;
        }
        match entry.op {
            AuthorityOp::ResidenceDirective(directive) => directives.push((hash, directive)),
            AuthorityOp::ResidenceResult(result) => {
                if results
                    .get(&result.directive_entry)
                    .is_none_or(|kept| result.finished_at < kept.finished_at)
                {
                    results.insert(result.directive_entry, result);
                }
            }
            _ => {}
        }
    }
    directives.sort_by_key(|(_, directive)| (directive.issued_at, directive.id));
    Ok(directives
        .into_iter()
        .map(|(entry, directive)| {
            let result = results.remove(&entry).filter(|result| {
                result.directive == directive.id && result.machine == directive.machine
            });
            ResidenceDirectiveState {
                directive,
                entry,
                result,
            }
        })
        .collect())
}

/// The accepted directives naming this install's machine that it has no
/// result for yet, oldest first. None on a machine the owner has not marked
/// "yours" under this install's key: its results would not stand.
pub(crate) fn pending_residence_directives(vault: &Vault) -> Result<Vec<ResidenceDirectiveState>> {
    let Some(local) = vault.local_machine()? else {
        return Ok(Vec::new());
    };
    if !local.mine {
        return Ok(Vec::new());
    }
    let txn = vault.store.env.read_txn()?;
    let mut states = directive_states_in_txn(vault, &txn)?;
    states.retain(|state| state.directive.machine == local.id && state.result.is_none());
    Ok(states)
}

/// A refusal's reason as a result carries it: one line, at most
/// [`RESIDENCE_REASON_MAX`] bytes.
pub(crate) fn residence_refusal_reason(text: &str) -> String {
    let mut reason = String::new();
    for character in text.chars().map(|c| if c.is_control() { ' ' } else { c }) {
        if reason.len() + character.len_utf8() > RESIDENCE_REASON_MAX {
            break;
        }
        reason.push(character);
    }
    if reason.trim().is_empty() {
        return "refused".to_owned();
    }
    reason
}

/// Records this machine's result for `pending` in the caller's transaction,
/// beside whatever the act committed there, signed by this install's machine
/// key. Refused unless the fold accepts it.
pub(crate) fn finish_residence_directive_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    pending: &ResidenceDirectiveState,
    status: ResidenceResultStatus,
    count: u64,
    reason: Option<String>,
) -> Result<AuthorityEntryHash> {
    let machine = pending.directive.machine;
    if crate::identity::read_machine_id_in_txn(vault, txn)? != Some(machine) {
        return Err(refused(
            "a residence result comes from the machine its directive names",
        ));
    }
    let key = crate::identity::read_machine_signing_key_in_txn(vault, txn)?
        .ok_or_else(|| refused("this install has no machine key"))?;
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let now = vault.instant_in_txn(txn)?.secs();
    let result = ResidenceResult {
        directive: pending.directive.id,
        machine,
        directive_entry: pending.entry,
        finished_at: now,
        status,
        count,
        reason,
    };
    result.validate()?;
    // The result names the directive and the rows its signer's standing
    // rests on, never an unrelated main-log head.
    let mut parents = standing_rows(&fold, machine);
    parents.insert(pending.entry);
    let signer = AuthorityKey::Ed25519(key.verifying_key().to_bytes());
    let entry = sign_side_entry(
        &fold,
        &key,
        next_sequence(&fold, &signer)?,
        parents,
        AuthorityOp::ResidenceResult(result),
        now,
    )?;
    let hash = authority_entry_hash(&entry)?;
    vault.put_authority_log_entries_in_txn(
        txn,
        &[(
            entry,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )],
    )?;
    if !vault
        .authority_view_readonly_in_txn(txn)?
        .valid_entries
        .contains(&hash)
    {
        return Err(invalid_authority());
    }
    Ok(hash)
}
