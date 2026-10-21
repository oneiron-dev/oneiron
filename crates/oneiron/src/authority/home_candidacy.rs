//! Folds each machine's signed MACRO home candidacy (FIX 4898; Engine 10-19
//! rulings on ARCH-0026: "Election order is cloud node when attached, then
//! an always-on local node, then the primary device"), judges it for an
//! election, and keeps the door this install declares its own through.
//!
//! Each install declares its own machine: its sync node id and the facts
//! the default order ranks ([`HomeCandidacy`]), signed by its live install
//! key under the carrier rule every owner act shares
//! ([`super::owner_act_signer_admits`]). The fold keeps each machine's
//! newest declaration: one replaces every declaration of its machine its
//! parents carry, and of concurrent ones the highest sequence, then hash,
//! reads as newest. A declaration lands whatever its machine's standing; an
//! election judges it again on the fold it reads, under this install's pin,
//! so a removed, held or key-conflicted machine drops out by itself, and one
//! the owner restores comes back with its declaration.
//!
//! The owner's machines are those he answered as his own, work/school or
//! rented, and a hosted node; an execution node and an install whose owner
//! has not answered never stand as candidates through a declaration
//! (Engine 10-19, ruling 2).

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, HostingPrivacyPosture, TimeRange, Vault};

use super::machine_standing::{InstallCounted, Standing};
use super::*;

/// This install cannot sign its own candidacy: it has no machine identity
/// or install key, or no live profile of it stands under that key.
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to sign \
                          its home candidacy";
/// The declaration would name more rows than one authority entry may: the
/// log's encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one home candidacy \
                              may name; nothing was written";

/// One machine's declaration as the fold keeps it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DeclaredHomeCandidacy {
    /// The declaration's authority entry hash.
    pub(crate) act: AuthorityEntryHash,
    /// The install key that signed it.
    pub(crate) key: [u8; 32],
    /// Its signer's sequence: of one key's declarations, the newest is the
    /// highest.
    pub(crate) seq: u64,
    pub(crate) node_id: u64,
    pub(crate) always_on: bool,
    pub(crate) primary: bool,
    pub(crate) macro_ready: bool,
    pub(crate) cloud: bool,
}

impl DeclaredHomeCandidacy {
    /// Whether it states `declaration`'s facts under `key`.
    fn says(&self, declaration: &HomeCandidacy, key: &[u8; 32]) -> bool {
        self.key == *key
            && self.node_id == declaration.node_id
            && self.always_on == declaration.always_on
            && self.primary == declaration.primary
            && self.macro_ready == declaration.macro_ready
            && self.cloud == declaration.cloud
    }
}

/// The vault's declarations in one fold state: each machine's that no later
/// declaration of it replaced, and every one a later one replaced.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct HomeCandidacyState {
    live: BTreeMap<EntityId, BTreeMap<AuthorityEntryHash, DeclaredHomeCandidacy>>,
    replaced: BTreeSet<AuthorityEntryHash>,
}

/// The `HomeCandidacy` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check: its signer is the declaring machine's install key, never a roster
/// key (FIX 2222: the host root acts as nobody), and some chain of the
/// machine must name it. It replaces every declaration of its machine its
/// parents carry.
pub(super) fn apply_home_candidacy(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    declaration: &HomeCandidacy,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    if !entry.cosigns.is_empty() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    let named = Standing::new(state, pin, counted).names_key(declaration.machine, key);
    if !named || state.roster.contains_key(signer) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(signer)
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    let landed = DeclaredHomeCandidacy {
        act: hash,
        key: *key,
        seq: entry.seq,
        node_id: declaration.node_id,
        always_on: declaration.always_on,
        primary: declaration.primary,
        macro_ready: declaration.macro_ready,
        cloud: declaration.cloud,
    };
    let register = &mut state.home_candidacy;
    let live = register.live.entry(declaration.machine).or_default();
    register.replaced.extend(live.keys().copied());
    live.clear();
    live.insert(hash, landed);
    Ok(())
}

/// Joins two states' declarations: one a later declaration replaced on
/// either side is replaced.
pub(super) fn merge_home_candidacies(merged: &mut HomeCandidacyState, right: &HomeCandidacyState) {
    merged.replaced.extend(right.replaced.iter().copied());
    for (machine, declarations) in &right.live {
        let live = merged.live.entry(*machine).or_default();
        for (hash, declaration) in declarations {
            live.entry(*hash).or_insert_with(|| declaration.clone());
        }
    }
    let HomeCandidacyState { live, replaced } = merged;
    live.retain(|_, declarations| {
        declarations.retain(|hash, _| !replaced.contains(hash));
        !declarations.is_empty()
    });
}

/// Each machine's newest declaration: the one no later declaration of it
/// replaced; of concurrent ones, the highest sequence, then hash.
pub(super) fn folded_home_candidacies(
    state: &FoldState,
) -> BTreeMap<EntityId, DeclaredHomeCandidacy> {
    state
        .home_candidacy
        .live
        .iter()
        .filter_map(|(machine, declarations)| {
            declarations
                .values()
                .max_by_key(|declared| (declared.seq, declared.act))
                .map(|declared| (*machine, declared.clone()))
        })
        .collect()
}

/// One machine's newest declaration as an election on one fold reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JudgedHomeCandidacy {
    pub(crate) node_id: u64,
    pub(crate) always_on: bool,
    pub(crate) primary: bool,
    pub(crate) macro_ready: bool,
    pub(crate) cloud: bool,
    /// Its machine still stands under the key that signed it: no chain
    /// removed it, and a live one names the key (the carrier rule).
    pub(crate) stands: bool,
    /// It stands as one of the owner's machines under this install's pin,
    /// under that same key: what makes it a candidate.
    pub(crate) owner_machine: bool,
}

impl AuthorityFold {
    /// Every machine's newest home candidacy, judged on this fold under
    /// this install's pin (FIX 4898).
    pub(crate) fn home_candidacies(&self) -> Vec<JudgedHomeCandidacy> {
        let pin = self.pinned_root.as_ref();
        self.home_candidacy
            .iter()
            .map(|(machine, declared)| {
                let folded = self.machines.get(machine);
                let stands = super::owner_act_signer_admits(folded, &self.roster, &declared.key);
                let owner_machine = stands
                    && folded.and_then(|folded| owner_machine_key(folded, pin))
                        == Some(declared.key);
                JudgedHomeCandidacy {
                    node_id: declared.node_id,
                    always_on: declared.always_on,
                    primary: declared.primary,
                    macro_ready: declared.macro_ready,
                    cloud: declared.cloud,
                    stands,
                    owner_machine,
                }
            })
            .collect()
    }
}

/// The install key `folded` stands under here as one of the owner's
/// machines (Engine 10-19, FIX 4898 ruling 2): `Yours` through its trusted
/// identity under this install's pin, and work/school, rented or a hosted
/// node through its live roster revision, the key a connection proves it by
/// ([`AuthorityFold::machine_proof_key`]). None for an execution node, an
/// unanswered install, or a machine removed, conflicted, held or stale here,
/// whose trusted keys are unsettled, or whose key another machine claims.
fn owner_machine_key(folded: &FoldedMachine, pin: Option<&PinnedRoot>) -> Option<[u8; 32]> {
    if let Some(trusted) = folded.trusted(pin) {
        return Some(trusted.profile.machine_key);
    }
    let admitter = pin.map_or(MachineAdmitter::Roster, |pin| {
        MachineAdmitter::Anchor(pin.anchor_key)
    });
    if folded.keys_unsettled(&admitter, &folded.trust_chains(&admitter)) {
        return None;
    }
    folded
        .roster
        .as_ref()
        .filter(|chain| {
            chain.is_live()
                && matches!(
                    chain.profile.role,
                    MachineRole::Owned(_) | MachineRole::HostedNode
                )
                && !folded.shared.contains_key(&chain.profile.machine_key)
        })
        .map(|chain| chain.profile.machine_key)
}

/// The vault's home candidacies as an election in `txn` reads them; `None`
/// when this snapshot cannot read them (history the vault lacks, or
/// conflicting vault roots), as the election reads the owner's pick.
pub(crate) fn election_home_candidacies_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<Vec<JudgedHomeCandidacy>>> {
    match authority_view_readonly_for_store_in_txn(store, posture, txn) {
        Ok(fold) if fold.vault_root_is_conflicted() => Ok(None),
        Ok(fold) => Ok(Some(fold.home_candidacies())),
        Err(error) if super::readonly_fold::is_history_incomplete(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The vault's home candidacies in `txn`'s snapshot, as the owner reads
/// them. History the vault lacks refuses as the fold does, and conflicting
/// vault roots refuse: neither reads as no candidacy.
pub(crate) fn home_candidacies_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<JudgedHomeCandidacy>> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    if fold.vault_root_is_conflicted() {
        return Err(invalid_authority());
    }
    Ok(fold.home_candidacies())
}

impl Vault {
    /// Declares this install's own machine as a MACRO home candidate (FIX
    /// 4898): its sync node id, and whether it stays on (`always_on`), is
    /// the owner's primary device (`primary`) and can take MACRO work now
    /// (`macro_ready`). It declares itself a cloud node when its own live
    /// profile is a hosted node's. Its install key signs the declaration,
    /// a main-log entry naming the log's heads, which lands atomically or
    /// not at all, re-electing this install's home in the same transaction;
    /// the commit then wakes the watchers.
    ///
    /// Nothing is written when the fold's newest declaration of this machine
    /// already says the same under this key: `Ok(None)`. Otherwise
    /// `Ok(Some(hash))`, the declaration's authority entry hash.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] for an install with
    /// no live machine profile under its install key; storage errors.
    pub fn declare_home_candidacy(
        &self,
        always_on: bool,
        primary: bool,
        macro_ready: bool,
    ) -> Result<Option<AuthorityEntryHash>> {
        self.load_install_signing_if_minted()?;
        let mut txn = self.store.env.write_txn()?;
        let node_id = crate::identity::load_or_mint_client_id_in_txn(self, &mut txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let machine = crate::identity::read_machine_id_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, &txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        let folded = fold.machine(machine);
        if !super::owner_act_signer_admits(folded, &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        let cloud = folded
            .and_then(|folded| folded.roster.as_ref())
            .is_some_and(|chain| {
                chain.is_live()
                    && chain.profile.machine_key == public_key
                    && chain.profile.role == MachineRole::HostedNode
            });
        let declaration = HomeCandidacy {
            machine,
            node_id,
            always_on,
            primary,
            macro_ready,
            cloud,
        };
        if fold
            .home_candidacy
            .get(&machine)
            .is_some_and(|newest| newest.says(&declaration, &public_key))
        {
            return Ok(None);
        }
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let fold = self
            .prepare_authority_frontier_in_txn(
                &mut txn,
                &fold,
                FrontierSigner::Install(machine, &key),
                MAX_PARENTS,
            )?
            .unwrap_or(fold);
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(Error::InvalidConfig(TOO_MANY_HEADS.to_owned()));
        }
        let now = self.instant_in_txn(&txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::HomeCandidacy(declaration),
            now,
        )?;
        let act = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(&mut txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        if after
            .home_candidacy
            .get(&machine)
            .is_none_or(|newest| newest.act != act)
        {
            return Err(invalid_authority());
        }
        txn.commit()?;
        // The landing re-elected this install's home in its transaction;
        // the topology route and the deadline lane re-read it now.
        self.store.notify_proactivity_changes();
        Ok(Some(act))
    }
}
