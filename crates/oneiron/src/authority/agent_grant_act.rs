//! The signed half of the owner's agent Grant doors (FIX 5628, Engine 10-20
//! 00:5x): the owner's mint or revoke of a Grant that names an agent's
//! explicit verb list lands as one owner act this install carries.
//!
//! The door (`vault.agents.grants.mint` / `.revoke`, L13) authenticates the
//! owner, and in its own write transaction, before it puts or deletes the
//! FEDERATION_GRANT row, calls [`Vault::append_agent_grant_act_in_txn`]. That
//! revalidates the live owner, signs the act with this install's machine key
//! under the one carrier rule ([`super::owner_act_signer_admits`]), appends
//! it and folds it, so one commit lands both the Grant and the signed record
//! of the owner's will, or neither.
//!
//! The fold keeps no register for these acts and no state moves with one:
//! the Grant row is the state. A mint's `seen` names a fresh Grant and a
//! revoke's always lands, so both are zero
//! ([`AGENT_GRANT_ACT_SEEN`], CALLS "FIX 5628 grant act revision").

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{FederationGrantKind, GitPushBounds, RepoAccessBounds, Scope};
use crate::{TimeRange, Vault};

use super::machine_standing::{InstallCounted, Standing};
use super::*;

/// This install cannot carry the owner's act: it has no machine identity or
/// install key, or no live profile of it stands under that key. No roster
/// key, the host root included, carries an owner act (FIX 2222).
const NO_CARRIER: &str = "this install has no live machine profile in the vault's roster to carry \
                          the owner's agent Grant act";
/// The act would name more rows than one authority entry may: the log's
/// encoding bound, never a possession test.
const TOO_MANY_HEADS: &str = "the authority log has more concurrent heads than one agent Grant act \
                              may name; nothing was written";
/// The fold did not count the signed act, so the caller's transaction must
/// not commit the Grant change it records.
const NOT_COUNTED: &str = "the authority fold did not count the owner's agent Grant act; nothing \
                           was written";

/// The owner's act on an agent's Grant, as the mint and revoke doors pass it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentGrantAct {
    /// The owner grants `member`, a live agent principal, the explicit
    /// `scope` he gave, until `expires_at`, or until revoked when `None`.
    /// `grant` is the new FEDERATION_GRANT row's id; `repo_bounds` the repo
    /// bounds he gave besides, signed with the rest (FIX 6867). A `GitPush`
    /// `grant_kind` grants raw git push to the `git_push_bounds` repos alone
    /// (G1-PUSH); the same act, signer and fold carry it.
    Mint {
        grant: EntityId,
        member: EntityId,
        scope: Scope,
        expires_at: Option<u64>,
        repo_bounds: Option<RepoAccessBounds>,
        grant_kind: FederationGrantKind,
        git_push_bounds: Option<GitPushBounds>,
    },
    /// The owner revokes the Grant `grant`.
    Revoke { grant: EntityId },
}

impl AgentGrantAct {
    /// The Grant the act names, and the change its record carries.
    fn into_change(self) -> (EntityId, AgentGrantChange) {
        match self {
            Self::Mint {
                grant,
                member,
                scope,
                expires_at,
                repo_bounds,
                grant_kind,
                git_push_bounds,
            } => (
                grant,
                AgentGrantChange::Mint {
                    member,
                    scope,
                    expires_at,
                    repo_bounds,
                    grant_kind,
                    git_push_bounds,
                },
            ),
            Self::Revoke { grant } => (grant, AgentGrantChange::Revoke),
        }
    }
}

/// The signed authority entry that records one agent Grant act: the BLAKE3
/// hash of its canonical signed body, never an entity id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AgentGrantActRef(AuthorityEntryHash);

impl AgentGrantActRef {
    /// The entry hash.
    pub(crate) const fn as_bytes(&self) -> &AuthorityEntryHash {
        &self.0
    }

    /// The entry hash in lowercase hex, as a mint or revoke answer shows it.
    pub(crate) fn to_hex(&self) -> String {
        crate::entity_id::bytes_to_hex_lower(&self.0)
    }
}

/// The `AgentGrantAct` transition, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check: its signer is a machine's install key, never a roster key (FIX
/// 2222), and some chain of the machine must name the key. The shape check
/// already refused an agent's act, an answered ask and a nonzero `seen`.
/// It moves no fold state. Whether the one carrier rule admits the machine
/// and whether its owner is live are the writer's to refuse; a record either
/// misses on a replica is valid and without effect, as every owner act is,
/// so it never stalls what descends from it, and with no state it has
/// nothing to withhold.
pub(super) fn apply_agent_grant_act(
    state: &FoldState,
    entry: &AuthorityLogEntry,
    record: &AgentGrantActRecord,
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
    let named = Standing::new(state, pin, counted).names_key(record.machine, key);
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
    Ok(())
}

impl Vault {
    /// Signs, appends and folds the owner's `act` on an agent's Grant in the
    /// caller's write transaction `txn`, before the caller puts or deletes
    /// the FEDERATION_GRANT row it names (FIX 5628). `owner` is revalidated
    /// as the vault's live owner in `txn`; `surface` is where he said so, for
    /// audit only. The act's `seen` is zero ([`AGENT_GRANT_ACT_SEEN`]): a
    /// mint names a fresh Grant, and his revoke always lands, never refused
    /// as stale.
    ///
    /// The act names the main-log heads alone, as every owner act does, and
    /// returns only once the fold in `txn` counted it. Nothing commits here:
    /// the caller's commit lands the act and the Grant change together.
    ///
    /// # Errors
    /// An owner refusal when the proof is no longer the vault's live owner;
    /// [`crate::error::RecordError::AuthorityRefused`] for an install that
    /// cannot carry the act, more heads than one entry may name, or an act
    /// the fold did not count.
    pub(crate) fn append_agent_grant_act_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        act: AgentGrantAct,
    ) -> Result<AgentGrantActRef> {
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let machine = crate::identity::read_machine_id_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let key = crate::identity::read_machine_signing_key_in_txn(self, txn)?
            .ok_or_else(|| authority_refused(NO_CARRIER))?;
        let public_key = key.verifying_key().to_bytes();
        if !super::owner_act_signer_admits(fold.machine(machine), &fold.roster, &public_key) {
            return Err(authority_refused(NO_CARRIER));
        }
        // FIX 7908: join a frontier wider than one entry names, else today's path.
        let fold = self
            .prepare_authority_frontier_in_txn(
                txn,
                &fold,
                FrontierSigner::Install(machine, &key),
                MAX_PARENTS,
            )?
            .unwrap_or(fold);
        let signer = AuthorityKey::Ed25519(public_key);
        let seq = next_sequence(&fold, &signer)?;
        let parents = fold.append_heads.clone();
        if parents.len() > MAX_PARENTS {
            return Err(authority_refused(TOO_MANY_HEADS));
        }
        let (grant, change) = act.into_change();
        let record = AgentGrantActRecord {
            act: OwnerAct::by_owner(
                actor,
                change.act_kind(),
                grant,
                surface,
                AGENT_GRANT_ACT_SEEN,
            ),
            machine,
            grant,
            change,
        };
        let now = self.instant_in_txn(txn)?.secs();
        let entry = sign_side_entry(
            &fold,
            &key,
            seq,
            parents,
            AuthorityOp::AgentGrantAct(record),
            now,
        )?;
        let entry_hash = authority_entry_hash(&entry)?;
        let at = TimeRange {
            start: now,
            end: now,
        };
        self.put_authority_log_entries_in_txn(txn, &[(entry, at, now)])?;
        let after = self.authority_view_readonly_in_txn(txn)?;
        if !after.valid_entries.contains(&entry_hash)
            || after.install.held_back.contains(&entry_hash)
        {
            return Err(authority_refused(NOT_COUNTED));
        }
        Ok(AgentGrantActRef(entry_hash))
    }
}
