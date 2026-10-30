//! An agent's sight of a file stored with keys in it (OF-560; owner ruling
//! G04 binary = C2): "Agent with a grant: the real bytes."
//!
//! An agent that reads a marked file and says why is asking for every key in
//! it at once, so the read runs the one reveal check over the file's keys:
//! this connection × their class × this project. Inside a standing grant the
//! read gets the stored bytes, and each read leaves its own reveal row with
//! its why, a quiet use receipt and a T1 lease per key, as a delivered reveal
//! does. Outside one, the read gets the masked copy and files one ask for
//! this agent, this file, this project and this run; the owner answers it
//! as any reveal ask, and an approval once opens the next such read.
//!
//! A file whose keys are of more than one custody class (FIX 6624) is read
//! as a typed body's read is: in one group per class, each judged by the
//! same check and asking under its own class, and the read opens only when
//! every group does; each group's ask card names the others (FIX 6738). A
//! file whose keys are not all active and admitted to a model (T1) reads
//! masked, with no ask.
//!
//! A delivered read, and the owner's answer to an ask, keep their reveal row
//! under the id it was asked under (FIX 6623, 6737): the next ask of the
//! same read is filed under the next id in that ask's sequence, never over a
//! delivered or answered row.
//!
//! A sealed file (a container the write door could not read whole, stored
//! as it is and unmarked) holds keys no mark names. Its read asks for the
//! file whole, as for one key of [`SEALED_FILE_CLASS`]: under a standing
//! grant, or once the owner approves the read, the agent gets the stored
//! bytes and the read leaves its reveal row. No lease is stamped, as no
//! custody record holds a key of it.
//!
//! A typed body's read (OF-067, FIX 2941) is one read of one projection of
//! the body, a deck's export or a body's view, whose lifted texts name keys
//! of any classes ([`Vault::typed_body_sight`]). Its keys are judged in one
//! group per custody class, each by the same check, and the read opens only
//! when every group does: no approval once is spent, and no group is
//! delivered, while another still waits on the owner.
//!
//! Every read runs through one core ([`Vault::read_sight_in_txn`]): each of
//! its groups judged before anything is written, then either every group
//! delivered with its own receipt, or an ask filed for each group with no
//! open one.

use super::agent::{file_ask_in_txn, standing};
use super::{
    FileSight, READER_AGENT, REVEAL_ASK_TTL_SECS, REVEAL_LEASE_TTL_SECS, REVEALS, RevealAsker,
    RevealAuthority, RevealGrantScope, RevealRow, SecretRevealState, checked_text, reveal_class,
};
use crate::consent::{
    ApproveOnceAuthorization, StandingConsentGrant, approve_once_authorization_in_txn,
    approve_once_decision_in_txn, load_active_standing_grants, spend_approve_once_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::secret_custody::{
    CustodyClass, SecretCustodyFloor, SecretCustodyStatus, SecretSight, masked_file_in_txn,
    read_secret_custody_admission_in_txn,
};
use crate::typed_body::LiftedSources;
use crate::vault::Vault;

/// Domain of the id of the one ask an agent's read of a file files.
const FILE_ASK_DOMAIN: &[u8] = b"oneiron.secret_reveal.file_ask.v1";

/// Domain of the next id in an ask's sequence, hashed from the one before:
/// where a read asks again once its ask was delivered or answered (FIX 6623,
/// 6737).
const FILE_REASK_DOMAIN: &[u8] = b"oneiron.secret_reveal.file_reask.v1";

/// Domain of a typed body read's fingerprint, the hash its reveal rows name
/// in place of a stored file's: never a hash of stored bytes.
const TYPED_BODY_READ_DOMAIN: &[u8] = b"oneiron.secret_reveal.typed_body_read.v1";

/// The class a sealed file's read is granted as: the class the write door
/// gives each key it lifts from a file (CALLS, open).
const SEALED_FILE_CLASS: CustodyClass = CustodyClass::CustodyPortable;

/// The handle a sealed file's read names in place of its keys'.
const SEALED_FILE_HANDLE: &str = "sealed file";

/// One read of keys an agent asks for: who asks and why, the artifact, the
/// hash of what it reads, and its keys in one group per custody class.
struct KeyRead<'a> {
    asker: &'a RevealAsker,
    artifact: &'a EntityId,
    /// The asker's why, checked.
    why: &'a str,
    /// The stored file's bytes' hash, or a typed body read's fingerprint.
    hash: [u8; 32],
    groups: Vec<ReadGroup>,
    /// Whether each group's ask names its class: a typed body's read, or a
    /// file whose keys span more than one class, one ask per class group. A
    /// file of one class, or a sealed one, asks once under an id naming none.
    per_class: bool,
    /// The ORIGINAL repo file and actual recipient a repo read names (FIX
    /// 7608 2b-ii, [`repo`]): its bound, rows and digest bind them.
    repo: Option<&'a RepoFileRevealTarget>,
}

/// The keys of one custody class a read opens: one reveal row, one grant
/// check and one ask.
struct ReadGroup {
    class: CustodyClass,
    /// The key the row names as its secret: the group's first, or the
    /// artifact for a sealed file.
    first: EntityId,
    /// Each key with its handle; none for a sealed file.
    keys: Vec<(EntityId, String)>,
    /// What the row and the ask card name: the keys' handles.
    handle: String,
}

/// Where one group of a read stands, judged with nothing written.
enum GroupPlan {
    /// Its read may go out now.
    Ready(Ready),
    /// Its ask waits on the owner, or was denied, in its window.
    Waiting,
    /// No ask of it is open: the read files one.
    Asks,
}

/// How a ready group's read goes out.
enum Ready {
    /// A standing grant covers it: the grant's reach (none for a repo file
    /// read's own scopes) and its registry ref.
    Covered(Option<RevealGrantScope>, String),
    /// The owner approved its ask once: the ask, and its marker, not spent.
    Once(Box<RevealRow>, ApproveOnceAuthorization),
}

/// One admitted key: its record, class and handle.
struct AdmittedKey {
    class: CustodyClass,
    secret: EntityId,
    handle: String,
}

impl Vault {
    /// How `asker` reads the stored `bytes` of `artifact` when it says `why`:
    /// [`SecretSight::Granted`] once a grant covers every key in them and
    /// this read's receipt is written, [`SecretSight::Masked`] otherwise. A
    /// file with no keys in it writes nothing, unless it is sealed: its read
    /// is asked for as one key of [`SEALED_FILE_CLASS`].
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`](crate::error::GateError::InvalidConsentBound)
    /// for a `why` that is empty, longer than 512 bytes or more than one
    /// line; the scan's refusal for one that holds a credential.
    pub(crate) fn file_sight(
        &self,
        asker: &RevealAsker,
        artifact: &EntityId,
        bytes: &[u8],
        why: &str,
    ) -> Result<SecretSight> {
        let hash = *blake3::hash(bytes).as_bytes();
        let sealed = {
            let txn = self.store.env.read_txn()?;
            masked_file_in_txn(&self.store, &txn, &hash)?.is_none()
        };
        if sealed && !crate::batch::secret_scan::is_sealed(bytes) {
            return Ok(SecretSight::Masked);
        }
        self.stored_file_sight(asker, artifact, (hash, sealed), why)
    }

    /// [`Self::file_sight`] for a file a mark covers, judged by its stored
    /// digest `hash` alone (FIX 6507): the stored bytes need not be held to
    /// decide. `None` when no mark covers the file, and the caller judges its
    /// stored bytes with [`Self::file_sight`].
    ///
    /// # Errors
    /// As [`Self::file_sight`].
    pub(crate) fn marked_file_sight(
        &self,
        asker: &RevealAsker,
        artifact: &EntityId,
        hash: &[u8; 32],
        why: &str,
    ) -> Result<Option<SecretSight>> {
        let marked = {
            let txn = self.store.env.read_txn()?;
            masked_file_in_txn(&self.store, &txn, hash)?.is_some()
        };
        if !marked {
            return Ok(None);
        }
        self.stored_file_sight(asker, artifact, (*hash, false), why)
            .map(Some)
    }

    /// How `asker` reads one projection of `artifact`'s typed body when it
    /// says `why` (OF-067, FIX 2941): `projection_fingerprint` names what the
    /// read shows (a deck's export key, a body's view), and `lifted_sources`
    /// the keys its lifted texts hold, read in the projection's own snapshot
    /// ([`Vault::typed_body_lifted_sources_in_txn`]).
    /// [`SecretSight::Granted`] once a grant covers every key and this read's
    /// receipts are written, [`SecretSight::Masked`] otherwise.
    ///
    /// The keys are judged in one group per custody class, each by the one
    /// reveal check: this connection × that class × this project. Every
    /// group is judged before anything is written. Only when each is covered
    /// by a standing grant or approved once by the owner is an approval
    /// spent, and each group then leaves its own reveal row, grant use or
    /// spent approval, and a T1 lease per key. While any group's ask is open
    /// or denied in its window, the read is masked, no approval is spent and
    /// no group is delivered; each group with no open ask files one (by this
    /// agent, this read, the group's class, this project and this run), and
    /// the asks stay, as a masked read is no error. A key that is not active
    /// or not admitted to a model (T1) reads the whole body masked, with no
    /// ask and nothing spent; `lifted_sources` that name no key read masked
    /// with nothing written.
    ///
    /// The read's fingerprint binds the artifact, `projection_fingerprint`
    /// and each group's class and keys under its own domain: an answer to
    /// its ask opens that projection's read alone, and never a stored file.
    ///
    /// # Errors
    /// As [`Self::file_sight`].
    pub(crate) fn typed_body_sight(
        &self,
        asker: &RevealAsker,
        artifact: &EntityId,
        projection_fingerprint: &[u8; 32],
        lifted_sources: &LiftedSources,
        why: &str,
    ) -> Result<SecretSight> {
        if lifted_sources.is_empty() {
            return Ok(SecretSight::Masked);
        }
        let why = checked_text(
            why,
            "a read of a typed body with keys in it says why it needs them",
            "a typed body read's why is one line of at most 512 bytes",
        )?;
        self.with_write_txn_grouped(|txn| {
            let keys = lifted_sources.keys().iter().copied();
            let Some(admitted) = admitted_keys_in_txn(self, txn, keys)? else {
                return Ok(SecretSight::Masked);
            };
            let groups = class_groups(admitted)?;
            let read = KeyRead {
                asker,
                artifact,
                why: &why,
                hash: typed_read_hash(artifact, projection_fingerprint, &groups),
                groups,
                per_class: true,
                repo: None,
            };
            self.read_sight_in_txn(txn, &read)
        })
    }

    /// The read check of the stored file `hash` of `artifact`, `sealed` when
    /// no mark covers it and it is a sealed file: its receipt, grant use or
    /// ask, and the sight it gives.
    fn stored_file_sight(
        &self,
        asker: &RevealAsker,
        artifact: &EntityId,
        (hash, sealed): ([u8; 32], bool),
        why: &str,
    ) -> Result<SecretSight> {
        let why = checked_text(
            why,
            "a read of a file with keys in it says why it needs them",
            "a file read's why is one line of at most 512 bytes",
        )?;
        self.with_write_txn_grouped(|txn| {
            let groups = if sealed {
                vec![ReadGroup {
                    class: SEALED_FILE_CLASS,
                    first: *artifact,
                    keys: Vec::new(),
                    handle: SEALED_FILE_HANDLE.to_owned(),
                }]
            } else {
                let Some(groups) = marked_groups_in_txn(self, txn, &hash)? else {
                    return Ok(SecretSight::Masked);
                };
                groups
            };
            // Only a file whose keys span classes asks per class: a file of
            // one class keeps the one ask id it has always had.
            let per_class = groups.len() > 1;
            let read = KeyRead {
                asker,
                artifact,
                why: &why,
                hash,
                groups,
                per_class,
                repo: None,
            };
            self.read_sight_in_txn(txn, &read)
        })
    }

    /// The one read check every agent's read of keys runs, in the caller's
    /// write transaction: each group of `read` judged first, with nothing
    /// written. When every group is ready (a standing grant covers it, or
    /// the owner approved its ask once), each goes out: a covered group
    /// leaves a fresh reveal row and a quiet grant use, an approved one
    /// spends its approval on its ask's row, and each stamps a T1 lease per
    /// key; the read is [`SecretSight::Granted`]. Otherwise nothing is spent
    /// or delivered, each group with no open ask files one, and the read is
    /// [`SecretSight::Masked`]: an `Ok`, so the asks it filed stay.
    fn read_sight_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        read: &KeyRead<'_>,
    ) -> Result<SecretSight> {
        self.read_sight_core_in_txn(txn, read)
            .map(|(sight, _)| sight)
    }

    /// [`Self::read_sight_in_txn`], with the id of each reveal row it
    /// delivered, in its groups' order: none for a masked read. The rows are
    /// written in `txn`; the caller hands nothing on before it commits.
    fn read_sight_core_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        read: &KeyRead<'_>,
    ) -> Result<(SecretSight, Vec<EntityId>)> {
        if read.groups.is_empty() {
            return Ok((SecretSight::Masked, Vec::new()));
        }
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        let grants = load_active_standing_grants(&self.store, txn)?;
        let mut ready = Vec::with_capacity(read.groups.len());
        let mut asks = Vec::new();
        for group in &read.groups {
            let ask = read.ask_in_txn(self, txn, group, now)?;
            let plan = match read.covering_grant(group, &grants)? {
                Some((scope, grant_ref)) => GroupPlan::Ready(Ready::Covered(scope, grant_ref)),
                None => asked_plan_in_txn(self, txn, &ask, now)?,
            };
            match plan {
                GroupPlan::Ready(plan) => ready.push((group, ask, plan)),
                GroupPlan::Waiting => {}
                GroupPlan::Asks => asks.push((group, ask)),
            }
        }
        if ready.len() < read.groups.len() {
            for (group, ask) in asks {
                let mut asked = read.row(group, now, SecretRevealState::Asked);
                file_ask_in_txn(self, txn, &ask, &mut asked, now)?;
                REVEALS.put(&self.store, txn, &ask, &asked)?;
            }
            return Ok((SecretSight::Masked, Vec::new()));
        }
        let mut delivered = Vec::with_capacity(ready.len());
        for (group, ask, plan) in ready {
            match plan {
                Ready::Covered(scope, grant_ref) => {
                    // Each read under a grant is its own receipt.
                    let reveal = self.store.clock.entity_id()?;
                    let mut row = read.row(group, now, SecretRevealState::Covered);
                    let digest = row.ask_digest(&reveal);
                    row.once_digest = Some(*digest.as_bytes());
                    let used = self.record_standing_grant_use_in_txn(txn, &grant_ref, digest)?;
                    row.answered_by = Some(standing(&grant_ref));
                    row.scope = scope;
                    row.decision = Some(used.decision_id());
                    deliver_file_in_txn(self, txn, &reveal, row)?;
                    delivered.push(reveal);
                }
                Ready::Once(mut asked, authorization) => {
                    spend_approve_once_in_txn(&self.store, txn, &authorization)?;
                    asked.decision =
                        approve_once_decision_in_txn(&self.store, txn, &authorization.digest())?;
                    deliver_file_in_txn(self, txn, &ask, *asked)?;
                    delivered.push(ask);
                }
            }
        }
        Ok((SecretSight::Granted, delivered))
    }
}

impl KeyRead<'_> {
    /// The id `group` of this read asks under at `now`: its ask's id
    /// ([`file_ask_id`]), or past each delivered or answered row of it and
    /// each row that asked for another effect, the next in its sequence
    /// ([`open_ask_id_in_txn`]).
    fn ask_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        group: &ReadGroup,
        now: u64,
    ) -> Result<EntityId> {
        let base = file_ask_id(
            self.asker,
            self.artifact,
            &self.hash,
            self.per_class.then_some(group.class),
        )?;
        let current = self.row(group, now, SecretRevealState::Asked);
        open_ask_id_in_txn(vault, txn, base, &current, now)
    }

    /// The standing grant covering `group` of this read now, with its reach:
    /// the reveal's own under any reach (FIX 2354), or a repo read's under
    /// any scope the owner granted it
    /// ([`RepoFileRevealTarget::covering_grant`]), which names no reach.
    fn covering_grant(
        &self,
        group: &ReadGroup,
        grants: &[StandingConsentGrant],
    ) -> Result<Option<(Option<RevealGrantScope>, String)>> {
        let connection = self.asker.connection();
        match self.repo {
            Some(target) => {
                let run = self.asker.run.as_deref();
                let project = self.asker.project;
                Ok(target
                    .covering_grant(&connection, group.class, project, run, grants)?
                    .map(|grant_ref| (None, grant_ref)))
            }
            None => Ok(self
                .asker
                .reach()
                .covering_grant(&connection, &reveal_class(group.class), grants)?
                .map(|(scope, grant_ref)| (Some(scope), grant_ref))),
        }
    }

    /// The reveal row `group` of this read writes, in `state`, at `now`.
    fn row(&self, group: &ReadGroup, now: u64, state: SecretRevealState) -> RevealRow {
        RevealRow {
            reader: READER_AGENT.to_owned(),
            actor: Some(self.asker.agent),
            connection: Some(self.asker.connection()),
            provider: self.asker.provider.clone(),
            secret: group.first,
            person: None,
            handle: group.handle.clone(),
            class: group.class.as_str().to_owned(),
            why: self.why.to_owned(),
            project: self.asker.project,
            run: self.asker.run.clone(),
            created_at: now,
            expires_at: now.saturating_add(REVEAL_ASK_TTL_SECS),
            state,
            once_digest: None,
            asked_decision: None,
            answered_by: None,
            decision: None,
            lease: None,
            delivered_at: None,
            file: Some(FileSight {
                artifact: *self.artifact,
                hash: self.hash,
                keys: group.keys.clone(),
                leases: Vec::new(),
                siblings: self.siblings(group),
                repo: self.repo.cloned(),
            }),
            notices: Vec::new(),
            closed: None,
            task: self.asker.task.clone(),
            attempt: self.asker.attempt,
            scope: None,
        }
    }

    /// This read's groups other than `group`, each as its class word and its
    /// keys' handles, which its ask card names (FIX 6738): none for a read of
    /// one group.
    fn siblings(&self, group: &ReadGroup) -> Vec<(String, String)> {
        self.groups
            .iter()
            .filter(|other| other.class != group.class)
            .map(|other| (other.class.as_str().to_owned(), other.handle.clone()))
            .collect()
    }
}

impl ReadGroup {
    /// The group of `keys`, each of `class`, in their order; its row names
    /// the first.
    fn of(class: CustodyClass, keys: Vec<(EntityId, String)>) -> Result<Self> {
        let first = keys
            .first()
            .map(|(secret, _)| *secret)
            .ok_or(Error::InvariantViolation("a read's key group holds no key"))?;
        let handle = keys
            .iter()
            .map(|(_, handle)| handle.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        Ok(Self {
            class,
            first,
            keys,
            handle,
        })
    }
}

/// Where the ask `ask` stands now, with nothing written: approved once in
/// its window (its marker read, not spent), waiting on the owner or denied
/// in its window, or not open, so the read asks.
fn asked_plan_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ask: &EntityId,
    now: u64,
) -> Result<GroupPlan> {
    Ok(match REVEALS.get(&vault.store, txn, ask)? {
        Some(asked) if asked.state == SecretRevealState::ApprovedOnce && now < asked.expires_at => {
            let digest = asked.stored_once_digest()?;
            let authorization = approve_once_authorization_in_txn(&vault.store, txn, &digest)?
                .ok_or(Error::InvariantViolation(
                    "an approved file read has no approve-once marker",
                ))?;
            GroupPlan::Ready(Ready::Once(Box::new(asked), authorization))
        }
        // Still waiting on the owner, or denied: the masked copy, and no
        // second ask while the window is open.
        Some(asked)
            if matches!(
                asked.state,
                SecretRevealState::Asked | SecretRevealState::Denied
            ) && now < asked.expires_at =>
        {
            GroupPlan::Waiting
        }
        _ => GroupPlan::Asks,
    })
}

/// The id a read whose ask's id is `base` asks under at `now` (FIX 6623,
/// 6737): `base` until its row is kept ([`kept_row`]) or asked for another
/// effect than `current`, the read now (FIX 7992), then the first id of its
/// sequence, each hashed from the one before under [`FILE_REASK_DOMAIN`],
/// whose row is neither. A delivered read and an owner's answer keep their
/// row and their id; the next ask, its answer and its delivery are another
/// row's. An approval once of another reason or provider keeps its row and
/// its unspent marker, so it is never spent on this read.
fn open_ask_id_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    base: EntityId,
    current: &RevealRow,
    now: u64,
) -> Result<EntityId> {
    let mut ask = base;
    while REVEALS
        .get(&vault.store, txn, &ask)?
        .is_some_and(|row| kept_row(&row, now) || !row.asks_as(current, &ask))
    {
        ask = crate::codebase::entity_id_from_hash_material(
            FILE_REASK_DOMAIN,
            &[ask.as_bytes().as_slice()],
        )?;
    }
    Ok(ask)
}

/// Whether `row` stays as it is at `now`, so the read's next ask takes the
/// next id: a delivered read, or the owner's answer (FIX 6737), a standing
/// one at once, and an approval once or a denial once its window has closed.
/// In its window an approval once still opens the read and a denial still
/// holds it masked ([`asked_plan_in_txn`]), as an open ask does; an
/// unanswered ask past its window is asked again under its own id.
fn kept_row(row: &RevealRow, now: u64) -> bool {
    match row.state {
        SecretRevealState::Delivered
        | SecretRevealState::ApprovedStanding
        | SecretRevealState::Unavailable => true,
        SecretRevealState::ApprovedOnce | SecretRevealState::Denied => now >= row.expires_at,
        SecretRevealState::Asked | SecretRevealState::Covered | SecretRevealState::Expired => false,
    }
}

impl RevealRow {
    /// Whether this row, at `ask`, asked for exactly the effect `current`
    /// would: every fact its digest binds, the reason and the provider among
    /// them, read under this row's own window (FIX 7992).
    fn asks_as(&self, current: &Self, ask: &EntityId) -> bool {
        let mut current = current.clone();
        current.expires_at = self.expires_at;
        self.once_digest == Some(*current.ask_digest(ask).as_bytes())
    }
}

/// Each key `custody` names, once, with its class and handle, in the order
/// given: `None` when one has no custody record, is not active, or is not
/// admitted to a model (T1).
fn admitted_keys_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    custody: impl IntoIterator<Item = EntityId>,
) -> Result<Option<Vec<AdmittedKey>>> {
    let floor = SecretCustodyFloor::resolve(&vault.store, txn)?;
    let mut keys: Vec<AdmittedKey> = Vec::new();
    for secret in custody {
        if keys.iter().any(|key| key.secret == secret) {
            continue;
        }
        let Some(rec) = read_secret_custody_admission_in_txn(&vault.store, txn, &secret)? else {
            return Ok(None);
        };
        if rec.status != SecretCustodyStatus::Active
            || crate::secret_lease::reveal_tier_admission(&rec, &floor).is_err()
        {
            return Ok(None);
        }
        let class = rec.class;
        let handle =
            crate::ports::ShortIdStoreRead::port_short_id_reference(&vault.store, txn, &secret)?
                .map_or(rec.name, |(short, _)| short);
        keys.push(AdmittedKey {
            class,
            secret,
            handle,
        });
    }
    Ok(Some(keys))
}

/// The keys the mark of the file `hash` names, each with its handle, in one
/// group per custody class ([`class_groups`]), each group's keys in the
/// file's order: `None` when no mark covers the file, it names no key, or a
/// key is not admitted ([`admitted_keys_in_txn`]).
fn marked_groups_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hash: &[u8; 32],
) -> Result<Option<Vec<ReadGroup>>> {
    let Some(mark) = masked_file_in_txn(&vault.store, txn, hash)? else {
        return Ok(None);
    };
    // Every key the mark places: in the stored bytes, and in each member of a
    // container.
    let marked = mark
        .keys
        .iter()
        .chain(mark.members.iter().flat_map(|member| member.keys.iter()))
        .map(|key| key.custody);
    let Some(admitted) = admitted_keys_in_txn(vault, txn, marked)? else {
        return Ok(None);
    };
    if admitted.is_empty() {
        return Ok(None);
    }
    class_groups(admitted).map(Some)
}

/// `keys` in one group per custody class: the groups in their class word's
/// order, each group's keys in the order given.
fn class_groups(keys: Vec<AdmittedKey>) -> Result<Vec<ReadGroup>> {
    let mut classes: Vec<(CustodyClass, Vec<(EntityId, String)>)> = Vec::new();
    for key in keys {
        match classes.iter_mut().find(|(class, _)| *class == key.class) {
            Some((_, held)) => held.push((key.secret, key.handle)),
            None => classes.push((key.class, vec![(key.secret, key.handle)])),
        }
    }
    classes.sort_by_key(|(class, _)| class.as_str());
    classes
        .into_iter()
        .map(|(class, keys)| ReadGroup::of(class, keys))
        .collect()
}

/// A typed body read's fingerprint: the artifact, the projection it reads
/// and each class group's keys, hashed under [`TYPED_BODY_READ_DOMAIN`].
fn typed_read_hash(
    artifact: &EntityId,
    projection_fingerprint: &[u8; 32],
    groups: &[ReadGroup],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TYPED_BODY_READ_DOMAIN);
    let mut part = |field: &[u8]| {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    };
    part(artifact.as_bytes());
    part(projection_fingerprint);
    for group in groups {
        part(group.class.as_str().as_bytes());
        part(&(group.keys.len() as u64).to_be_bytes());
        for (secret, _) in &group.keys {
            part(secret.as_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

/// The one ask an agent's reads of a file file: by the agent, the artifact
/// it reads (FIX 7992: two artifacts with the same bytes ask apart), the
/// read's hash (the stored bytes', or a typed body read's fingerprint), the
/// project and the run, and the keys' class for a group of a typed body or
/// of a file whose keys span classes. The one ask of a file of one class
/// names no class.
fn file_ask_id(
    asker: &RevealAsker,
    artifact: &EntityId,
    hash: &[u8; 32],
    class: Option<CustodyClass>,
) -> Result<EntityId> {
    let project = asker
        .project
        .map(|project| project.to_hex())
        .unwrap_or_default();
    let class = class.map_or("", CustodyClass::as_str);
    let parts: [&[u8]; 6] = [
        asker.agent.as_bytes(),
        artifact.as_bytes(),
        hash,
        project.as_bytes(),
        asker.run.as_deref().unwrap_or_default().as_bytes(),
        class.as_bytes(),
    ];
    let parts = if class.is_empty() {
        &parts[..5]
    } else {
        &parts[..]
    };
    crate::codebase::entity_id_from_hash_material(FILE_ASK_DOMAIN, parts)
}

/// Delivers a granted file read in `txn`: a T1 lease per key, each receipt
/// first, as a delivered reveal stamps one, then the row. The file's bytes
/// carry the keys; the values the leases read go nowhere.
fn deliver_file_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reveal: &EntityId,
    mut row: RevealRow,
) -> Result<()> {
    let connection = row
        .connection
        .clone()
        .ok_or(Error::CorruptedIndex("secret reveal connection"))?;
    let class = row.class()?;
    let mut file = row
        .file
        .take()
        .ok_or(Error::CorruptedIndex("secret reveal file"))?;
    let mut delivered_at = None;
    for (secret, handle) in &file.keys {
        let authority = RevealAuthority {
            secret: *secret,
            handle: handle.clone(),
            class,
            effector: format!("model:{connection}"),
        };
        let materialized = crate::secret_lease::stamp_reveal_lease_in_txn(
            vault,
            txn,
            &authority,
            REVEAL_LEASE_TTL_SECS,
        )?;
        file.leases.push(materialized.lease.lease_id);
        delivered_at.get_or_insert(materialized.lease.granted_at);
        drop(materialized.value);
    }
    // A sealed file's read stamps no lease: it is delivered now.
    if delivered_at.is_none() {
        delivered_at = Some(crate::ports::recorded_at_in_txn(&vault.store, txn)?);
    }
    row.state = SecretRevealState::Delivered;
    row.lease = file.leases.first().copied();
    row.delivered_at = delivered_at;
    row.file = Some(file);
    REVEALS.put(&vault.store, txn, reveal, &row)
}

mod lfs;
mod repo;

pub use self::repo::RepoFileRevealScope;
pub(crate) use self::repo::{
    RepoFileKeys, RepoFileOriginal, RepoFileReadDisclosure, RepoFileRevealDelivery,
    RepoFileRevealTarget, RepoFileSight,
};
