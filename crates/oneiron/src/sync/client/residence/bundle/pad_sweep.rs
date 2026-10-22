//! Erase's proofs against the home's kept pad objects (FIX 8868, 7192,
//! 7294). Each erase subject, a world whose keys were destroyed here or one
//! hard-erased key ([`PadEraseSubject`]), keeps one row in the sweep's
//! family: empty while it is only owed, else its proof. A proof binds the
//! home, the revision of the list it was made against, and only the kept
//! objects the sweep checked without the subject or rewrote without it, each
//! by its generation and the digest the home holds for it since. A kept
//! object the proof does not name, as one committed after the sweep listed
//! the home, one rewritten since or any on another home, owes the subject
//! again on the next connected upkeep: nothing counts swept because a list
//! named it.
//!
//! Rows of the earlier codec, keyed by the world alone, are not read: each
//! erased world is swept once more.

use std::collections::BTreeSet;

use super::entries::ListedGeneration;
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{PadEraseSubject, SealedBundleGeneration};
use crate::{EntityId, Vault};

/// The sweep's family: one row per subject, keyed by
/// [`PadEraseSubject::table_key`].
const SWEPT: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_SWEPT);

/// When a subject's proof is checked against the home's list again (CALLS:
/// PAD_SWEEP_RESWEEP_CADENCE).
enum ResweepCadence {
    /// On each connected upkeep: a kept object its proof does not name, a
    /// new commit, a rewrite or another home, is owed on that upkeep's list.
    /// A failed list leaves only what was owed before it.
    EachConnectedUpkeep,
}

const PAD_SWEEP_RESWEEP_CADENCE: ResweepCadence = ResweepCadence::EachConnectedUpkeep;

/// home (16) ‖ revision (32) ‖ held back (1) ‖ u64be slot ‖ u32be count.
const PROOF_HEAD_LEN: usize = 16 + 32 + 1 + 8 + 4;
/// generation (24) ‖ digest (32).
const PROOF_PAIR_LEN: usize = 24 + 32;

/// What one subject's sweep proved against the home's kept pad objects
/// (CALLS: rbe proof codec): home (16) ‖ the list's revision (32) ‖ 1 and
/// the u64be slot a kept object that opened with no key here held it back
/// in, or 0 and eight zero bytes ‖ u32be count ‖ each kept object, its
/// generation (24) ‖ its digest (32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PadSweepProof {
    pub(super) home: EntityId,
    pub(super) subject: PadEraseSubject,
    pub(super) retained_revision: [u8; 32],
    pub(super) held_back: Option<u64>,
    /// Each kept object checked or rewritten without the subject, by its
    /// generation and the digest the home holds for it since.
    pub(super) generations: Vec<(SealedBundleGeneration, [u8; 32])>,
}

impl PadSweepProof {
    fn encode(&self) -> crate::error::Result<Vec<u8>> {
        let count = u32::try_from(self.generations.len()).map_err(|_| crate::Error::InvalidKey)?;
        let mut out = Vec::with_capacity(PROOF_HEAD_LEN + self.generations.len() * PROOF_PAIR_LEN);
        out.extend_from_slice(self.home.as_bytes());
        out.extend_from_slice(&self.retained_revision);
        out.push(u8::from(self.held_back.is_some()));
        out.extend_from_slice(&self.held_back.unwrap_or_default().to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        for (generation, digest) in &self.generations {
            out.extend_from_slice(&generation.to_bytes());
            out.extend_from_slice(digest);
        }
        Ok(out)
    }

    /// `raw` as `subject`'s proof; `None` for a row that holds none (an
    /// obligation only) or does not decode.
    fn decode(subject: PadEraseSubject, raw: &[u8]) -> Option<Self> {
        let (head, pairs) = raw.split_at_checked(PROOF_HEAD_LEN)?;
        let count = u32::from_be_bytes(head[57..61].try_into().ok()?) as usize;
        if pairs.len() != count.checked_mul(PROOF_PAIR_LEN)? {
            return None;
        }
        let held_back = match head[48] {
            0 => None,
            1 => Some(u64::from_be_bytes(head[49..57].try_into().ok()?)),
            _ => return None,
        };
        let generations = pairs
            .chunks(PROOF_PAIR_LEN)
            .map(|pair| {
                Some((
                    SealedBundleGeneration::from_bytes(&pair[..24]).ok()?,
                    pair[24..].try_into().ok()?,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            home: EntityId::from_bytes(head[..16].try_into().ok()?).ok()?,
            subject,
            retained_revision: head[16..48].try_into().ok()?,
            held_back,
            generations,
        })
    }

    /// Whether it names `listed` on `home` as the home keeps it now.
    fn covers(&self, home: EntityId, listed: &ListedGeneration) -> bool {
        self.home == home
            && self
                .generations
                .contains(&(listed.generation, listed.pads_digest))
    }
}

/// One subject this machine owes the home's kept pad objects a sweep of,
/// with its proof so far.
pub(super) struct Owed {
    pub(super) subject: PadEraseSubject,
    pub(super) proof: Option<PadSweepProof>,
}

impl Owed {
    /// Whether it is due whatever the home lists: never swept, or held back
    /// in a slot before `due_from`. An unreachable home leaves such a one
    /// unswept, an error.
    pub(super) fn due_unlisted(&self, due_from: u64) -> bool {
        self.proof
            .as_ref()
            .is_none_or(|proof| proof.held_back.is_some_and(|slot| slot < due_from))
    }

    /// The kept objects of `listed` on `home` it owes a sweep of: each its
    /// proof does not name. `None` while nothing is owed, or while it was
    /// held back in `due_from` or later.
    pub(super) fn uncovered(
        &self,
        home: EntityId,
        listed: &[ListedGeneration],
        due_from: u64,
    ) -> Option<Vec<ListedGeneration>> {
        match PAD_SWEEP_RESWEEP_CADENCE {
            ResweepCadence::EachConnectedUpkeep => {}
        }
        let held_back = self.proof.as_ref().and_then(|proof| proof.held_back);
        if held_back.is_some_and(|slot| slot >= due_from) {
            return None;
        }
        let owed: Vec<_> = listed
            .iter()
            .filter(|listed| {
                self.proof
                    .as_ref()
                    .is_none_or(|proof| !proof.covers(home, listed))
            })
            .copied()
            .collect();
        (self.proof.is_none() || held_back.is_some() || !owed.is_empty()).then_some(owed)
    }

    /// Its proof once the sweep checked or rewrote `swept` on `home`, against
    /// the list of revision `revision` that keeps `kept`: those, and each
    /// pair of its proof so far on that home whose generation is still kept,
    /// the newer winning. `held_back` names the slot a kept object that
    /// opened with no key here held it back in.
    pub(super) fn proved(
        &self,
        home: EntityId,
        revision: [u8; 32],
        kept: &[SealedBundleGeneration],
        swept: &[(SealedBundleGeneration, [u8; 32])],
        held_back: Option<u64>,
    ) -> PadSweepProof {
        let fresh: BTreeSet<_> = swept.iter().map(|(generation, _)| *generation).collect();
        let mut generations: Vec<_> = self
            .proof
            .iter()
            .filter(|proof| proof.home == home)
            .flat_map(|proof| proof.generations.iter().copied())
            .filter(|(generation, _)| kept.contains(generation) && !fresh.contains(generation))
            .collect();
        generations.extend_from_slice(swept);
        PadSweepProof {
            home,
            subject: self.subject,
            retained_revision: revision,
            held_back,
            generations,
        }
    }
}

/// Every subject this machine owes the home's kept pad objects: each world
/// erased here and each key a hard erase staged, with its proof so far.
pub(super) fn owed_subjects(vault: &Vault) -> crate::error::Result<Vec<Owed>> {
    let destroyed = vault.world_key_destructions()?;
    let txn = vault.store.env.read_txn()?;
    let mut subjects = BTreeSet::new();
    for receipt in destroyed {
        if let Ok(world) = EntityId::from_hex(&receipt.world) {
            subjects.insert(PadEraseSubject::World(world));
        }
    }
    for row in SWEPT.iter_raw_from(&vault.store, &txn, b"k:")? {
        let (key, _) = row?;
        if let Some(subject) = PadEraseSubject::from_table_key(&key) {
            subjects.insert(subject);
        }
    }
    subjects
        .into_iter()
        .map(|subject| {
            let raw = SWEPT.get_bytes(&vault.store, &txn, &subject.table_key())?;
            Ok(Owed {
                subject,
                proof: raw.and_then(|raw| PadSweepProof::decode(subject, &raw)),
            })
        })
        .collect()
}

/// Writes each of `proofs`.
pub(super) fn record(vault: &Vault, proofs: &[PadSweepProof]) -> crate::error::Result<()> {
    if proofs.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for proof in proofs {
            SWEPT.put(
                &vault.store,
                wtxn,
                &proof.subject.table_key(),
                &proof.encode()?,
            )?;
        }
        Ok(())
    })
}
