//! The home's prediction for one machine at the predicted level (ARCH-0023b #predicted-residence).
//!
//! "Home computes PPR over the machine's admitted world set. The set is filtered before the
//! walk, so a withheld world moves no score. Home pushes the result as a residence directive. It picks window and entity
//! documents, never single items. Home recomputes on a cadence, with hysteresis. ... Prediction freezes while home is down."
//!
//! The machine's connection drives the cadence (Engine ruling L7-46-MERGE A, 14 Nov): each ask
//! runs on a fresh per-request admission, and the home signs and appends a full-set prediction
//! that replaces the last one. The owner's live `SyncPredicted` directive is the parent the
//! prediction names (PLAN-SIGNER A); its budget binds, with no ceiling (L7-46-BUDGET B and
//! BUDGET-CEILING): the prediction entry carries only the set's digest and counts, the set body
//! is content-addressed, and only the target machine fetches it, by digest, over its connection.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_retrieval::pipeline::ScoredEntity;

use super::directives::directive_states_in_txn;
use super::{
    ResidenceAdmission, ResidenceDirectiveState, local_is_elected_home, residence_window_for_blob,
};
#[cfg(oneiron_test_support)]
use crate::authority::{Destination, WorldPrivacyView};
use crate::authority::{
    HostSlipIssuer, PredictedResidenceSet, ResidenceAct, ResidenceDirective, invalid_authority,
};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::ppr::{PprNodeVisibility, SeedWeighting, ppr_query_scoped_in_txn};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::{EntityId, Vault};

/// The home's touch log: when one proved machine last touched one entity, in recorded-clock
/// seconds.
const MACHINE_TOUCH: SideTable<(HexId, HexId), u64, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_MACHINE_TOUCH);
/// The predicted-set bodies the home pushed for one machine, by digest (64 lowercase hex).
const PREDICTED_BODY: SideTable<(HexId, String), Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_PREDICTED_BODY);

/// The most touches one prediction walks from.
pub(crate) const PREDICT_SEEDS_MAX: usize = 64;
/// How long a touch seeds predictions, in recorded-clock seconds: thirty days.
pub(crate) const PREDICT_SEED_AGE_SECS: u64 = 30 * 24 * 3600;
/// How many hops a prediction walk runs from its seeds.
pub(crate) const PREDICT_DEPTH: u32 = 2;
/// The walk's restart probability: the standard expansion's 0.15, as `retrieval_depth` runs it
/// (that module keeps its own `STANDARD_PPR_ALPHA` private).
const PREDICT_PPR_ALPHA: f32 = 0.15;

/// What the home did with one machine's ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredictedResidenceAnswer {
    /// A new prediction, appended and signed by this host.
    Pushed(ResidenceDirectiveState),
    /// The kept set equals the machine's last prediction: nothing appended.
    Unchanged,
}

/// One request's admission as a walk's visibility: a node holds mass only while the admission
/// reads it, so a withheld world moves no score.
struct AdmittedNodes<'a, 'v>(&'a ResidenceAdmission<'v>);

impl PprNodeVisibility for AdmittedNodes<'_, '_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        self.0.allows_item_in(txn, *id)
    }
}

/// The owner-grade view a home holds of one linked machine: every node is visible except those in
/// a world withheld from it. Test doors predict through it; production predicts through the
/// request's own admission.
#[cfg(oneiron_test_support)]
pub(crate) struct WithholdingNodes<'v> {
    vault: &'v Vault,
    withheld: BTreeSet<EntityId>,
}

#[cfg(oneiron_test_support)]
impl<'v> WithholdingNodes<'v> {
    /// The view of `machine`: the worlds kept off it, read now.
    pub(crate) fn for_machine(vault: &'v Vault, machine: EntityId) -> Result<Self> {
        let txn = vault.store.env.read_txn()?;
        let withheld =
            WorldPrivacyView::load_in(vault, &txn)?.withheld_for(Destination::Machine(machine))?;
        Ok(Self { vault, withheld })
    }
}

#[cfg(oneiron_test_support)]
impl PprNodeVisibility for WithholdingNodes<'_> {
    fn ppr_node_visible(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let Some(raw) = self.vault.store.port_entity_raw(txn, id)? else {
            return Ok(false);
        };
        let world = crate::sync::types::entity_world(&raw)?;
        Ok(world.is_none_or(|world| !self.withheld.contains(&world)))
    }
}

/// The owner's live approval one prediction executes.
struct LivePredictedParent {
    /// The approval's directive id: the parent the prediction names.
    id: EntityId,
    /// The owner the approval's door authenticated.
    owner: EntityId,
    /// The most windows one prediction names.
    window_budget: u32,
    /// The most entity documents one prediction names.
    document_budget: u32,
}

/// Refuses a prediction, as the directive door refuses one.
fn refused(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// A set digest as its key spells it: 64 lowercase hex characters.
fn digest_hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

/// The set body's key for the prediction `machine` holds under `digest`.
fn predicted_body_key(machine: EntityId, digest: &[u8; 32]) -> (HexId, String) {
    (HexId(machine), digest_hex(digest))
}

/// The live predicted-level approval for `machine`: its latest mode act, which must be the
/// owner's predicted approval. The states arrive oldest first, so the last mode act naming the
/// machine is the live one.
fn live_predicted_parent(
    states: &[ResidenceDirectiveState],
    machine: EntityId,
) -> Result<LivePredictedParent> {
    let live = states.iter().rev().find(|state| {
        state.directive.machine == machine
            && matches!(
                state.directive.act,
                ResidenceAct::SyncAll
                    | ResidenceAct::SyncOpened
                    | ResidenceAct::SyncPredicted { .. }
            )
    });
    let Some(state) = live else {
        return Err(refused("this machine is not at the predicted level"));
    };
    let ResidenceAct::SyncPredicted {
        window_budget,
        document_budget,
    } = state.directive.act
    else {
        return Err(refused("this machine is not at the predicted level"));
    };
    Ok(LivePredictedParent {
        id: state.directive.id,
        owner: state.directive.owner,
        window_budget,
        document_budget,
    })
}

/// The units one prediction keeps under `budget` with hysteresis toward the previous set: the
/// previous set's members ranked within the first `2 * budget` stay, then the first-ranked units
/// fill to `budget`. A previous member ranked beyond `2 * budget`, or no longer scored, leaves.
fn hysteresis_keep<T>(ranked: &[T], previous: &BTreeSet<T>, budget: u32) -> BTreeSet<T>
where
    T: Clone + Ord,
{
    let budget = usize::try_from(budget).unwrap_or(usize::MAX);
    // A previous set never exceeds its budget; the cap keeps a foreign one from breaking this.
    let mut kept: BTreeSet<T> = ranked
        .iter()
        .take(budget.saturating_mul(2))
        .filter(|unit| previous.contains(*unit))
        .take(budget)
        .cloned()
        .collect();
    for unit in ranked {
        if kept.len() >= budget {
            break;
        }
        kept.insert(unit.clone());
    }
    kept
}

/// The windows one prediction names: scored windows ranked by summed score descending, ties by key
/// ascending, kept under `budget` with hysteresis toward `previous`.
fn keep_ranked_windows(
    scores: &BTreeMap<String, f32>,
    previous: &BTreeSet<String>,
    budget: u32,
) -> BTreeSet<String> {
    let mut ranked: Vec<(String, f32)> = scores
        .iter()
        .map(|(key, score)| (key.clone(), *score))
        .collect();
    ranked.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    let ranked: Vec<String> = ranked.into_iter().map(|(key, _)| key).collect();
    hysteresis_keep(&ranked, previous, budget)
}

/// The entity documents one prediction names: scored holders ranked by score descending, ties by
/// id ascending, kept under `budget` with hysteresis toward `previous`.
fn keep_ranked_documents(
    scores: &[(EntityId, f32)],
    previous: &BTreeSet<EntityId>,
    budget: u32,
) -> BTreeSet<EntityId> {
    let mut ranked: Vec<(EntityId, f32)> = scores.to_vec();
    ranked.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
    });
    let ranked: Vec<EntityId> = ranked.into_iter().map(|(id, _)| id).collect();
    hysteresis_keep(&ranked, previous, budget)
}

impl Vault {
    /// Records that this home served `entity` to the proved `machine` on a residence touch: one
    /// seed of that machine's next prediction. A promotion records nothing, so the machine's own
    /// prefetch of a prediction never seeds the next one.
    ///
    /// # Errors
    ///
    /// Storage.
    pub fn record_machine_touch(&self, machine: EntityId, entity: EntityId) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let now = self.instant_in_txn(txn)?.secs();
            MACHINE_TOUCH.put(&self.store, txn, &(HexId(machine), HexId(entity)), &now)
        })
    }

    /// The home's prediction for `machine`, over what `admission` lets it read (production: the
    /// request's own admission).
    ///
    /// # Errors
    ///
    /// A refusal (`InvalidConfig`) for a machine with no standing proof, for the elected home's own
    /// machine, or for one not at the predicted level; storage.
    pub fn predict_residence_for(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        admission: &ResidenceAdmission<'_>,
    ) -> Result<PredictedResidenceAnswer> {
        let nodes = AdmittedNodes(admission);
        self.predict_residence_with(issuer, machine, &nodes)
    }

    /// The set body this home pushed for `machine` under `digest`, if it still holds it.
    ///
    /// # Errors
    ///
    /// Storage.
    pub fn predicted_residence_body(
        &self,
        machine: EntityId,
        digest: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let txn = self.store.env.read_txn()?;
        PREDICTED_BODY.get(&self.store, &txn, &predicted_body_key(machine, digest))
    }

    /// [`Self::predict_residence_for`] through `visibility`: the whole prediction in one write
    /// transaction, from the refusals to the appended directive.
    pub(crate) fn predict_residence_with(
        &self,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        visibility: &dyn PprNodeVisibility,
    ) -> Result<PredictedResidenceAnswer> {
        // Read before the writer: the election check may mint this install's sync id.
        let home_here = local_is_elected_home(self)?;
        let mut txn = self.store.env.write_txn()?;
        self.refuse_unless_predictable(&txn, machine, home_here)?;
        let states = directive_states_in_txn(self, &txn)?;
        let parent = live_predicted_parent(&states, machine)?;
        let now = self.instant_in_txn(&txn)?.secs();
        let seeds = self.fresh_machine_seeds(&mut txn, machine, now, visibility)?;
        if seeds.is_empty() {
            txn.commit()?;
            return Ok(PredictedResidenceAnswer::Unchanged);
        }
        let scores = ppr_query_scoped_in_txn(
            &self.store,
            &txn,
            &seeds,
            PREDICT_DEPTH,
            PREDICT_PPR_ALPHA,
            self.config.ppr_vad_alpha,
            SeedWeighting::Uniform,
            visibility,
        )?;
        let (windows, documents) = self.prediction_units(&txn, &scores)?;
        let (previous, prediction_exists) =
            self.previous_predicted_set(&txn, &states, machine, parent.id)?;
        let set = PredictedResidenceSet {
            windows: keep_ranked_windows(&windows, &previous.windows, parent.window_budget),
            documents: keep_ranked_documents(
                &documents,
                &previous.documents,
                parent.document_budget,
            ),
        };
        if prediction_exists && set == previous {
            txn.commit()?;
            return Ok(PredictedResidenceAnswer::Unchanged);
        }
        let pushed = self.push_prediction(&mut txn, issuer, machine, &parent, now, &set)?;
        txn.commit()?;
        Ok(PredictedResidenceAnswer::Pushed(pushed))
    }

    /// Refuses a prediction that names no standing machine, or this install while it is the
    /// elected home.
    fn refuse_unless_predictable(
        &self,
        txn: &heed::RoTxn<'_>,
        machine: EntityId,
        home_here: bool,
    ) -> Result<()> {
        if self
            .authority_view_readonly_in_txn(txn)?
            .machine_proof_key(machine)
            .is_none()
        {
            return Err(refused("a prediction names one of the owner's machines"));
        }
        if home_here && crate::identity::read_machine_id_in_txn(self, txn)? == Some(machine) {
            return Err(refused(
                "the elected home always syncs every window it may read",
            ));
        }
        Ok(())
    }

    /// The machine's fresh prediction seeds: its touch log's touches within `PREDICT_SEED_AGE_SECS`
    /// of `now`, most recent first, at most `PREDICT_SEEDS_MAX`, each shown by `visibility`. Drops
    /// its older touches in the same transaction.
    fn fresh_machine_seeds(
        &self,
        txn: &mut heed::RwTxn<'_>,
        machine: EntityId,
        now: u64,
        visibility: &dyn PprNodeVisibility,
    ) -> Result<Vec<EntityId>> {
        let rows = MACHINE_TOUCH.scan_from(&self.store, txn, machine.to_hex().as_bytes())?;
        let mut fresh: Vec<(u64, EntityId)> = Vec::new();
        for (key, touched) in rows {
            if now.saturating_sub(touched) > PREDICT_SEED_AGE_SECS {
                MACHINE_TOUCH.delete(&self.store, txn, &key)?;
                continue;
            }
            fresh.push((touched, key.1.0));
        }
        fresh.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
        });
        let mut seeds = Vec::new();
        for (_, entity) in fresh {
            if seeds.len() >= PREDICT_SEEDS_MAX {
                break;
            }
            if visibility.ppr_node_visible(txn, &entity)? {
                seeds.push(entity);
            }
        }
        Ok(seeds)
    }

    /// The scored units of one prediction walk: each scored entity's window with its summed score,
    /// and each scored entity holding an entity document with its own score. Seeds count as scored.
    fn prediction_units(
        &self,
        txn: &heed::RoTxn<'_>,
        scores: &[ScoredEntity],
    ) -> Result<(BTreeMap<String, f32>, Vec<(EntityId, f32)>)> {
        let mut windows: BTreeMap<String, f32> = BTreeMap::new();
        let mut documents = Vec::new();
        for scored in scores {
            let Some(raw) = self.store.port_entity_raw(txn, &scored.id)? else {
                continue;
            };
            let window = residence_window_for_blob(&raw)?;
            *windows.entry(window.as_str().to_owned()).or_default() += scored.score;
            if crate::entity_doc::has_record_head(&self.store, txn, &scored.id)? {
                documents.push((scored.id, scored.score));
            }
        }
        Ok((windows, documents))
    }

    /// The machine's previous predicted set under `parent`: the body of its last `Predicted`
    /// directive under that parent, and whether such a prediction exists. Empty when it has none,
    /// or no longer holds its body.
    fn previous_predicted_set(
        &self,
        txn: &heed::RoTxn<'_>,
        states: &[ResidenceDirectiveState],
        machine: EntityId,
        parent: EntityId,
    ) -> Result<(PredictedResidenceSet, bool)> {
        let last = states.iter().rev().find(|state| {
            state.directive.machine == machine
                && matches!(
                    &state.directive.act,
                    ResidenceAct::Predicted { parent: named, .. } if *named == parent
                )
        });
        let Some(state) = last else {
            return Ok((PredictedResidenceSet::default(), false));
        };
        let ResidenceAct::Predicted { set_digest, .. } = &state.directive.act else {
            return Ok((PredictedResidenceSet::default(), false));
        };
        let body =
            PREDICTED_BODY.get(&self.store, txn, &predicted_body_key(machine, set_digest))?;
        let Some(body) = body else {
            return Ok((PredictedResidenceSet::default(), true));
        };
        Ok((
            PredictedResidenceSet::decode_verified(&body, set_digest)?,
            true,
        ))
    }

    /// Pushes `set` as the machine's new prediction under `parent` in `txn`: stores its body,
    /// keeps only that body, and appends and signs the directive naming it. The caller commits.
    fn push_prediction(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        machine: EntityId,
        parent: &LivePredictedParent,
        now: u64,
        set: &PredictedResidenceSet,
    ) -> Result<ResidenceDirectiveState> {
        let body = set.encode()?;
        let digest = PredictedResidenceSet::body_digest(&body);
        let (window_count, document_count) = set.counts().ok_or_else(invalid_authority)?;
        PREDICTED_BODY.put(
            &self.store,
            txn,
            &predicted_body_key(machine, &digest),
            &body,
        )?;
        self.drop_older_predicted_bodies(txn, machine, &digest)?;
        let directive = ResidenceDirective {
            id: EntityId::now(),
            machine,
            owner: parent.owner,
            issued_at: now,
            act: ResidenceAct::Predicted {
                parent: parent.id,
                set_digest: digest,
                window_count,
                document_count,
            },
        };
        let entry = self.append_residence_directive_in_txn(txn, issuer, directive.clone())?;
        Ok(ResidenceDirectiveState {
            directive,
            entry,
            result: None,
        })
    }

    /// Drops the predicted-set bodies `machine` no longer holds: every `pb:` row but the one under
    /// `keep`.
    fn drop_older_predicted_bodies(
        &self,
        txn: &mut heed::RwTxn<'_>,
        machine: EntityId,
        keep: &[u8; 32],
    ) -> Result<()> {
        let keep = digest_hex(keep);
        let held = PREDICTED_BODY.scan_keys(&self.store, txn, machine.to_hex().as_bytes())?;
        for key in held {
            if key.1 != keep {
                PREDICTED_BODY.delete(&self.store, txn, &key)?;
            }
        }
        Ok(())
    }
}
