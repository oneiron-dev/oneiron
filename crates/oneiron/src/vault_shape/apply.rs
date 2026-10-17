//! Apply: the gated landing of a plan, one item at a time, through the named
//! doors the vault already has. The seed is stored first, so the intent
//! leads and the live arrangement follows it. A journal row keyed by the
//! plan's frontier records how each item landed, written after each one, so
//! a torn apply resumes where it stopped and an item that already landed is
//! read as landed. The shape holds no authority: an owner's apply lands
//! through the owner's doors, a widening only on the owner's word for that
//! item, and an actor's apply lands nothing and leaves every item waiting.
//! A new grant an actor declares also goes to the owner's widen inbox, filed
//! under the actor's own credential.
use super::live::world_name;
use super::plan::{ShapeChange, ShapeItemClass, ShapePlan, ShapePlanItem};
use super::{ShapeRow, ShapeTarget, invalid};
use crate::agent_def::{AgentDefinition, AgentScope};
use crate::authority::VerifiedSlip;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::PackInstallDisposition;
use crate::{EntityId, TimeRange, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How long a grant an actor's apply files waits in the owner's widen inbox:
/// the inbox's own ceiling. The item itself waits in the journal past it.
const SHAPE_GRANT_PROPOSAL_SECS: u64 = 3600;

/// Every apply's journal, keyed by the frontier of the plan it lands.
const JOURNAL: SideTable<String, ShapeApplyReceipt, Named> =
    SideTable::new(&side_table::VAULT_SHAPE_APPLY);

/// `vault.shape.apply`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeApplyRequest {
    /// The plan to land, as `vault.shape.plan` rendered it.
    pub plan: ShapePlan,
    /// The widening items the owner gives their word for, by `seq`. Only
    /// the owner's apply reads it.
    #[serde(default)]
    pub approve: Vec<u32>,
}

/// Where one item stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ShapeItemState {
    /// Not reached yet; a torn apply resumes here.
    Pending,
    /// Landed through its door, with that door's receipt.
    Landed { at: u64, receipt: String },
    /// Waits for the owner's word: an owner's apply that approves its `seq`
    /// lands it.
    Proposed,
    /// A new grant an actor's apply filed to the owner's widen inbox, where
    /// accepting `proposal_ref` mints it. Until the owner answers, it waits
    /// as [`Self::Proposed`] does, and an owner's apply may land it.
    Filed {
        proposal_ref: String,
        expires_at: u64,
    },
    /// An authority operation, for its AUTHORITY_LOG ceremony.
    Ceremony,
    /// The vault has no door for it yet; nothing landed.
    NoDoor,
    /// Its door refused it, or the structure changed since the plan read it.
    Refused { reason: String },
}

/// One plan item and where it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeApplyItem {
    pub item: ShapePlanItem,
    pub state: ShapeItemState,
}

/// One apply: its journal row, and `vault.shape.apply`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ShapeApplyReceipt {
    /// The frontier of the plan this apply lands; its journal key.
    pub frontier: String,
    /// The seed revision the apply stored first.
    pub seed_id: String,
    /// The actor that started it, hex.
    pub author: String,
    pub started_at: u64,
    pub items: Vec<ShapeApplyItem>,
    /// No item is pending or waiting.
    pub done: bool,
}

/// Who applies: the vault's owner, or another actor with the credential it
/// presented, if any.
#[derive(Debug, Clone, Copy)]
pub enum ShapeApplier<'a> {
    Owner(&'a AuthenticatedOwner),
    Actor {
        actor: EntityId,
        credential: Option<&'a VerifiedSlip>,
    },
}

const fn open(state: &ShapeItemState) -> bool {
    matches!(
        state,
        ShapeItemState::Pending | ShapeItemState::Proposed | ShapeItemState::Filed { .. }
    )
}

/// Where an item rests before anyone may land it.
fn held(item: &ShapePlanItem) -> ShapeItemState {
    if item.door.is_none() {
        ShapeItemState::NoDoor
    } else if item.class == ShapeItemClass::Authority {
        ShapeItemState::Ceremony
    } else {
        ShapeItemState::Proposed
    }
}

/// The next version of a definition the shape updates: the next integer,
/// else the old version with a `.shape` step.
fn next_version(version: &str) -> String {
    version.parse::<u64>().map_or_else(
        |_| format!("{version}.shape"),
        |number| (number + 1).to_string(),
    )
}

type LiveByTarget = BTreeMap<ShapeTarget, (ShapeRow, Option<EntityId>)>;

impl Vault {
    /// The journal of the apply landing the plan at `frontier`.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn shape_apply(&self, frontier: &str) -> Result<Option<ShapeApplyReceipt>> {
        let txn = self.store.env.read_txn()?;
        JOURNAL.get(&self.store, &txn, &frontier.to_owned())
    }

    /// Every apply with an item still pending or waiting for the owner.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn open_shape_applies(&self) -> Result<Vec<ShapeApplyReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(JOURNAL
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .filter(|receipt| !receipt.done)
            .collect())
    }

    fn put_shape_apply(&self, receipt: &ShapeApplyReceipt) -> Result<()> {
        self.with_write_txn_grouped(|txn| JOURNAL.put(&self.store, txn, &receipt.frontier, receipt))
    }

    /// Lands `request.plan`. A first apply re-plans its seed over the rows
    /// `visible` admits and refuses a plan whose frontier has moved; then it
    /// stores the seed and opens the journal. Later applies of the same plan
    /// resume its journal. Each open item then lands, waits or is refused,
    /// and the journal is written after each.
    ///
    /// # Errors
    ///
    /// A stale plan, an owner proof that no longer holds, or a store failure.
    /// A door's own refusal is the item's state, not an error.
    pub fn apply_shape(
        &self,
        applier: ShapeApplier<'_>,
        request: &ShapeApplyRequest,
        now: u64,
        visible: &mut dyn FnMut(&EntityId) -> Result<bool>,
    ) -> Result<ShapeApplyReceipt> {
        // The owner's proof names the author; it must still hold.
        let author = match applier {
            ShapeApplier::Owner(owner) => owner.revalidate(self)?,
            ShapeApplier::Actor { actor, .. } => actor,
        };
        let mut journal = if let Some(journal) = self.shape_apply(&request.plan.frontier)? {
            journal
        } else {
            let plan = self.plan_shape_visible(Some(&request.plan.seed), visible)?;
            if plan.frontier != request.plan.frontier {
                return Err(invalid(
                    "the vault has moved since this plan was read; plan again",
                ));
            }
            let stored = self.put_shape_seed(author, &plan.seed, now)?;
            let journal = ShapeApplyReceipt {
                frontier: plan.frontier,
                seed_id: stored.id,
                author: author.to_hex(),
                started_at: now,
                items: plan
                    .items
                    .into_iter()
                    .map(|item| ShapeApplyItem {
                        item,
                        state: ShapeItemState::Pending,
                    })
                    .collect(),
                done: false,
            };
            self.put_shape_apply(&journal)?;
            journal
        };

        let owner = match applier {
            ShapeApplier::Owner(owner) => owner,
            ShapeApplier::Actor { credential, .. } => {
                // An actor holds none of the owner's doors, so its apply
                // lands nothing: each item waits for the owner (DEC-0006 is
                // unchanged), and a new grant is also filed to the owner's
                // widen inbox.
                for entry in &mut journal.items {
                    if entry.state == ShapeItemState::Pending {
                        entry.state = self.file_shape_grant(credential, &entry.item);
                    }
                }
                journal.done = !journal.items.iter().any(|entry| open(&entry.state));
                self.put_shape_apply(&journal)?;
                return Ok(journal);
            }
        };

        let live: LiveByTarget = self
            .read_live_shape(&mut |_| Ok(true))?
            .rows
            .into_iter()
            .map(|(row, entity)| (row.target(), (row, entity)))
            .collect();
        for index in 0..journal.items.len() {
            let entry = &journal.items[index];
            if !open(&entry.state) {
                continue;
            }
            let item = &entry.item;
            let state = match held(item) {
                ShapeItemState::Proposed
                    if item.class == ShapeItemClass::Widening
                        && !request.approve.contains(&item.seq) =>
                {
                    match &entry.state {
                        // A filing keeps its inbox reference while it waits.
                        filed @ ShapeItemState::Filed { .. } => filed.clone(),
                        _ => ShapeItemState::Proposed,
                    }
                }
                ShapeItemState::Proposed => match self.land_shape_item(owner, item, &live, now) {
                    Ok(receipt) => ShapeItemState::Landed { at: now, receipt },
                    Err(error) => ShapeItemState::Refused {
                        reason: error.to_string(),
                    },
                },
                rest => rest,
            };
            journal.items[index].state = state;
            self.put_shape_apply(&journal)?;
        }
        journal.done = !journal.items.iter().any(|entry| open(&entry.state));
        self.put_shape_apply(&journal)?;
        Ok(journal)
    }

    /// Where an actor's apply leaves `item`: a new grant it carries the bound
    /// of is filed to the owner's widen inbox under `credential`, as an
    /// action or a disclosure widening, for the vault's embedded owner to
    /// answer. Anything else, or a filing the inbox refuses, rests where any
    /// actor's item rests, waiting for the owner.
    fn file_shape_grant(
        &self,
        credential: Option<&VerifiedSlip>,
        item: &ShapePlanItem,
    ) -> ShapeItemState {
        let resting = held(item);
        let (
            Some(credential),
            ShapeItemState::Proposed,
            ShapeChange::Create,
            Some(ShapeRow::Grant {
                bound: Some(bound), ..
            }),
        ) = (credential, &resting, item.change, &item.after)
        else {
            return held(item);
        };
        let filed = bound.bound().and_then(|grant| {
            let owner_ref = crate::vault::embedded_owner_actor_id()?.to_hex();
            let expires_at = self.store.clock.peek_recorded_at() + SHAPE_GRANT_PROPOSAL_SECS;
            if bound.is_action() {
                self.propose_action_widen(credential, grant, &owner_ref, expires_at)
            } else {
                self.propose_disclosure_widen(credential, grant, &owner_ref, expires_at)
            }
        });
        match filed {
            Ok(proposal) => ShapeItemState::Filed {
                proposal_ref: proposal.proposal_ref,
                expires_at: proposal.expires_at,
            },
            Err(_) => resting,
        }
    }

    /// Lands one item through its door, after checking the structure is
    /// still as the plan read it. An item already true is landed.
    fn land_shape_item(
        &self,
        owner: &AuthenticatedOwner,
        item: &ShapePlanItem,
        live: &LiveByTarget,
        now: u64,
    ) -> Result<String> {
        let current = live.get(&item.target);
        let already = |row: &ShapeRow| {
            item.after
                .as_ref()
                .is_some_and(|after| after.satisfied_by(row))
        };
        let stale = || invalid("the structure changed since the plan read it");
        let entity = match (item.change, current) {
            (ShapeChange::Create, None) => None,
            (ShapeChange::Create | ShapeChange::Update, Some((row, _))) if already(row) => {
                return Ok("already so".to_owned());
            }
            (ShapeChange::Update | ShapeChange::Retire, Some((row, entity)))
                if item.before.as_ref() == Some(row) =>
            {
                *entity
            }
            (ShapeChange::Retire, None) => return Ok("already gone".to_owned()),
            _ => return Err(stale()),
        };
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        match (&item.change, &item.target, &item.after) {
            (ShapeChange::Create, ShapeTarget::World { name }, _) => {
                Ok(self.create_world(owner, name, now)?.to_hex())
            }
            (
                ShapeChange::Create,
                ShapeTarget::Actor { agent_id },
                Some(ShapeRow::Actor {
                    ceiling, enabled, ..
                }),
            ) => {
                let id = EntityId::now();
                let def = AgentDefinition::new(
                    agent_id.clone(),
                    "Declared by the vault's shape.",
                    "1",
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    None,
                    AgentScope::All,
                    (*ceiling).into(),
                    None,
                    ClaimApprovalStatus::Approved,
                    ClaimLifecycleStatus::Active,
                    ClaimSource::UserStated,
                    1.0,
                    false,
                    true,
                    rmpv::Value::Map(Vec::new()),
                    None,
                    *enabled,
                    None,
                );
                owner.revalidate(self)?;
                self.put_agent_definition(&id, &def, occurred, now)?;
                Ok(id.to_hex())
            }
            (ShapeChange::Update | ShapeChange::Retire, ShapeTarget::Actor { .. }, after) => {
                let id = entity.ok_or_else(stale)?;
                let mut def = self.get_agent_definition(&id)?.ok_or_else(stale)?;
                match after {
                    Some(ShapeRow::Actor {
                        ceiling, enabled, ..
                    }) => {
                        def.ceiling = (*ceiling).into();
                        def.enabled = *enabled;
                    }
                    // Retiring an actor takes it off duty; its row stays.
                    _ => def.enabled = false,
                }
                def.version = next_version(&def.version);
                self.update_agent_definition_as(owner, &id, &def, occurred, now)?;
                Ok(id.to_hex())
            }
            (
                ShapeChange::Create | ShapeChange::Update,
                ShapeTarget::Pack { name },
                Some(ShapeRow::Pack { version, .. }),
            ) => {
                let source = self
                    .list_pack_sources()?
                    .into_iter()
                    .map(|(_, source)| source)
                    .filter(|source| {
                        source.manifest().name == *name
                            && version
                                .as_ref()
                                .is_none_or(|version| source.manifest().version == *version)
                    })
                    .last()
                    .ok_or_else(|| invalid("no staged source of that pack and version"))?;
                match self.put_pack(owner, source.files().to_vec())? {
                    PackInstallDisposition::Installed(receipt) => Ok(receipt.content_hash),
                    PackInstallDisposition::Candidate(_) => {
                        Err(invalid("the pack is held a candidate until it qualifies"))
                    }
                    PackInstallDisposition::Blocked { reason } => Err(invalid(reason)),
                }
            }
            (ShapeChange::Retire, ShapeTarget::Pack { name }, _) => {
                Ok(self.remove_pack(owner, name)?.content_hash)
            }
            (
                ShapeChange::Create,
                ShapeTarget::Grant { grant_ref },
                Some(ShapeRow::Grant {
                    bound: Some(bound), ..
                }),
            ) => {
                let _receipt = self.create_standing_grant(owner, bound.bound()?)?;
                Ok(grant_ref.clone())
            }
            (ShapeChange::Retire, ShapeTarget::Grant { grant_ref }, _) => {
                let _receipt = self.revoke_consent_grant(owner, grant_ref)?;
                Ok(grant_ref.clone())
            }
            _ => Err(invalid("the vault has no door for this item")),
        }
    }

    /// Creates a world named `name`, as `owner`: an ordinary setup write
    /// that widens nothing. A live world already carrying the name refuses.
    ///
    /// # Errors
    ///
    /// A blank or taken name, an owner proof that no longer holds, or a
    /// store failure.
    pub fn create_world(
        &self,
        owner: &AuthenticatedOwner,
        name: &str,
        now: u64,
    ) -> Result<EntityId> {
        #[derive(Serialize)]
        struct WorldBody<'a> {
            name: &'a str,
        }
        if name.trim().is_empty() || name.len() > super::SHAPE_NAME_MAX_BYTES {
            return Err(invalid("a world's name is 1 to 256 bytes and not blank"));
        }
        let body = rmp_serde::to_vec_named(&WorldBody { name })
            .map_err(|_| invalid("world encoding failed"))?;
        let id = EntityId::now();
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            for (_, existing) in self.shape_bodies_in_txn(txn, ENTITY_TYPE_WORLD)? {
                if world_name(&existing).as_deref() == Some(name) {
                    return Err(invalid("a live world already carries that name"));
                }
            }
            self.batch_in()
                .put(
                    &id,
                    ENTITY_TYPE_WORLD,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .apply(txn)?;
            Ok(id)
        })
    }
}
