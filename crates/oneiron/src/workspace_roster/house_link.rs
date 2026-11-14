//! A house mind's link to the org it runs (HOUSE-BIND = A: the owner, 10 Nov
//! 07:43; the Engine's link shapes, 07:5x).
//!
//! The house agent keeps its own model PERSON anchor (ARCH-0067): binding it
//! changes no subject anchor, so everything the agent knows and did stays
//! keyed to the agent. The workspace's stored preset is the statement that
//! its house runs its ORG. The bind adds the house's role in that org: one
//! FEDERATION_GRANT over the workspace's shared vault, its member the house,
//! at the role its binder chose: member, steward, admin, deputy or owner. So
//! [`Vault::authorize_shared_vault_write`] gates the house by that role and
//! by nothing else, and its actor class stays `agent`. The binder names the
//! role; a binder that names none gets [`DEFAULT_HOUSE_ROLE`], deputy
//! (DEPUTY = A, the owner, 10 Nov 07:45), which the host's finish applies.
//!
//! Who may set that role is the role table's rule (ARCH-0043), the one the
//! membership acts apply: a member, steward or admin role is set by whoever
//! holds `org:assign-role` over the vault (an Admin or an Owner by the
//! shipped defaults), the deputy and owner roles only by an Owner
//! (HOUSE-UNBIND-AUTHORITY = A), and the vault's own owner holds every
//! assignment. The bind checks it in its own write, and so
//! does the unbind; an Admin's assignment also stands on the MFA step-up
//! its request shows (L7-17). [`Vault::set_house_role`] and
//! [`Vault::clear_house_role`] set and clear the role alone, under the same
//! rule; neither touches the root's leader, which only the owner's bind and
//! unbind sign.
//!
//! Each bind and each unbind keeps one receipt (`IdentityLifecycle`) that
//! names the binder, the house, the org and the role. The receipts are the
//! bind intervals a byline reads: a statement the house wrote inside one is
//! the house's for that org, and an unbind changes no statement written
//! before it.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::WorkspaceRosterPreset;
use super::records::PRESET;
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error, Result};
use crate::federation::{
    FederationGrant, FederationGrantRole, FederationGrantScope, OrgAdminPower, OrgAdminStepUp,
    OrgAdminWriter, SharedVaultWrite, encode_federation_grant_body,
};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_FEDERATION_GRANT};
use crate::scan_check::ScanCount;
use crate::side_table::{self, Named, SideTable};
use crate::store::EngineScan;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

const RECEIPT_VERSION: u8 = 1;

/// One house link receipt. Key: id16 (house) + id16 (receipt, time ordered).
const RECEIPTS: SideTable<(EntityId, EntityId), HouseLinkReceipt, Named> =
    SideTable::new(&side_table::HOUSE_LINK_RECEIPT);

/// What one receipt records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HouseLinkAct {
    /// The house took its role in the org.
    Bind,
    /// The house left it.
    Unbind,
}

impl HouseLinkAct {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        }
    }
}

/// One bind or unbind of a house's org link, kept for the receipt read and
/// the byline's bind intervals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HouseLinkReceipt {
    pub(crate) version: u8,
    pub(crate) act: HouseLinkAct,
    /// The write's recorded time.
    pub(crate) at: u64,
    /// The owner who bound or unbound the house.
    pub(crate) binder: EntityId,
    pub(crate) house: EntityId,
    pub(crate) org: EntityId,
    pub(crate) role: FederationGrantRole,
    pub(crate) workspace_ref: String,
    pub(crate) workspace_vault_id: u64,
    /// The FEDERATION_GRANT the bind wrote or the unbind removed.
    pub(crate) grant: EntityId,
}

/// The role a house runs its org in when its binder names none: deputy, an
/// Admin's powers that check in with the Owner on owner acts (DEPUTY = A,
/// the owner, 10 Nov 07:45; HOUSE-ROLE-DEPUTY-AFTER-7071 = A). Only an
/// Owner assigns it ([`assignment_write`]).
pub const DEFAULT_HOUSE_ROLE: FederationGrantRole = FederationGrantRole::Deputy;

/// The roles a house may run its org in: member up to owner, deputy among
/// them. Viewer, delegate and guest are no org role for a house.
fn require_house_role(role: FederationGrantRole) -> Result<()> {
    if matches!(
        role,
        FederationGrantRole::Owner
            | FederationGrantRole::Deputy
            | FederationGrantRole::Admin
            | FederationGrantRole::Steward
            | FederationGrantRole::Member
    ) {
        return Ok(());
    }
    Err(Error::InvalidConfig(
        "a house runs its org as a member, steward, admin, deputy or owner".into(),
    ))
}

/// The role a house runs its org in, from its pinned spelling: `member`,
/// `steward`, `admin`, `deputy` or `owner`. `None` for any other role or
/// spelling.
#[must_use]
pub fn parse_house_role(value: &str) -> Option<FederationGrantRole> {
    FederationGrantRole::parse(value).filter(|role| require_house_role(*role).is_ok())
}

/// The refusal of an Owner link over the own-device residence vault.
const OWNER_OVER_OWN_DEVICE_REFUSAL: &str = "an Owner house link over the own-device residence vault (7) would read as device access; refused until FIX row OWN-DEVICE-GRANT-PURPOSE-MARKER lands";

/// The refusal of a house link change on a vault whose sharing was deleted.
const DELETED_VAULT_REFUSAL: &str = "a deleted shared vault takes no house link change";

/// Refuses a house link change once this vault's sharing was deleted, as the
/// membership gate refuses every write then. A vault never shared has no
/// deletion and passes, so a house may still be bound before sharing.
fn require_undeleted_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
    if vault.shared_vault_deletion_in_txn(txn)?.is_some() {
        return Err(Error::InvalidConfig(DELETED_VAULT_REFUSAL.into()));
    }
    Ok(())
}

/// The refusal of a set or clear by someone the role table does not let
/// assign that role.
const ROLE_ASSIGNER_REFUSAL: &str = "a house's role is set or cleared only by whoever may assign that role: org:assign-role, or an Owner for the steward, deputy or owner role";

/// What the role table asks of whoever assigns `role` (ARCH-0043), as the
/// membership acts ask it: a member or admin role is the `org:assign-role`
/// power's (`change_shared_member_role`), the steward, deputy and owner
/// roles the org root's, an Owner's. An assigner never grants a power it
/// lacks, so an Admin assigns up to Admin; Steward is a named grant preset
/// that only the vault's owner gives (ARCH-0043: an Admin "cannot self-grant
/// blanket access"; lead 10 Nov 06:5x); a deputy is the Owner's delegate
/// (ARCH-0082 #roles). So only an Owner seats a house at steward or deputy
/// (HOUSE-UNBIND-AUTHORITY = A; HOUSE-ROLE-DEPUTY-AFTER-7071 = A, Engine
/// 12 Nov 09:36), and only an Owner moves or clears it from there.
fn assignment_write(role: FederationGrantRole) -> SharedVaultWrite {
    if matches!(
        role,
        FederationGrantRole::Owner | FederationGrantRole::Deputy | FederationGrantRole::Steward
    ) {
        SharedVaultWrite::OrgRoot
    } else {
        SharedVaultWrite::Admin(OrgAdminPower::AssignRole)
    }
}

/// `actor` may set or clear `role` on a house seated in shared vault
/// `vault_id`, in `txn`: this vault's live owner holds every assignment, and
/// anyone else needs the role table's power over that vault, and an
/// Admin's power the step-up `step_up` shows (L7-17). An actor with no live
/// authority binding keeps that refusal; one without the power gets
/// [`ROLE_ASSIGNER_REFUSAL`]; an Admin with no standing step-up gets
/// [`crate::federation::ORG_ADMIN_STEP_UP_REQUIRED`].
fn require_role_assigner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_id: u64,
    actor: EntityId,
    step_up: &OrgAdminStepUp,
    role: FederationGrantRole,
) -> Result<()> {
    if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &actor)? {
        return Ok(());
    }
    let writer = WriteActor::new(actor, EdgeActorClass::Human);
    vault.verify_write_actor_in_txn(txn, &writer).map(drop)?;
    match assignment_write(role) {
        SharedVaultWrite::Admin(power) => vault.authorize_org_admin_act_in_txn(
            txn,
            vault_id,
            &OrgAdminWriter::showing(writer, step_up.clone()),
            power,
        ),
        root => vault.authorize_shared_vault_write_in_txn(txn, vault_id, &writer, &root),
    }
    .map_err(|error| match error {
        Error::Claim(ClaimError::ActorLacksClaimAuthority { .. }) => {
            Error::Claim(ClaimError::ActorLacksClaimAuthority {
                reason: ROLE_ASSIGNER_REFUSAL,
            })
        }
        other => other,
    })
}

/// The live membership grants that seat `house` in shared vault `vault_id`,
/// in id order.
fn house_grants_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    house: EntityId,
    vault_id: u64,
) -> Result<Vec<(EntityId, FederationGrant)>> {
    Ok(vault
        .vault_grants_in_txn(txn, vault_id)?
        .into_iter()
        .filter(|(_, grant)| {
            grant.member_ref == house && grant.role != FederationGrantRole::Delegate
        })
        .collect())
}

/// The stored presets that name `house` as their house mind.
fn presets_naming_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    house: EntityId,
) -> Result<Vec<WorkspaceRosterPreset>> {
    Ok(PRESET
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, row)| row.preset)
        .filter(|preset| preset.house_actor_ref == house)
        .collect())
}

/// Each stored preset naming `house` whose shared vault seats it through a
/// live grant: the orgs the house runs now, with its role in each.
pub(crate) fn house_links_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    house: EntityId,
) -> Result<Vec<(WorkspaceRosterPreset, FederationGrantRole)>> {
    let mut links = Vec::new();
    for preset in presets_naming_in_txn(vault, txn, house)? {
        if let Some((_, grant)) = house_grants_in_txn(vault, txn, house, preset.workspace_vault_id)?
            .into_iter()
            .next()
        {
            links.push((preset, grant.role));
        }
    }
    Ok(links)
}

/// Whether `grant` is a house mind's org link: its member an AGENT_DEF that a
/// stored preset names as its house, over that preset's shared vault. Such a
/// grant is no person's membership.
pub(crate) fn is_house_link_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: &FederationGrant,
) -> Result<bool> {
    if vault.get_entity_type_in_txn(txn, &grant.member_ref)? != Some(ENTITY_TYPE_AGENT_DEF) {
        return Ok(false);
    }
    Ok(presets_naming_in_txn(vault, txn, grant.member_ref)?
        .iter()
        .any(|preset| grant.scope == FederationGrantScope::vault(preset.workspace_vault_id)))
}

/// The links `house` held at `at`, read from its receipts alone, oldest bind
/// first: for each grant, its latest bind at or before `at`, unless an
/// unbind of that grant at or before `at` came after it. Times are the
/// vault's recorded seconds, so an act and a write in the same second read in
/// receipt order, the act's receipt last.
fn open_links_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    house: EntityId,
    at: u64,
) -> Result<Vec<HouseLinkReceipt>> {
    let mut open: BTreeMap<EntityId, (usize, HouseLinkReceipt)> = BTreeMap::new();
    for (index, (_, receipt)) in RECEIPTS
        .scan_from(&vault.store, txn, house.as_bytes())?
        .into_iter()
        .enumerate()
    {
        if receipt.at > at {
            break;
        }
        match receipt.act {
            HouseLinkAct::Bind => {
                open.insert(receipt.grant, (index, receipt));
            }
            HouseLinkAct::Unbind => {
                open.remove(&receipt.grant);
            }
        }
    }
    let mut links: Vec<(usize, HouseLinkReceipt)> = open.into_values().collect();
    links.sort_by_key(|(index, _)| *index);
    Ok(links.into_iter().map(|(_, receipt)| receipt).collect())
}

fn apply_grant_ops_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ops: Vec<BatchOp>,
) -> Result<()> {
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        ops,
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )
}

fn append_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &HouseLinkReceipt,
) -> Result<()> {
    let id = vault.store.clock.entity_id()?;
    RECEIPTS.put(&vault.store, txn, &(receipt.house, id), receipt)
}

/// Seats `preset`'s house in its workspace's shared vault at `role`, in the
/// caller's transaction, and keeps the bind receipt naming `binder`. A grant
/// the house already holds there is rewritten in place at the new role; a
/// house already seated at exactly `role` is left as it is, with no second
/// receipt. `binder` must be able to assign `role`, and every role the house
/// holds there now, by the role table, an Admin on the step-up `step_up`
/// shows.
pub(crate) fn link_house_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    preset: &WorkspaceRosterPreset,
    role: FederationGrantRole,
    binder: EntityId,
    step_up: &OrgAdminStepUp,
    now: u64,
) -> Result<()> {
    require_house_role(role)?;
    let house = preset.house_actor_ref;
    let vault_id = preset.workspace_vault_id;
    // `federation::is_own_device_grant` reads a grant's shape alone, and an
    // Owner grant over the own-device residence vault has that shape, so no
    // house holds one until own-device grants carry their own mark (FIX row
    // OWN-DEVICE-GRANT-PURPOSE-MARKER). Every house grant the engine's own
    // doors write is written here; a row a trusted replay or restore carries
    // is that FIX row's case, as it is for a person's grant.
    if role == FederationGrantRole::Owner
        && FederationGrantScope::vault(vault_id) == crate::federation::own_device_residence_scope()
    {
        return Err(Error::InvalidConfig(OWNER_OVER_OWN_DEVICE_REFUSAL.into()));
    }
    require_undeleted_in_txn(vault, txn)?;
    let held = house_grants_in_txn(vault, txn, house, vault_id)?;
    require_role_assigner_in_txn(vault, txn, vault_id, binder, step_up, role)?;
    for (_, grant) in &held {
        require_role_assigner_in_txn(vault, txn, vault_id, binder, step_up, grant.role)?;
    }
    // The same link is a retry: the grant at `role` and its open bind
    // receipt for this workspace. A grant another workspace's bind opened, or
    // one with no receipt here (a peer's), takes this bind's receipt.
    let open = open_links_at_in_txn(vault, txn, house, u64::MAX)?;
    let linked_here = |id: &EntityId| {
        open.iter().any(|link| {
            link.grant == *id && link.workspace_ref == preset.workspace_ref && link.role == role
        })
    };
    if !held.is_empty()
        && held
            .iter()
            .all(|(id, grant)| grant.role == role && linked_here(id))
    {
        return Ok(());
    }
    let mut ids: Vec<EntityId> = held.into_iter().map(|(id, _)| id).collect();
    if ids.is_empty() {
        ids.push(vault.store.clock.entity_id()?);
    }
    let mut grant = FederationGrant::new(
        FederationGrantScope::vault(vault_id),
        house,
        role,
        crate::federation::role_preset(role)?,
    );
    grant.authority_scope = vault.grant_default_scope_in_txn(txn, role, vault_id, house)?;
    grant.validate()?;
    let data = encode_federation_grant_body(&grant)?;
    let ops = ids
        .iter()
        .map(|id| BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: None,
            data: data.clone(),
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        })
        .collect();
    apply_grant_ops_in_txn(vault, txn, ops)?;
    // One bind receipt per grant written, as the unlink keeps one unbind per
    // grant removed, so the next same bind finds every grant linked here.
    for id in ids {
        append_receipt_in_txn(
            vault,
            txn,
            &HouseLinkReceipt {
                version: RECEIPT_VERSION,
                act: HouseLinkAct::Bind,
                at: now,
                binder,
                house,
                org: preset.org_ref,
                role,
                workspace_ref: preset.workspace_ref.clone(),
                workspace_vault_id: vault_id,
                grant: id,
            },
        )?;
    }
    Ok(())
}

/// Removes the live grants that seat `preset`'s house in its workspace's
/// shared vault, in the caller's transaction, each withdrawal known here and
/// to the vault's peers, and keeps one unbind receipt per removed grant,
/// naming `binder`, who must be able to assign each removed role by the role
/// table, an Admin on the step-up `step_up` shows. Whether any grant went.
fn unlink_preset_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    preset: &WorkspaceRosterPreset,
    binder: EntityId,
    step_up: &OrgAdminStepUp,
    now: u64,
) -> Result<bool> {
    let house = preset.house_actor_ref;
    let vault_id = preset.workspace_vault_id;
    let held = house_grants_in_txn(vault, txn, house, vault_id)?;
    if !held.is_empty() {
        require_undeleted_in_txn(vault, txn)?;
    }
    for (_, grant) in &held {
        require_role_assigner_in_txn(vault, txn, vault_id, binder, step_up, grant.role)?;
    }
    let open = open_links_at_in_txn(vault, txn, house, u64::MAX)?;
    for (id, grant) in &held {
        // The unbind names the org and workspace its grant's bind named; a
        // grant with no bind receipt here (a peer's) names this preset's.
        let (org, workspace_ref) = open.iter().find(|link| link.grant == *id).map_or_else(
            || (preset.org_ref, preset.workspace_ref.clone()),
            |link| (link.org, link.workspace_ref.clone()),
        );
        crate::authority::withdraw_grant_row_in_txn(&vault.store, txn, *id)?;
        apply_grant_ops_in_txn(vault, txn, vec![BatchOp::Delete { id: *id }])?;
        append_receipt_in_txn(
            vault,
            txn,
            &HouseLinkReceipt {
                version: RECEIPT_VERSION,
                act: HouseLinkAct::Unbind,
                at: now,
                binder,
                house,
                org,
                role: grant.role,
                workspace_ref,
                workspace_vault_id: vault_id,
                grant: *id,
            },
        )?;
    }
    Ok(!held.is_empty())
}

/// [`unlink_preset_in_txn`] over every stored preset naming `house`, one per
/// shared vault. Whether any grant went.
pub(crate) fn unlink_house_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    house: EntityId,
    binder: EntityId,
    step_up: &OrgAdminStepUp,
    now: u64,
) -> Result<bool> {
    let mut seen = BTreeSet::new();
    let mut removed = false;
    for preset in presets_naming_in_txn(vault, txn, house)? {
        if seen.insert(preset.workspace_vault_id) {
            removed |= unlink_preset_in_txn(vault, txn, &preset, binder, step_up, now)?;
        }
    }
    Ok(removed)
}

/// `workspace_ref`'s stored preset, read in `txn`, its house an AGENT_DEF.
fn stored_preset_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    workspace_ref: &str,
) -> Result<WorkspaceRosterPreset> {
    let preset = PRESET
        .get(&vault.store, txn, &workspace_ref.to_owned())?
        .map(|row| row.preset)
        .ok_or(Error::EntityNotFound)?;
    if vault.get_entity_type_in_txn(txn, &preset.house_actor_ref)? != Some(ENTITY_TYPE_AGENT_DEF) {
        return Err(Error::InvalidConfig(
            "a workspace's house mind is an AGENT_DEF".into(),
        ));
    }
    Ok(preset)
}

impl Vault {
    /// Sets the role `workspace_ref`'s house mind runs its org in, as the
    /// bind does, and nothing else: the root's leader, which only the
    /// owner's bind and unbind sign, stays as it is. One grant at `role`,
    /// rewritten in place if the house holds another, and one bind receipt
    /// naming `actor`. `actor` must be able to assign `role`, and the role it
    /// replaces, by the role table: `org:assign-role` for member, steward or
    /// admin, an Owner for deputy or owner; the vault's owner may assign
    /// any. The house
    /// already at `role` is left as it is, with no receipt. No stored preset
    /// is `EntityNotFound`.
    pub fn set_house_role(
        &self,
        actor: &AuthenticatedOwner,
        workspace_ref: &str,
        role: FederationGrantRole,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            let step_up = actor.org_admin_step_up();
            let actor = actor.revalidate_person_in_txn(self, txn)?;
            let preset = stored_preset_in_txn(self, txn, workspace_ref)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            link_house_in_txn(self, txn, &preset, role, actor, &step_up, now)
        })
    }

    /// Clears the role `workspace_ref`'s house mind runs its org in: its
    /// grant goes, with one unbind receipt naming `actor`, and the root's
    /// leader stays as it is. `actor` must be able to assign the role it
    /// clears, by the role table, as [`Self::set_house_role`] asks; a refusal
    /// writes nothing. `Ok(false)`, writing nothing, when the house holds no
    /// role there.
    pub fn clear_house_role(
        &self,
        actor: &AuthenticatedOwner,
        workspace_ref: &str,
    ) -> Result<bool> {
        self.with_write_txn(|txn| {
            let step_up = actor.org_admin_step_up();
            let actor = actor.revalidate_person_in_txn(self, txn)?;
            let preset = stored_preset_in_txn(self, txn, workspace_ref)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            unlink_preset_in_txn(self, txn, &preset, actor, &step_up, now)
        })
    }
}

/// The workspaces one live grant of `house` over `vault_id` links it to:
/// the workspace its open bind receipt names (`open`), or, for a grant with
/// no bind receipt here (a peer's), every stored preset naming the house over
/// that vault.
fn grant_workspaces<'p>(
    presets: &'p [WorkspaceRosterPreset],
    open: &[HouseLinkReceipt],
    house: EntityId,
    vault_id: u64,
    grant: EntityId,
) -> Vec<&'p WorkspaceRosterPreset> {
    match open.iter().find(|link| link.grant == grant) {
        Some(link) => presets
            .iter()
            .filter(|preset| preset.workspace_ref == link.workspace_ref)
            .collect(),
        None => presets
            .iter()
            .filter(|preset| {
                preset.house_actor_ref == house && preset.workspace_vault_id == vault_id
            })
            .collect(),
    }
}

/// The role each house that runs an org reads on its PEOPLE row (ARCH-0067:
/// the house mind, an agent, the root's leader), while its link is live at
/// the board's read: for each live grant, the bind interval its receipts
/// hold open ([`open_links_at_in_txn`]) names the workspace, and the row reads
/// `runs <org> as <role>`, the org named by that workspace's venture name. A
/// house that runs none has no line.
pub(crate) fn house_role_lines_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, String>> {
    let presets: Vec<WorkspaceRosterPreset> = PRESET
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, row)| row.preset)
        .collect();
    let mut seats: BTreeMap<EntityId, BTreeSet<u64>> = BTreeMap::new();
    for preset in &presets {
        seats
            .entry(preset.house_actor_ref)
            .or_default()
            .insert(preset.workspace_vault_id);
    }
    let mut lines = BTreeMap::new();
    for (house, vault_ids) in seats {
        let open = open_links_at_in_txn(vault, txn, house, u64::MAX)?;
        let mut runs = Vec::new();
        for vault_id in vault_ids {
            for (id, grant) in house_grants_in_txn(vault, txn, house, vault_id)? {
                for preset in grant_workspaces(&presets, &open, house, vault_id, id) {
                    runs.push(format!(
                        "runs {} as {}",
                        preset.venture_name,
                        grant.role.as_str()
                    ));
                }
            }
        }
        if !runs.is_empty() {
            lines.insert(house, runs.join("; "));
        }
    }
    Ok(lines)
}

/// Erasing `actor` from the house link receipts (FIX 3520): every receipt
/// that names it as the binder, the house or the org goes, in the erase's own
/// transaction, so no receipt read or bind interval names it again. The
/// table names an ORG, which is no actor, so every erase scans it.
pub(crate) fn erase_house_link_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let doomed: Vec<(EntityId, EntityId)> = RECEIPTS
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, row)| row.binder == *actor || row.house == *actor || row.org == *actor)
        .map(|(key, _)| key)
        .collect();
    for key in &doomed {
        RECEIPTS.delete(&vault.store, wtxn, key)?;
    }
    Ok(())
}

/// The org `house` ran at `at`, read from its receipts alone: the org of the
/// latest bind still open at `at` ([`open_links_at_in_txn`]). Nothing about a
/// statement is stored for this, so an unbind never changes how a statement
/// written before it reads. A statement's byline reads it at the statement's
/// write time (FIX row SPEAKER-BYLINE-FOR-ORG). Times are recorded seconds: a
/// statement written in the second of a bind or an unbind reads as after it.
#[cfg_attr(not(oneiron_test_support), allow(dead_code))]
pub(crate) fn house_org_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    house: EntityId,
    at: u64,
) -> Result<Option<EntityId>> {
    Ok(open_links_at_in_txn(vault, txn, house, at)?
        .last()
        .map(|link| link.org))
}

/// The house link receipts the query admits, as `IdentityLifecycle`
/// receipts: actor the binder, trigger the house, outcome `bind` or
/// `unbind`, and the org, role, workspace and grant in its fields.
pub(crate) fn house_link_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let txn = vault.store.env.read_txn()?;
    let mut count = ScanCount::start(
        &vault.store,
        &txn,
        EngineScan::ReceiptSourceRows,
        b"house_link_receipt",
    )?;
    let rows = RECEIPTS.scan(&vault.store, &txn)?;
    count.rows(rows.len());
    count.finish(vault);
    let mut receipts = Vec::new();
    for ((house, id), row) in rows {
        let fields = BTreeMap::from([
            ("binder".to_owned(), row.binder.to_hex()),
            ("house".to_owned(), house.to_hex()),
            ("org".to_owned(), row.org.to_hex()),
            ("role".to_owned(), row.role.as_str().to_owned()),
            ("workspace_ref".to_owned(), row.workspace_ref.clone()),
            (
                "workspace_vault_id".to_owned(),
                row.workspace_vault_id.to_string(),
            ),
            ("grant".to_owned(), row.grant.to_hex()),
            ("receipt_version".to_owned(), row.version.to_string()),
        ]);
        let receipt = ReceiptRecord {
            receipt_id: format!("house_link:{}", id.to_hex()),
            receipt_kind: ReceiptKind::IdentityLifecycle,
            occurred_at: row.at,
            actor: Some(row.binder.to_hex()),
            on_behalf_of: None,
            outcome: row.act.as_str().to_owned(),
            job_ref: None,
            trigger_ref: Some(format!("entity:{}", house.to_hex())),
            policy_trace: Vec::new(),
            fields,
        };
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}
