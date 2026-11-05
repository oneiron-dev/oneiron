//! Historical carrier origin for native SKILL facts, never owner permission.

use super::*;

/// Origin coordinates of a separately authenticated native SKILL fact.
/// These coordinates do not prove its signature or its native admission.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NativeSkillCarrier {
    pub(crate) heads: BTreeSet<AuthorityEntryHash>,
    pub(crate) machine: EntityId,
    pub(crate) key: [u8; 32],
    pub(crate) token: AuthorityEntryHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeSkillOrigin {
    Stands,
    Pending,
    Refused,
}

/// Read each carrier at its actual signed heads, then its removal race here.
/// Unlike an owner act, native engine provenance asserts no person's will.
/// The caller must separately verify the closed native fact and its source.
pub(crate) fn native_skill_origins_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    carriers: &BTreeSet<NativeSkillCarrier>,
    fold: &AuthorityFold,
) -> Result<BTreeMap<NativeSkillCarrier, NativeSkillOrigin>> {
    let mut origins: BTreeMap<_, _> = carriers
        .iter()
        .cloned()
        .map(|carrier| (carrier, NativeSkillOrigin::Pending))
        .collect();
    if carriers.is_empty() {
        return Ok(origins);
    }
    let pin = super::super::pinned_root::read_pinned_root_in_txn(store, txn)?;
    let heads = carriers
        .iter()
        .flat_map(|carrier| carrier.heads.iter().copied())
        .collect();
    let Some((
        ImageFold {
            per_parent, merged, ..
        },
        parents,
    )) = capture_in_txn(store, txn, &heads, pin.as_ref())?
    else {
        return Ok(origins);
    };
    let counted =
        |machine: EntityId, admitter: MachineAdmitter| install_hold(fold, machine, admitter);
    let now = Standing::new(&merged, pin.as_ref(), &counted);
    // Carriers sort by heads first, so each parent state is reconstructed once.
    let mut parent: Option<(&BTreeSet<AuthorityEntryHash>, Option<FoldState>)> = None;
    for carrier in carriers {
        if parent
            .as_ref()
            .is_none_or(|(heads, _)| *heads != &carrier.heads)
        {
            parent = Some((
                &carrier.heads,
                parent_state(&per_parent, &parents, &carrier.heads),
            ));
        }
        let Some((_, Some(state))) = &parent else {
            continue;
        };
        let at = Standing::new(state, pin.as_ref(), &every_chain);
        let roster = StandingView::Under(MachineAdmitter::Roster);
        let origin = if !at.admits_owner_act_signer(carrier.machine, &carrier.key, roster) {
            NativeSkillOrigin::Refused
        } else {
            let marks =
                at.live_signing_chains(carrier.machine, &AuthorityKey::Ed25519(carrier.key));
            if now.owner_act_race(
                carrier.machine,
                &carrier.token,
                &carrier.key,
                &marks,
                StandingView::Install,
            ) {
                NativeSkillOrigin::Stands
            } else {
                NativeSkillOrigin::Refused
            }
        };
        origins.insert(carrier.clone(), origin);
    }
    Ok(origins)
}
