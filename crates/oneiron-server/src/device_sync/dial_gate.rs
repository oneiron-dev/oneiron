//! The dial gate ([`standing`]): whether this install may dial its home, read
//! from the heads each machine stands under on this install.

/// This install's MACHINE, when it may dial `home`, and whether `home` has a
/// paired mesh address. It may when it is enrolled and live, and `home` is a
/// live machine; an elected MACRO home dials its home as any device does. A
/// machine `oneiron device enrol` added (`enrolled`) is enrolled at the home:
/// its own profile, and the home's, reach this vault on the first authority
/// catch-up. A profile the owner has not answered yet (an unanswered serving
/// install's own) counts here as no profile, so it dials and is dialled as
/// before it had one (selfprofile). Both read the heads a machine stands
/// under on this install, the roster's and its pinned anchor's
/// ([`oneiron::authority::FoldedMachine::standing_heads`]): another anchor's
/// chain, which any fresh root can write, neither enrols nor keeps a removed
/// machine live here (FIX FOREIGN-ANCHOR-CHAIN-COUNTS-IN-EVERY-CHAIN-PREDICATES).
pub(crate) fn standing(
    vault: &oneiron::Vault,
    home: oneiron::EntityId,
    enrolled: bool,
) -> anyhow::Result<(oneiron::EntityId, bool)> {
    let fold = vault.authority_fold()?;
    let pin = fold.pinned_root.as_ref();
    let live = |machine: &oneiron::authority::FoldedMachine| {
        machine
            .standing_heads(pin)
            .iter()
            .any(|chain| chain.is_live())
    };
    let answered = |machine: &&oneiron::authority::FoldedMachine| {
        machine
            .standing_heads(pin)
            .iter()
            .any(|chain| chain.profile.role.answered())
    };
    // A head this install believes that says removed vetoes the machine
    // before any live head or the enrolment fallback counts, as the carrier
    // rule reads them (#8722 review round 2, P1).
    let removed = |machine: &oneiron::authority::FoldedMachine| {
        machine
            .standing_heads(pin)
            .iter()
            .any(|chain| chain.removed)
    };
    let local = vault
        .local_machine()?
        .ok_or_else(|| anyhow::anyhow!("this install is not a machine yet"))?;
    anyhow::ensure!(
        !local.profile.as_ref().is_some_and(removed),
        "this machine is not enrolled live in the vault"
    );
    match local.profile.as_ref().filter(answered) {
        Some(profile) => anyhow::ensure!(
            live(profile),
            "this machine is not enrolled live in the vault"
        ),
        None => anyhow::ensure!(
            enrolled,
            "this machine is not enrolled in the vault; `oneiron device enrol` enrols it"
        ),
    }
    anyhow::ensure!(local.id != home, "home_machine names this machine");
    anyhow::ensure!(
        !fold.machine(home).is_some_and(removed),
        "home_machine {} is not a live machine",
        home.to_hex()
    );
    match fold.machine(home).filter(answered) {
        Some(machine) => anyhow::ensure!(
            live(machine),
            "home_machine {} is not a live machine",
            home.to_hex()
        ),
        None => anyhow::ensure!(
            enrolled,
            "home_machine {} is not a machine of this vault",
            home.to_hex()
        ),
    }
    Ok((local.id, vault.mesh_machine(home)?.is_some()))
}
