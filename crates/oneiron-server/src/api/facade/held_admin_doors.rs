//! The host doors of the org two-admin rule's rows (UNBUILT-06 PR 2): the
//! admin acts a shared vault's rule holds (`vault.members.held`), a second
//! admin's approve, which re-runs the held verb under their own proof with
//! the host's slip issuer (`vault.members.held.approve`), and the first
//! admin's withdraw (`vault.members.held.withdraw`), each under the caller's
//! own shared person proof as the other `vault.members.*` doors take it.
//! `host_doors` re-exports them. Each engine door checks the caller again in
//! its own writer.
use std::sync::Arc;

use oneiron::federation::{HeldAdminAct, SharedActExecutionReceipt};
use oneiron::task_verb::sdk::{
    self, HeldAdminActApproved, HeldAdminActRequest, SharedVaultRequest,
};

use super::host_doors::support::MaybeListed;
use super::shared_act_doors::{as_person_naming, person, receipt_rows, with_slips};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.members.held`: the held acts a live admin may see; they live in a
/// side table, so it lists no row.
pub(crate) async fn vault_members_held(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SharedVaultRequest,
) -> MaybeListed<Vec<HeldAdminAct>> {
    const VERB: &str = "vault.members.held";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, reader| sdk::read_held_admin_acts(server.vault(), &reader, input),
        |_| Some(Vec::new()),
    )
    .await
}

/// `vault.members.held.approve`: a second admin approves a held act, whose
/// verb runs again under their proof with the host's slip issuer, listing
/// the rows a membership receipt it answers with names.
pub(crate) async fn vault_members_held_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HeldAdminActRequest,
) -> MaybeListed<HeldAdminActApproved> {
    const VERB: &str = "vault.members.held.approve";
    let vault = Arc::clone(server);
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, approver| {
            with_slips(server, VERB, |slips| {
                sdk::approve_held_admin_act_as(server.vault(), &approver, Some(slips), input)
            })
        },
        move |approved| {
            serde_json::from_value::<SharedActExecutionReceipt>(approved.output.clone())
                .map_or_else(
                    |_| Some(Vec::new()),
                    |receipt| receipt_rows(vault.vault(), &receipt),
                )
        },
    )
    .await
}

/// `vault.members.held.withdraw`: the first admin takes a held act back; no
/// membership changes, so it lists no row.
pub(crate) async fn vault_members_held_withdraw(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HeldAdminActRequest,
) -> MaybeListed<HeldAdminAct> {
    const VERB: &str = "vault.members.held.withdraw";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, first_admin| {
            sdk::withdraw_held_admin_act_as(server.vault(), &first_admin, input)
        },
        |_| Some(Vec::new()),
    )
    .await
}
