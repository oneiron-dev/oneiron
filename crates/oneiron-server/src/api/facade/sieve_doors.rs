//! The owner's sieve doors: the interest queue and its retained spans,
//! consumed-span receipts, the sieve and recipe policy rows, and the
//! wake-budget lease refill. The engine owns the queue, the policies and
//! the counter; each door rechecks the owner's proof.
use std::sync::Arc;

use oneiron::dreamer_wake::sieve_doors::{self, *};
use oneiron::dreamer_wake::{SievePolicy, WakeRecipePolicy};
use oneiron::memory::MemoryError;

use super::host_doors::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_sieve_queue(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SievePageRequest,
) -> Listed<SieveQueuePage> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.queue",
        move |server, owner| {
            sieve_doors::sieve_queue_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_sieve_retained(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SievePageRequest,
) -> Listed<SieveRetainedPage> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.retained",
        move |server, owner| {
            sieve_doors::sieve_retained_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_sieve_receipts(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SievePageRequest,
) -> Listed<SieveReceiptsPage> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.receipts",
        move |server, owner| {
            sieve_doors::sieve_receipts_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_sieve_policy(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SievePolicyRequest,
) -> Listed<SievePolicy> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.policy",
        move |server, owner| {
            sieve_doors::sieve_policy_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_sieve_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SievePolicySetRequest,
) -> Listed<SievePolicy> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.policy.set",
        move |server, owner| {
            sieve_doors::sieve_policy_set_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_sieve_recipe_policy(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SievePolicyRequest,
) -> Listed<WakeRecipePolicy> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.recipe_policy",
        move |server, owner| {
            sieve_doors::sieve_recipe_policy_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_sieve_recipe_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SieveRecipePolicySetRequest,
) -> Listed<WakeRecipePolicy> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.recipe_policy.set",
        move |server, owner| {
            sieve_doors::sieve_recipe_policy_set_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_sieve_lease(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SieveLeaseRequest,
) -> Listed<SieveLeaseView> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.lease",
        move |server, owner| {
            sieve_doors::sieve_lease_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_sieve_lease_refill(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SieveLeaseRefillRequest,
) -> Listed<SieveLeaseView> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.lease.refill",
        move |server, owner| {
            sieve_doors::sieve_lease_refill_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}
