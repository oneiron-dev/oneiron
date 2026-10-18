//! One credential-backed CHECKOUT door for HTTP, MCP and the generated SDK.
use super::host_doors::{Listed, credential_listing};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::checkout::lease::{
    CheckoutError, CheckoutId, CheckoutLiveness, CheckoutLivenessPulse, CheckoutResult,
};
use oneiron::memory::checkout_doors::*;
use oneiron::memory::{Memory, MemoryResult};
use oneiron::sync::{EphemeralStore, LoroValue};
use std::sync::Arc;

struct CheckoutPresence<'a>(&'a SyncServer);
impl CheckoutPresence<'_> {
    fn key(id: CheckoutId) -> String {
        format!("checkout:{id}")
    }

    fn emit(&self, key: &str, value: Option<LoroValue>) -> CheckoutResult<()> {
        let server = self.0;
        let mut charge = server.presence.lock();
        charge.expire(&server.ephemeral_store);
        let scratch = EphemeralStore::new(server.config.ephemeral_timeout_ms);
        scratch
            .apply(&server.ephemeral_store.encode_all())
            .map_err(|_| CheckoutError::Invalid("checkout presence snapshot"))?;
        match value {
            Some(value) => {
                scratch.set(key, value);
            }
            None => {
                scratch.delete(key);
            }
        };
        let payload = scratch.encode(key);
        if payload.len() > server.config.max_ephemeral_payload_bytes
            || !charge.fit(scratch.encode_all().len())
        {
            return Err(CheckoutError::RepoOps(
                "checkout presence memory line is full".into(),
            ));
        }
        server
            .ephemeral_store
            .apply(&payload)
            .map_err(|_| CheckoutError::Invalid("checkout presence frame"))?;
        drop(charge);
        let frame = oneiron::sync::encode_ephemeral(&server.ephemeral_store.encode(key))
            .into_result()
            .map_err(|_| CheckoutError::Invalid("checkout presence frame"))?;
        let _ = crate::broadcast::broadcast(&server.broadcast_tx, 0, frame);
        Ok(())
    }
}
impl CheckoutLiveness for CheckoutPresence<'_> {
    fn publish(&mut self, pulse: CheckoutLivenessPulse) -> CheckoutResult<()> {
        let text = serde_json::to_string(&(pulse.epoch, pulse.holder_ref, pulse.observed_at))
            .map_err(|_| CheckoutError::Invalid("checkout presence encoding"))?;
        self.emit(
            &Self::key(pulse.checkout_id),
            Some(LoroValue::String(text.into())),
        )
    }
    fn current(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        self.0.presence.lock().expire(&self.0.ephemeral_store);
        let Some(value) = self.0.ephemeral_store.get(&Self::key(id)) else {
            return Ok(None);
        };
        let LoroValue::String(text) = value else {
            return Err(CheckoutError::Invalid("checkout presence value"));
        };
        let (epoch, holder_ref, observed_at): (u64, String, u64) =
            serde_json::from_str(text.as_ref())
                .map_err(|_| CheckoutError::Invalid("checkout presence value"))?;
        Ok(Some(CheckoutLivenessPulse {
            checkout_id: id,
            epoch,
            holder_ref,
            observed_at,
        }))
    }
    fn clear(&mut self, id: CheckoutId, epoch: u64) -> CheckoutResult<()> {
        if self.current(id)?.is_some_and(|pulse| pulse.epoch == epoch) {
            self.emit(&Self::key(id), None)?;
        }
        Ok(())
    }
}

async fn as_caller<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    call: impl FnOnce(&SyncServer, Memory<'_>) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let caller = match super::facade_actor(server, auth) {
        Ok(caller) => caller,
        Err(error) => return (Err(error.into_memory_error()), Vec::new()),
    };
    credential_listing(server, auth, caller, verb, move |server, _, memory| {
        call(server, memory)
    })
    .await
}

pub(crate) async fn vault_code_checkout_claim(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutClaimInput,
) -> Listed<CheckoutLeaseView> {
    as_caller(
        server,
        auth,
        "vault.code.checkout.claim",
        move |server, memory| memory.checkout_claim_through(input, &mut CheckoutPresence(server)),
    )
    .await
}

pub(crate) async fn vault_code_checkout_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutGetInput,
) -> Listed<CheckoutLeaseView> {
    as_caller(server, auth, "vault.code.checkout.get", move |_, memory| {
        memory.checkout_get(input)
    })
    .await
}

pub(crate) async fn vault_code_checkout_renew(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutRenewInput,
) -> Listed<CheckoutLeaseView> {
    as_caller(
        server,
        auth,
        "vault.code.checkout.renew",
        move |server, memory| memory.checkout_renew_through(input, &mut CheckoutPresence(server)),
    )
    .await
}

pub(crate) async fn vault_code_checkout_reclaim(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutReclaimInput,
) -> Listed<CheckoutLeaseView> {
    as_caller(
        server,
        auth,
        "vault.code.checkout.reclaim",
        move |server, memory| memory.checkout_reclaim_through(input, &mut CheckoutPresence(server)),
    )
    .await
}

pub(crate) async fn vault_code_checkout_takeover(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutTakeoverInput,
) -> Listed<CheckoutLeaseView> {
    as_caller(
        server,
        auth,
        "vault.code.checkout.takeover",
        move |server, memory| {
            memory.checkout_takeover_through(input, &mut CheckoutPresence(server))
        },
    )
    .await
}

pub(crate) async fn vault_code_checkout_publish(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutPublishInput,
) -> Listed<CheckoutPublished> {
    as_caller(
        server,
        auth,
        "vault.code.checkout.publish",
        move |_, memory| memory.checkout_publish(input),
    )
    .await
}

pub(crate) async fn vault_code_checkout_settle(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutSettleInput,
) -> Listed<CheckoutSettled> {
    as_caller(
        server,
        auth,
        "vault.code.checkout.settle",
        move |_, memory| memory.checkout_settle(input),
    )
    .await
}

pub(crate) async fn vault_code_checkout_teardown(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CheckoutTeardownInput,
) -> Listed<CheckoutTornDown> {
    as_caller(
        server,
        auth,
        "vault.code.checkout.teardown",
        move |server, memory| {
            memory.checkout_teardown_through(input, &mut CheckoutPresence(server))
        },
    )
    .await
}
