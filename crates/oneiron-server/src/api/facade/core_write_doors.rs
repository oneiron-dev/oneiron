//! The host doors of `vault.conversations.turns.create`,
//! `vault.conversations.records.append` and `vault.batch` (OF-181).
//! `host_doors` re-exports them, so the generated HTTP facade handler, the
//! MCP dispatcher and the REST routes run one write each. A TURN's write
//! lands its turn on the vault once, here, so each row sets no
//! `lands_turn`; a batch commits at the grade of the credential that sent
//! it.
use std::sync::Arc;

use oneiron::WriteActor;
use oneiron::core_write::{
    ConversationTurnCreateInput, CoreBatchCommit, CoreBatchWriteInput, CoreBatchWriteReceipt,
    CoreEntityWriteReceipt, DagRecordAppendInput, DagRecordAppendReceipt,
};
use oneiron::dreamer_wake::WakeTurnSubject;
use oneiron::memory::{MemoryResult, ProducerRows};

use super::host_doors::{Listed, internal, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.conversations.turns.create`: one TURN under a conversation.
pub(crate) async fn vault_conversations_turns_create(
    server: &Arc<SyncServer>,
    _auth: &CoreAuth,
    input: ConversationTurnCreateInput,
) -> MemoryResult<CoreEntityWriteReceipt> {
    write_core_turn(server, input).await
}

/// One TURN under a conversation, then its landing on the vault. Every
/// caller runs this: the row's door and the REST route alike.
pub(crate) async fn write_core_turn(
    server: &Arc<SyncServer>,
    input: ConversationTurnCreateInput,
) -> MemoryResult<CoreEntityWriteReceipt> {
    let vault = Arc::clone(&server.vault);
    let receipt = tokio::task::spawn_blocking(move || vault.write_core_conversation_turn(&input))
        .await
        .map_err(|_| internal("vault.conversations.turns.create"))??;
    server
        .ai
        .turn_landed(server.vault(), WakeTurnSubject::Vault);
    Ok(receipt)
}

/// `vault.conversations.records.append`: one DAG record bylined the
/// credential's principal. Beside it, the rows its writer's reads listed.
pub(crate) async fn vault_conversations_records_append(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DagRecordAppendInput,
) -> Listed<DagRecordAppendReceipt> {
    let (actor, class) = match super::facade_actor(auth) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal.into_memory_error()),
    };
    let producers = ProducerRows::default();
    let answer = write_dag_record_listing(
        server,
        auth,
        WriteActor::new(actor, class),
        &input,
        Some(&producers),
    );
    (answer, producers.take())
}

/// One DAG record bylined `actor`, written on `auth`'s own lane, then its
/// landing on the vault. The REST route passes the actor its body binds,
/// which an owner-grade credential with no principal may name; the row's
/// door passes the credential's own.
pub(crate) fn write_dag_record(
    server: &SyncServer,
    auth: &CoreAuth,
    actor: WriteActor,
    input: &DagRecordAppendInput,
) -> MemoryResult<DagRecordAppendReceipt> {
    write_dag_record_listing(server, auth, actor, input, None)
}

/// [`write_dag_record`], its writer's reads listed in `producers` when a
/// door collects them.
fn write_dag_record_listing(
    server: &SyncServer,
    auth: &CoreAuth,
    actor: WriteActor,
    input: &DagRecordAppendInput,
    producers: Option<&ProducerRows>,
) -> MemoryResult<DagRecordAppendReceipt> {
    let writer = crate::api::credential_memory(
        &server.vault,
        Some(auth),
        actor.entity_ref(),
        actor.actor_class(),
    )
    .at(auth.locality());
    let writer = match producers {
        Some(producers) => writer.listing_producers(producers),
        None => writer,
    };
    let receipt = writer.conversations_records_append(input)?;
    server
        .ai
        .turn_landed(server.vault(), WakeTurnSubject::Vault);
    Ok(receipt)
}

/// `vault.batch`: an atomic core entity batch.
pub(crate) async fn vault_batch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CoreBatchWriteInput,
) -> MemoryResult<CoreBatchWriteReceipt> {
    write_core_batch(server, auth, input).await
}

/// One atomic batch, committed at owner grade only when `auth` carries it.
pub(crate) async fn write_core_batch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CoreBatchWriteInput,
) -> MemoryResult<CoreBatchWriteReceipt> {
    let commit = if auth.is_owner_grade() {
        CoreBatchCommit::Owner
    } else {
        CoreBatchCommit::BelowOwner
    };
    let vault = Arc::clone(&server.vault);
    tokio::task::spawn_blocking(move || vault.write_core_batch(&input, commit))
        .await
        .map_err(|_| internal("vault.batch"))?
}
