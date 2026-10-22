//! The host doors of `vault.conversations.turns.create`,
//! `vault.conversations.records.append` and `vault.batch` (OF-181).
//! `host_doors` re-exports them, so the generated HTTP facade handler, the
//! MCP dispatcher and the REST routes run one write each. A TURN's write
//! lands its turn on the vault once, here, so each row sets no
//! `lands_turn`; a batch commits at the grade of the credential that sent
//! it. Beside each receipt, its door lists the rows the receipt names
//! (`host_door_lists`).
use std::sync::Arc;

use oneiron::WriteActor;
use oneiron::core_write::{
    ConversationTurnCreateInput, CoreBatchCommit, CoreBatchWriteInput, CoreBatchWriteReceipt,
    CoreEntityWriteReceipt, DagRecordAppendInput, DagRecordAppendReceipt,
};
use oneiron::dreamer_wake::WakeTurnSubject;
use oneiron::memory::{MemoryResult, ProducerRows};

use super::host_doors::support::{Listed, hex_rows, internal, naming, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.conversations.turns.create`: one TURN under a conversation.
/// Beside it, the TURN it wrote and the conversation it landed under,
/// whose type the write read to land it.
pub(crate) async fn vault_conversations_turns_create(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConversationTurnCreateInput,
) -> Listed<CoreEntityWriteReceipt> {
    let conversation = input.conversation.clone();
    naming(write_core_turn(server, auth, input).await, |receipt| {
        hex_rows([receipt.id.as_str(), conversation.as_str()])
    })
}

/// One TURN under a conversation, held to the read `auth`'s credential
/// reads under on every `/v1` door (FIX 5939), then its landing on the
/// vault. Every caller runs this: the row's door and the REST route alike.
/// A host credential that acts as no person gets its refusal. It is a
/// platform announcement only at `auth`'s owner authority.
pub(crate) async fn write_core_turn(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConversationTurnCreateInput,
) -> MemoryResult<CoreEntityWriteReceipt> {
    let announcement = crate::api::announcement_authority(server, auth);
    let vault = Arc::clone(&server.vault);
    let auth = auth.clone();
    let receipt = tokio::task::spawn_blocking(move || {
        let writer = match crate::api::scoped_read_for_core_auth(&vault, &auth) {
            Ok(writer) => writer,
            Err(refused) => {
                // The owner's own credential that grants no read still
                // writes as the owner (FIX 6066); any other keeps its refusal.
                if matches!(
                    refused.details(),
                    crate::error::ApiErrorDetails::Unauthorized
                ) && let Some(proof) = auth.verified_slip()
                    && let Some(receipt) =
                        vault.write_core_conversation_turn_as_owner(&input, proof, announcement)?
                {
                    return Ok(receipt);
                }
                return Err(super::FacadeApiError::from(refused).into_memory_error());
            }
        };
        vault.write_core_conversation_turn(&input, &writer, announcement)
    })
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
    let (actor, class) = match super::facade_actor(server, auth) {
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
    let announcement = crate::api::announcement_authority(server, auth);
    let receipt = writer.conversations_records_append_at(input, announcement)?;
    server
        .ai
        .turn_landed(server.vault(), WakeTurnSubject::Vault);
    Ok(receipt)
}

/// `vault.batch`: an atomic core entity batch. Beside it, each entity it
/// put: a put reads no row.
pub(crate) async fn vault_batch(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CoreBatchWriteInput,
) -> Listed<CoreBatchWriteReceipt> {
    naming(write_core_batch(server, auth, input).await, |receipt| {
        hex_rows(receipt.entities.iter().map(|entity| entity.id.as_str()))
    })
}

/// One atomic batch, committed at owner grade only when `auth` carries it,
/// its TURNs platform announcements only at `auth`'s owner authority.
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
    let announcement = crate::api::announcement_authority(server, auth);
    let vault = Arc::clone(&server.vault);
    tokio::task::spawn_blocking(move || vault.write_core_batch(&input, commit, announcement))
        .await
        .map_err(|_| internal("vault.batch"))?
}
