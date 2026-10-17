//! `vault.lenses.default` (OF-250): the default vault projection over the
//! caller's own read key.
//!
//! The request names sources, never atoms, frames or backing refs. The host
//! builds the frame from the key the caller already holds, reads every source
//! through that key, mints backing refs only from the rows it admitted, and
//! composes them with [`compose_default_vault`]. A source the key does not
//! admit is left out exactly as a missing one is. No model call, layout,
//! navigation or owner proof.

use serde::{Deserialize, Serialize};

use super::{
    DefaultVaultInput, DefaultVaultItem, HostedLensRender, LedgerCell, LedgerRowAtom,
    LensBackingRefToken, LensBackingTarget, LensHandleName, LensHandleRole, LensPrincipalBinding,
    LensRenderFrame, LensRenderId, LensText, SectionAtom, compose_default_vault,
};
use crate::claim::{
    ClaimReadStatus, PointRead, ReadRow, ScopedRead, ScopedReadReceipt, ScopedReadResult,
};
use crate::edge::EdgeActorClass;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE};
use crate::thread_lens::ThreadLensEntry;
use crate::{EntityId, Error, Result};

/// The most sources one default projection reads, across all three lists.
pub const LENS_DEFAULT_MAX_SOURCES: usize = 64;
/// The excerpt of a source body a ledger row or thread entry shows.
const EXCERPT_BYTES: usize = 1024;
/// The body lines a dossier section shows, and the bytes of each.
const DOSSIER_LINES: usize = 32;
const DOSSIER_LINE_BYTES: usize = 512;

/// One dossier section: its source and the title the caller gives it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensDossierSource {
    /// A 32-hex entity id.
    pub entity_ref: String,
    pub title: String,
}

/// `vault.lenses.default`'s input: the sheet's title and the sources of its
/// ledger rows, dossier sections and thread entries, as 32-hex entity ids.
/// Thread sources are MESSAGE entities.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensDefaultRequest {
    pub title: String,
    #[serde(default)]
    pub ledger: Vec<String>,
    #[serde(default)]
    pub dossiers: Vec<LensDossierSource>,
    #[serde(default)]
    pub threads: Vec<String>,
}

/// One source row the caller's key admitted, with its minted backing ref and
/// the receipt of the read that admitted it.
struct Admitted {
    row: ReadRow,
    body: Vec<u8>,
    token: LensBackingRefToken,
    receipt: ScopedReadReceipt,
}

impl Memory<'_> {
    /// `vault.lenses.default`: compose the default vault projection from the
    /// named sources, read under this caller's own key, as a read-only card
    /// beside the frame that minted its backing refs (OF-181). The folded
    /// receipt names every narrowing those reads applied.
    pub fn lenses_default_framed(
        &self,
        input: LensDefaultRequest,
    ) -> MemoryResult<ScopedReadResult<HostedLensRender>> {
        let count = input.ledger.len() + input.dossiers.len() + input.threads.len();
        if count > LENS_DEFAULT_MAX_SOURCES {
            return Err(MemoryError::bad_request(format!(
                "a default projection reads at most {LENS_DEFAULT_MAX_SOURCES} sources"
            )));
        }
        let title = LensText::new(input.title)
            .map_err(|error| MemoryError::bad_request(error.to_string()))?;
        let ledger_ids = source_ids(&input.ledger.iter().map(String::as_str).collect::<Vec<_>>())?;
        let dossier_ids = source_ids(
            &input
                .dossiers
                .iter()
                .map(|source| source.entity_ref.as_str())
                .collect::<Vec<_>>(),
        )?;
        let thread_ids = source_ids(&input.threads.iter().map(String::as_str).collect::<Vec<_>>())?;
        let read = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let mut frame = principal_frame(&read)?;

        let mut ledger = Vec::new();
        for (_, admitted) in admit(&read, &mut frame, "ledger", &ledger_ids)? {
            let row = &admitted.row;
            let value = ScopedReadResult {
                value: LedgerRowAtom {
                    cells: vec![
                        cell("kind", kind(row.entity_type))?,
                        cell("ref", row.id.to_hex())?,
                        cell(
                            "value",
                            excerpt(&super::instrument::display_body(&admitted.body)),
                        )?,
                    ],
                    status: None,
                    seal: None,
                },
                receipt: admitted.receipt,
            };
            ledger.push(item(value, admitted.token));
        }
        let mut dossiers = Vec::new();
        for (index, admitted) in admit(&read, &mut frame, "dossier", &dossier_ids)? {
            let text = super::instrument::display_body(&admitted.body);
            let lines = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .take(DOSSIER_LINES)
                .map(|line| LensText::new(clip(line, DOSSIER_LINE_BYTES)))
                .collect::<Result<Vec<_>>>()?;
            let value = ScopedReadResult {
                value: SectionAtom {
                    title: LensText::new(input.dossiers[index].title.clone())
                        .map_err(|error| MemoryError::bad_request(error.to_string()))?,
                    lines,
                },
                receipt: admitted.receipt,
            };
            dossiers.push(item(value, admitted.token));
        }
        let mut threads = Vec::new();
        for (_, admitted) in admit(&read, &mut frame, "thread", &thread_ids)? {
            if admitted.row.entity_type != ENTITY_TYPE_MESSAGE {
                return Err(MemoryError::bad_request(
                    "thread sources are MESSAGE entities",
                ));
            }
            let Some(entry) = thread_entry(&admitted)? else {
                continue;
            };
            let value = ScopedReadResult {
                value: entry,
                receipt: admitted.receipt,
            };
            threads.push(item(value, admitted.token));
        }
        let ScopedReadResult { value, receipt } = compose_default_vault(
            &read,
            &frame,
            DefaultVaultInput {
                title,
                // The reads above are live; no as-of selection is applied, so
                // none is described.
                as_of: None,
                ledger,
                dossiers,
                threads,
            },
        )?;
        Ok(ScopedReadResult {
            value: HostedLensRender::new(frame, value)?,
            receipt,
        })
    }
}

fn source_ids(refs: &[&str]) -> MemoryResult<Vec<EntityId>> {
    refs.iter()
        .map(|reference| {
            EntityId::from_hex(reference.trim()).map_err(|_| {
                MemoryError::bad_request("default projection sources are 32-hex entity ids")
            })
        })
        .collect()
}

/// A frame for the caller's own selected key: an agent's task, else a
/// person's view. The key is the one the read lane built; nothing broadens it.
fn principal_frame(read: &ScopedRead<'_>) -> Result<LensRenderFrame> {
    let key = read.actor_key().clone();
    let principal_ref = key.actor_ref().to_owned();
    let principal = if key.actor_class() == Some(EdgeActorClass::Agent.gate_actor_class()) {
        LensPrincipalBinding::agent_task(principal_ref, key.clone(), vec![key])?
    } else {
        LensPrincipalBinding::human_view(principal_ref, key.clone(), vec![key])?
    };
    let render_id = LensRenderId::new(format!("default-vault-{}", EntityId::now().to_hex()))?;
    Ok(LensRenderFrame::new(render_id, principal))
}

/// The rows of `ids` the caller's key admits, in request order, each with a
/// backing ref minted from that admitted read. A withheld row and a missing
/// one are both left out. The index is the source's position in `ids`.
fn admit(
    read: &ScopedRead<'_>,
    frame: &mut LensRenderFrame,
    list: &str,
    ids: &[EntityId],
) -> Result<Vec<(usize, Admitted)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let reads: Vec<_> = ids.iter().map(|id| PointRead::id(*id)).collect();
    let ScopedReadResult {
        value: rows,
        receipt,
    } = read.read(&reads, None)?;
    let mut admitted = Vec::new();
    for (index, row) in rows.into_iter().enumerate() {
        let Some(row) = row else { continue };
        let Some(body) = row.body.clone() else {
            continue;
        };
        let (target, role) = if row.entity_type == ENTITY_TYPE_CLAIM {
            (
                LensBackingTarget::claim(row.id, row.id.to_hex(), row.content_hash)?,
                LensHandleRole::ClaimSet,
            )
        } else {
            (
                LensBackingTarget::entity(row.id, row.id.to_hex(), row.content_hash)?,
                LensHandleRole::EntitySet,
            )
        };
        let token = frame.mint_backing_ref(
            read,
            LensHandleName::new(format!("{list}-{index}"))?,
            role,
            target,
        )?;
        admitted.push((
            index,
            Admitted {
                row,
                body,
                token,
                receipt: receipt.clone(),
            },
        ));
    }
    Ok(admitted)
}

fn item<T>(projection: ScopedReadResult<T>, token: LensBackingRefToken) -> DefaultVaultItem<T> {
    DefaultVaultItem {
        projection,
        backing_refs: vec![token],
    }
}

fn cell(label: &str, value: String) -> Result<LedgerCell> {
    Ok(LedgerCell {
        label: LensText::new(label)?,
        value: LensText::new(value)?,
    })
}

fn kind(entity_type: u8) -> String {
    crate::registry::entity_type_registry_entry(entity_type).map_or_else(
        || format!("TYPE_{entity_type}"),
        |entry| entry.kind.to_owned(),
    )
}

fn excerpt(text: &str) -> String {
    clip(text.trim(), EXCERPT_BYTES).to_owned()
}

/// `text` cut to at most `bytes`, on a character boundary.
fn clip(text: &str, bytes: usize) -> &str {
    if text.len() <= bytes {
        return text;
    }
    let mut end = bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// A MESSAGE row as one read-only thread entry, or `None` when it carries no
/// text. Its bytes must be the canonical transcript envelope.
fn thread_entry(admitted: &Admitted) -> Result<Option<ThreadLensEntry>> {
    use crate::gate::{
        WITNESS_AUTHOR_COMPANION, WITNESS_AUTHOR_SYSTEM, WITNESS_AUTHOR_USER,
        WitnessMessageBodyAuthor, validate_canonical_witness_message_body,
    };
    let author = match validate_canonical_witness_message_body(&admitted.body)? {
        WitnessMessageBodyAuthor::User => WITNESS_AUTHOR_USER,
        WitnessMessageBodyAuthor::Companion => WITNESS_AUTHOR_COMPANION,
        WitnessMessageBodyAuthor::System => WITNESS_AUTHOR_SYSTEM,
    };
    let value = rmpv::decode::read_value(&mut admitted.body.as_slice())
        .map_err(|_| Error::InvalidConfig("thread source is not a MESSAGE envelope".into()))?;
    let content = value
        .as_map()
        .and_then(|entries| {
            entries
                .iter()
                .find(|(key, _)| key.as_str() == Some("content"))
                .and_then(|(_, value)| value.as_str())
        })
        .unwrap_or_default();
    let content = excerpt(content);
    if content.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        ThreadLensEntry::new("transcript", author, content)?
            .timestamp(admitted.row.occurred.start.to_string())
            .message_ref(admitted.row.id.to_hex()),
    ))
}
