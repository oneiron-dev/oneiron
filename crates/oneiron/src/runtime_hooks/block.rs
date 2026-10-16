//! Hook blocks (ARCH-0080 §11): the timed pins an AddBlock outcome leaves for
//! a recipient's next board deliveries. The board renders the rows a block
//! names in their own sections, tagged with the hook (OI-1 = A).

use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

use super::filter::glob_match;
use super::outcome::BlockRequest;

/// Block rows by block id. Consumed and expired rows stay as the record.
const BLOCKS: SideTable<EntityId, HookBlock, Named> = SideTable::new(&side_table::HOOKS_BLOCK);
pub(super) const DEFAULT_TOKEN_CAP: u32 = 512;
/// Rows one block scan reads.
const MAX_BLOCK_SCAN: usize = 10_000;

/// How long a block lasts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookBlockLifetime {
    /// This many board deliveries.
    Deliveries(u32),
    /// Until a claim whose predicate matches this glob lands.
    UntilPredicate(String),
}

impl Default for HookBlockLifetime {
    fn default() -> Self {
        Self::Deliveries(1)
    }
}

/// One block row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookBlock {
    #[serde(with = "crate::serialize::entity_ref")]
    pub binding: EntityId,
    /// `<pack>/<hook>`, the tag the board shows.
    pub hook: String,
    pub run_key: String,
    #[serde(with = "crate::serialize::entity_ref::sequence")]
    pub refs: Vec<EntityId>,
    /// `None` reaches any session.
    pub session: Option<String>,
    /// `None` reaches any branch.
    pub branch: Option<String>,
    pub lifetime: HookBlockLifetime,
    pub token_cap: u32,
    /// The block reaches the first board delivery at or after this time
    /// (Unix seconds).
    pub activation: u64,
    pub deliveries_used: u32,
    pub expired_at: Option<u64>,
}

impl HookBlock {
    /// The row an AddBlock outcome writes. `request` is already validated.
    pub(super) fn from_request(
        binding: EntityId,
        hook: String,
        run_key: String,
        request: &BlockRequest,
        at: u64,
    ) -> Result<Self> {
        let refs = request
            .refs
            .iter()
            .map(|id| EntityId::from_hex(id))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            binding,
            hook,
            run_key,
            refs,
            session: request.session.clone(),
            branch: request.branch.clone(),
            lifetime: request.lifetime.clone().unwrap_or_default(),
            token_cap: request.token_cap.unwrap_or(DEFAULT_TOKEN_CAP),
            activation: at,
            deliveries_used: 0,
            expired_at: None,
        })
    }

    fn reaches(&self, session: &str, branch: Option<&str>) -> bool {
        self.expired_at.is_none()
            && self.session.as_deref().is_none_or(|own| own == session)
            && self.branch.as_deref().is_none_or(|own| branch == Some(own))
    }
}

/// Writes `block` unless a row already stands under `id`: a retried call
/// does not reset a block's deliveries. Returns whether it wrote.
pub(super) fn put_new_block_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    block: &HookBlock,
) -> Result<bool> {
    if BLOCKS.get(&vault.store, txn, &id)?.is_some() {
        return Ok(false);
    }
    BLOCKS.put(&vault.store, txn, &id, block)?;
    Ok(true)
}

pub(super) fn put_block_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    block: &HookBlock,
) -> Result<()> {
    BLOCKS.put(&vault.store, txn, &id, block)
}

/// Whether any live block waits on a predicate.
pub(super) fn any_until_predicate(vault: &Vault) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    for row in BLOCKS
        .iter_from(&vault.store, &rtxn, &[])?
        .take(MAX_BLOCK_SCAN)
    {
        let (_, block) = row?;
        if block.expired_at.is_none()
            && matches!(block.lifetime, HookBlockLifetime::UntilPredicate(_))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Expires every live block waiting on a glob `predicate` matches.
pub(super) fn expire_for_predicate(vault: &Vault, predicate: &str, at: u64) -> Result<usize> {
    vault.with_write_txn_grouped(|txn| {
        let matched: Vec<(EntityId, HookBlock)> = BLOCKS
            .iter_from(&vault.store, txn, &[])?
            .take(MAX_BLOCK_SCAN)
            .filter_map(|row| match row {
                Ok((id, block)) => match &block.lifetime {
                    HookBlockLifetime::UntilPredicate(glob)
                        if block.expired_at.is_none() && glob_match(glob, predicate) =>
                    {
                        Some(Ok((id, block)))
                    }
                    _ => None,
                },
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<_>>()?;
        for (id, mut block) in matched.iter().cloned() {
            block.expired_at = Some(at);
            BLOCKS.put(&vault.store, txn, &id, &block)?;
        }
        Ok(matched.len())
    })
}

impl Vault {
    /// The live blocks that reach `session` on `branch`, for the board.
    pub fn hook_blocks_for(
        &self,
        session: &str,
        branch: Option<&str>,
    ) -> Result<Vec<(EntityId, HookBlock)>> {
        let rtxn = self.store.env.read_txn()?;
        let mut blocks = Vec::new();
        for row in BLOCKS
            .iter_from(&self.store, &rtxn, &[])?
            .take(MAX_BLOCK_SCAN)
        {
            let (id, block) = row?;
            if block.reaches(session, branch) {
                blocks.push((id, block));
            }
        }
        Ok(blocks)
    }

    /// Records one board delivery of `block`. A block that spends its last
    /// delivery expires in the same write.
    pub fn record_hook_block_delivery(&self, block: EntityId) -> Result<HookBlock> {
        self.with_write_txn_grouped(|txn| {
            let mut row = BLOCKS
                .get(&self.store, txn, &block)?
                .ok_or(Error::EntityNotFound)?;
            if row.expired_at.is_some() {
                return Ok(row);
            }
            row.deliveries_used = row.deliveries_used.saturating_add(1);
            if let HookBlockLifetime::Deliveries(count) = row.lifetime
                && row.deliveries_used >= count
            {
                row.expired_at = Some(self.store.clock.now_recorded_at());
            }
            BLOCKS.put(&self.store, txn, &block, &row)?;
            Ok(row)
        })
    }
}
