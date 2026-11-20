//! The PPR walk's owner Setting keys (DESIGN 15-setting-primitive): rows the setting catalogue
//! reads from this file.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::setting::{Kind, SettingValue, lower_is_tighter};
use crate::side_table::SideTableDbs;

/// The most gated, visible edges one group of a narrowed walk may hold and still spread mass,
/// unless the owner sets it.
const DEFAULT_NARROWED_HUB_FANOUT_CAP: u32 = 256;

/// The most gated, visible edges one (node, kind, direction) group of a narrowed PPR walk may
/// hold and still spread mass: at least 1, because a cap of 0 would stop every narrowed walk at
/// its seeds.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub(crate) struct HubFanoutCap(pub(crate) u32);

impl SettingValue for HubFanoutCap {
    fn check(self) -> Result<Self> {
        if self.0 >= 1 {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "a narrowed walk's hub cap is at least one edge: a cap of 0 spreads no mass".into(),
            ))
        }
    }
}

const fn narrowed_hub_fanout_cap_default() -> HubFanoutCap {
    HubFanoutCap(DEFAULT_NARROWED_HUB_FANOUT_CAP)
}

crate::setting::setting_keys! {
    /// The most edges one group of a narrowed PPR walk may hold and still spread mass (default
    /// 256). A narrowed walk is the compute-only walk of a read scoped to a reader or narrowed
    /// by a filter: a scoped recall, a filtered search (a type, time, project or world filter),
    /// a code-memory pull, the home's residence prediction. A group is one node's edges of one
    /// kind in one direction, counting only edges that pass the walk's gates and that the
    /// reader can see; a group above the cap (an author's byline over every message they wrote,
    /// a large conversation, a busy subject) spreads no mass, so its far rows leave the PPR
    /// channel, and the text and time channels still find them. The owner-wide cached walk
    /// takes no cap. A cap of 0 is refused. A larger value is looser, so only the owner raises
    /// it; an agent's raise waits on the owner's answer. An unreadable row reads the default.
    pub(crate) NARROWED_HUB_FANOUT_CAP: HubFanoutCap = "retrieval.ppr.narrowed_hub_fanout_cap" {
        kind: Kind::new(narrowed_hub_fanout_cap_default)
            .strictest(narrowed_hub_fanout_cap_default)
            .tighter(lower_is_tighter::<HubFanoutCap>),
    };
}

/// The narrowed walk's hub cap in force, read in the walk's own transaction.
pub(super) fn narrowed_hub_fanout_cap_in(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<u32> {
    Ok(NARROWED_HUB_FANOUT_CAP
        .read_in_dbs_txn(dbs, txn, &[], None)?
        .value
        .0)
}
