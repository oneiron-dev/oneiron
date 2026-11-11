//! What a checkpoint does with each side table, written on the table's row (core split slice 1):
//! the storage tier that decides whether an image carries its rows, and the restore class a
//! restore over a live vault applies to them. The payload family a capture places them in is
//! the payload registry's own [`Class`](crate::store::checkpoint_payload::rows::Class). Recovery
//! reads all three from the row; no list beside the rows names them.

/// Where a row sits for a checkpoint: index pages and process coordination never enter the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageTier {
    /// History an image carries.
    Canonical,
    /// A projection a restore rebuilds from canonical rows.
    Derived,
    /// This node's own working state: no image carries it.
    Runtime,
}

/// What a restore over a live vault does with a side table's rows, as its row declares it
/// (ARCH-0038). Recovery's restore table turns it into its own class; only these forms are open
/// to a side table, and the projections an entity kind's body carries stay with the kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestoreClass {
    /// Historical content: the image's rows come back.
    Content,
    /// Authority, consent, policy, access, credential or erasure state, and the record of acts
    /// that already left the vault: the live vault's rows replace the image's.
    Live,
    /// Authority entangled with content: the restore refuses when any row differs from the live
    /// vault's. The text names it.
    Refuse(&'static str),
    /// As [`Self::Refuse`], over only the rows keyed by an entity the restored target holds.
    RefuseImageEntities(&'static str),
    /// No image carries the rows: the table's tier is derived or runtime.
    NotImaged,
    /// A canonical table with no restore class yet: a restore refuses a row that differs from the
    /// live vault's, as a row of an undeclared family.
    None,
}
