//! Where a payload family's rows go in a checkpoint (KS7-2b): its one [`Class`], with the owner
//! getters, custody clients and mixed sync carriers a class names. A side table's row declares its
//! family's class (`[family: ..]`); recovery's payload registry reads it there and classes the
//! manifest databases and entity kinds itself. These types sit below recovery, with the rows they
//! place, so a table's row names them without naming recovery; recovery's checkpoint payload
//! dispatches each getter to its store's capture and restore.

use serde::{Deserialize, Serialize};

use super::OtherClient;
use crate::store::CustodyKind;

/// Where a family's rows go: its one class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// An owner getter reads the family and places each row.
    Owner(Getter),
    /// Ids, counts, digests, markers and pins with no payload of their own.
    Structure,
    /// Another custody client's rows, handed to it as they stand.
    Other(Client),
    /// A mixed sync carrier, which KS7-3's port splits.
    Mixed(Carrier),
    /// Not compartmented: under the vault-wide seal, named on the receipt.
    Unclassified,
    /// Runtime or derived rows, which no image takes.
    NotImaged,
}

/// The custody client another family's rows belong to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Client {
    /// One the getters dispatch to as well (KS-2, KS-2B, KS-5, KS-6).
    Dispatch(OtherClient),
    /// Rows already sealed under that kind's own keys, which stay live in
    /// custody: KS-1's claim-bound gate decisions.
    Sealed(CustodyKind),
}

#[doc(hidden)]
pub(crate) use oneiron_records::store::checkpoint_payload::rows::class::{Carrier, Getter};
