//! Public base-vs-merged iterator enums returned by the accessors (iter/rev/range/prefix/dup/str).

use heed::iteration_method::{MoveBetweenKeys, MoveOnCurrentKeyDuplicates};
use heed::types::{Bytes, Str};
use heed::{DefaultComparator, RoIter, RoPrefix, RoRange, RoRevIter, RoRevRange};

use crate::error::Result;

use super::accessors::{KvPair, StrKvPair};
use super::merge::{
    MergedPrefixRows, MergedRows, PrefetchedMergedRows, StrMergedRows, convert_pair,
    convert_str_pair,
};

pub(crate) enum OverlayIter<'txn> {
    Base(RoIter<'txn, Bytes, Bytes>),
    Merged(Box<MergedRows<'txn, RoIter<'txn, Bytes, Bytes>>>),
}

impl<'txn> Iterator for OverlayIter<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayRevIter<'txn> {
    Base(RoRevIter<'txn, Bytes, Bytes>),
    Merged(Box<MergedRows<'txn, RoRevIter<'txn, Bytes, Bytes>>>),
}

impl<'txn> Iterator for OverlayRevIter<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayRange<'txn> {
    Base(RoRange<'txn, Bytes, Bytes>),
    Merged(Box<MergedRows<'txn, RoRange<'txn, Bytes, Bytes>>>),
}

impl<'txn> Iterator for OverlayRange<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayRevRange<'txn> {
    Base(RoRevRange<'txn, Bytes, Bytes>),
    Merged(Box<MergedRows<'txn, RoRevRange<'txn, Bytes, Bytes>>>),
}

impl<'txn> Iterator for OverlayRevRange<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayPrefix<'txn> {
    Base(RoPrefix<'txn, Bytes, Bytes, DefaultComparator>),
    BaseBetweenKeys(RoPrefix<'txn, Bytes, Bytes, DefaultComparator, MoveBetweenKeys>),
    Merged(Box<MergedPrefixRows<'txn>>),
}

impl OverlayPrefix<'_> {
    pub(crate) fn move_between_keys(self) -> Self {
        match self {
            Self::Base(inner) => Self::BaseBetweenKeys(inner.move_between_keys()),
            Self::BaseBetweenKeys(inner) => Self::BaseBetweenKeys(inner),
            Self::Merged(inner) => Self::Merged(Box::new((*inner).move_between_keys())),
        }
    }
}

impl<'txn> Iterator for OverlayPrefix<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::BaseBetweenKeys(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayDupValues<'txn> {
    Base(RoIter<'txn, Bytes, Bytes, MoveOnCurrentKeyDuplicates>),
    Merged(Box<PrefetchedMergedRows<'txn, RoIter<'txn, Bytes, Bytes, MoveOnCurrentKeyDuplicates>>>),
}

impl<'txn> Iterator for OverlayDupValues<'txn> {
    type Item = Result<KvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

#[allow(
    dead_code,
    reason = "returned by the completed OverlayStrDb::iter accessor; first session sync-state scan lands after ONE-1727"
)]
pub(crate) enum OverlayStrIter<'txn> {
    Base(RoIter<'txn, Str, Bytes>),
    Merged(Box<StrMergedRows<'txn, RoIter<'txn, Str, Bytes>>>),
}

impl<'txn> Iterator for OverlayStrIter<'txn> {
    type Item = Result<StrKvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_str_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}

pub(crate) enum OverlayStrPrefix<'txn> {
    Base(RoPrefix<'txn, Str, Bytes, DefaultComparator>),
    Merged(Box<StrMergedRows<'txn, RoPrefix<'txn, Str, Bytes, DefaultComparator>>>),
}

impl<'txn> Iterator for OverlayStrPrefix<'txn> {
    type Item = Result<StrKvPair<'txn>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Base(inner) => inner.next().map(convert_str_pair),
            Self::Merged(inner) => inner.next(),
        }
    }
}
