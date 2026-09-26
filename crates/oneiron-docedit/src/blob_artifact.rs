//! Storage-free version-chain decisions for a content-addressed artifact.

/// The head observed in the host's version transaction.
#[derive(Debug, Clone, Copy)]
pub struct VersionHead {
    pub version: u64,
    pub content_hash: [u8; 32],
}

/// An ordinary duplicate is a no-op; an explicit fork always appends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionDecision {
    Dedupe,
    Append {
        next_version: u64,
        parent_version: Option<u64>,
    },
}

/// A malformed parent or exhausted scalar version counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    MissingParent,
    Overflow,
}

/// Decide an append without looking outside the one transaction. The host
/// separately checks the proposed parent's stored record before writing.
pub fn decide_version(
    head: Option<VersionHead>,
    fork_parent: Option<u64>,
    hash: [u8; 32],
) -> Result<VersionDecision, VersionError> {
    if let Some(parent) = fork_parent
        && (parent == 0 || head.is_none_or(|head| parent > head.version))
    {
        return Err(VersionError::MissingParent);
    }
    if fork_parent.is_none() && head.is_some_and(|head| head.content_hash == hash) {
        return Ok(VersionDecision::Dedupe);
    }
    let next_version = match head {
        Some(head) => head.version.checked_add(1).ok_or(VersionError::Overflow)?,
        None => 1,
    };
    Ok(VersionDecision::Append {
        next_version,
        parent_version: fork_parent.or(head.map(|h| h.version)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dedupe_only_for_ordinary_same_head() {
        let h = VersionHead {
            version: 4,
            content_hash: [3; 32],
        };
        assert_eq!(
            decide_version(Some(h), None, [3; 32]),
            Ok(VersionDecision::Dedupe)
        );
        assert_eq!(
            decide_version(Some(h), Some(2), [3; 32]),
            Ok(VersionDecision::Append {
                next_version: 5,
                parent_version: Some(2)
            })
        );
        assert_eq!(
            decide_version(Some(h), None, [4; 32]),
            Ok(VersionDecision::Append {
                next_version: 5,
                parent_version: Some(4)
            })
        );
    }
    #[test]
    fn parent_and_overflow_refuse() {
        let h = VersionHead {
            version: 4,
            content_hash: [0; 32],
        };
        assert_eq!(
            decide_version(None, Some(1), [1; 32]),
            Err(VersionError::MissingParent)
        );
        assert_eq!(
            decide_version(Some(h), Some(5), [1; 32]),
            Err(VersionError::MissingParent)
        );
        assert_eq!(
            decide_version(Some(h), Some(0), [1; 32]),
            Err(VersionError::MissingParent)
        );
        assert_eq!(
            decide_version(
                Some(VersionHead {
                    version: u64::MAX,
                    content_hash: [0; 32]
                }),
                None,
                [1; 32]
            ),
            Err(VersionError::Overflow)
        );
    }
}
