use super::*;
use crate::test_util::entity;

#[test]
fn project_scope_set_is_exact_and_canonical() -> Result<()> {
    let a = entity(41);
    let b = entity(42);
    let default = crate::claim::default_project_id();
    let selected = CorpusScope::AnyOf(vec![b, a, b]).canonicalize()?;
    assert_eq!(selected, CorpusScope::AnyOf(vec![a, b]));
    assert!(selected.matches(a));
    assert!(selected.matches(b));
    assert!(!selected.matches(default));
    assert!(CorpusScope::Unscoped.matches(default));
    assert!(!CorpusScope::Corpus(a).matches(default));
    assert!(matches!(
        CorpusScope::AnyOf(vec![]).canonicalize(),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}
