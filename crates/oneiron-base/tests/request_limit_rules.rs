//! The five page-limit rules (UC-13 PR 3): each at an absent ask, 0, 1,
//! the default, the maximum and the maximum + 1, and with no ceiling.

use oneiron_base::request_limits::{
    PageLimit, ZeroLimitRefused, page_limit_absent_as_all, page_limit_zero_as_default,
    page_limit_zero_as_empty, page_limit_zero_as_one, page_limit_zero_refused,
};

const DEFAULT: u32 = 32;
const MAX: u32 = 128;

fn served(rows: u32) -> PageLimit<u32> {
    PageLimit {
        rows,
        clamped: false,
    }
}

fn cut(rows: u32) -> PageLimit<u32> {
    PageLimit {
        rows,
        clamped: true,
    }
}

#[test]
fn zero_refused_rule() {
    let rule = |asked| page_limit_zero_refused(asked, DEFAULT, MAX);
    assert_eq!(rule(None), Ok(served(DEFAULT)));
    assert_eq!(rule(Some(0)), Err(ZeroLimitRefused));
    assert_eq!(rule(Some(1)), Ok(served(1)));
    assert_eq!(rule(Some(DEFAULT)), Ok(served(DEFAULT)));
    assert_eq!(rule(Some(MAX)), Ok(served(MAX)));
    assert_eq!(rule(Some(MAX + 1)), Ok(cut(MAX)));
    assert_eq!(
        page_limit_zero_refused(Some(usize::MAX), 100, usize::MAX),
        Ok(PageLimit {
            rows: usize::MAX,
            clamped: false
        })
    );
    assert_eq!(
        page_limit_zero_refused(Some(0_usize), 100, usize::MAX),
        Err(ZeroLimitRefused)
    );
}

#[test]
fn zero_as_one_rule() {
    let rule = |asked| page_limit_zero_as_one(asked, DEFAULT, MAX);
    assert_eq!(rule(None), served(DEFAULT));
    assert_eq!(rule(Some(0)), served(1));
    assert_eq!(rule(Some(1)), served(1));
    assert_eq!(rule(Some(DEFAULT)), served(DEFAULT));
    assert_eq!(rule(Some(MAX)), served(MAX));
    assert_eq!(rule(Some(MAX + 1)), cut(MAX));
    for asked in [
        None,
        Some(0),
        Some(1),
        Some(DEFAULT),
        Some(MAX),
        Some(MAX + 1),
    ] {
        assert_eq!(
            rule(asked).rows,
            asked.unwrap_or(DEFAULT).clamp(1, MAX),
            "{asked:?} is served as limit.clamp(1, max) serves it"
        );
    }
    assert_eq!(
        page_limit_zero_as_one(Some(0_usize), 50, usize::MAX),
        PageLimit {
            rows: 1,
            clamped: false
        }
    );
}

#[test]
fn zero_as_default_rule() {
    let rule = |asked| page_limit_zero_as_default(asked, DEFAULT, MAX);
    assert_eq!(rule(None), served(DEFAULT));
    assert_eq!(rule(Some(0)), served(DEFAULT));
    assert_eq!(rule(Some(1)), served(1));
    assert_eq!(rule(Some(DEFAULT)), served(DEFAULT));
    assert_eq!(rule(Some(MAX)), served(MAX));
    assert_eq!(rule(Some(MAX + 1)), cut(MAX));
    assert_eq!(
        page_limit_zero_as_default(Some(0_u64), 50, u64::MAX),
        PageLimit {
            rows: 50,
            clamped: false
        }
    );
}

#[test]
fn zero_as_empty_rule() {
    let rule = |asked| page_limit_zero_as_empty(asked, DEFAULT, MAX);
    assert_eq!(rule(None), served(DEFAULT));
    assert_eq!(rule(Some(0)), served(0));
    assert_eq!(rule(Some(1)), served(1));
    assert_eq!(rule(Some(DEFAULT)), served(DEFAULT));
    assert_eq!(rule(Some(MAX)), served(MAX));
    assert_eq!(rule(Some(MAX + 1)), cut(MAX));
}

#[test]
fn absent_as_all_rule() {
    let rule = |asked| page_limit_absent_as_all(asked, MAX);
    assert_eq!(rule(None), None);
    assert_eq!(rule(Some(0)), Some(served(0)));
    assert_eq!(rule(Some(1)), Some(served(1)));
    assert_eq!(rule(Some(DEFAULT)), Some(served(DEFAULT)));
    assert_eq!(rule(Some(MAX)), Some(served(MAX)));
    assert_eq!(rule(Some(MAX + 1)), Some(cut(MAX)));
    assert_eq!(page_limit_absent_as_all(None::<usize>, usize::MAX), None);
}
