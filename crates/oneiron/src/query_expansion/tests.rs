use super::*;

#[test]
fn grounding_resolves_placeholder() {
    let mut context = GroundingContext::default();
    context.bindings.insert("name".into(), "世界 🌙".into());
    context.bindings.insert("q1_2".into(), "ok".into());
    assert_eq!(
        ground_query("hello ${name}! ${q1_2}", &context).unwrap(),
        "hello 世界 🌙! ok"
    );
    assert!(matches!(
        ground_query("${missing}", &context),
        Err(Error::InvalidConfig(_))
    ));
    for malformed in ["${name", "${}", "${a b}", "${nested_${x}}"] {
        assert!(matches!(
            ground_query(malformed, &context),
            Err(Error::InvalidConfig(_))
        ));
    }
}

#[test]
fn hyde_retry_channel_widens_without_shrinking_and_saturates_at_the_ceiling() {
    let ceiling = HYDE_RETRY_MAX_LIMIT;
    let multiplier = HYDE_RETRY_LIMIT_MULTIPLIER;
    assert!(multiplier > 1);
    assert!(ceiling > multiplier);
    let saturation_at = ceiling.div_ceil(multiplier);
    for (limit, expected) in [
        (1, multiplier),
        (saturation_at, ceiling),
        ((saturation_at + ceiling) / 2, ceiling),
        (ceiling, ceiling),
    ] {
        assert_eq!(retry_channel_limit(limit), expected, "limit {limit}");
    }

    let mut previous = 0;
    for limit in 0..=ceiling + 1 {
        let widened = retry_channel_limit(limit);
        assert!(widened >= limit, "retry must not shrink limit {limit}");
        assert!(widened <= ceiling.max(limit), "retry must remain bounded");
        assert!(widened >= previous, "retry must be monotone");
        previous = widened;
    }
    // The ceiling bounds added expansion, not the caller's original limit.
    assert_eq!(retry_channel_limit(ceiling + 1), ceiling + 1);
    assert_eq!(retry_channel_limit(usize::MAX), usize::MAX);
}

#[test]
fn hyde_subqueries_deduped_and_capped() {
    let values = ["q", "q", "", "r", "s", "t"].map(str::to_owned);
    assert_eq!(normalized_subqueries(&values), vec!["q", "r", "s"]);
}
