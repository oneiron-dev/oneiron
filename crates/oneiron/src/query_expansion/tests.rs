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
fn hyde_retry_limit_saturates_at_200() {
    assert_eq!(retry_channel_limit(1), 2);
    assert_eq!(retry_channel_limit(100), 200);
    assert_eq!(retry_channel_limit(150), 200);
    assert_eq!(retry_channel_limit(200), 200);
}

#[test]
fn hyde_subqueries_deduped_and_capped() {
    let values = ["q", "q", "", "r", "s", "t"].map(str::to_owned);
    assert_eq!(normalized_subqueries(&values), vec!["q", "r", "s"]);
}
