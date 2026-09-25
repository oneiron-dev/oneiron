use super::*;

#[test]
fn retrieval_tag_types_round_trip_and_reject_invalid_output() {
    let entity = EntityId::from_bytes([7; 16]).unwrap();
    let text = "Ada: she";
    let tags = RetrievalTags {
        mentions: vec![
            MentionTag {
                start: 0,
                end: 3,
                entity,
                weight: 1.0,
            },
            MentionTag {
                start: 5,
                end: 8,
                entity,
                weight: 0.8,
            },
        ],
        ppr_seeds: vec![PprSeed {
            entity,
            weight: 0.7,
        }],
        affect: [0.2, -0.3, 0.4],
        coreference: vec![CoreferenceTag {
            mention: 1,
            antecedent: 0,
        }],
    };
    tags.validate(text).unwrap();
    assert_eq!(tags.read_refs(), vec![entity]);
    let decoded: RetrievalTags =
        serde_json::from_value(serde_json::to_value(&tags).unwrap()).unwrap();
    assert_eq!(decoded, tags);
    for case in 0..5 {
        let mut invalid = tags.clone();
        match case {
            0 => invalid.mentions[0].end = text.len() + 1,
            1 => invalid.mentions[0].weight = f32::NAN,
            2 => invalid.ppr_seeds[0].weight = -1.0,
            3 => invalid.affect[0] = 1.1,
            4 => invalid.coreference[0].antecedent = 2,
            _ => unreachable!(),
        }
        assert!(matches!(
            invalid.validate(text),
            Err(Error::InvalidConfig(_))
        ));
    }
    let mut bad_boundary = tags;
    bad_boundary.mentions[0].end = 1;
    assert!(matches!(
        bad_boundary.validate("éda: she"),
        Err(Error::InvalidConfig(_))
    ));
}
