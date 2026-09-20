use super::*;
use crate::outbound_consent::tool_call::ToolGrantDataClass;

#[test]
fn scoped_grant_class_codec_requires_explicit_canonical_classes() {
    let mut intent = scoped_intent("files");
    intent
        .tool_data_classes
        .push(ToolGrantDataClass::XMcpHeader);
    let grant =
        StandingOutboundGrant::from_scoped_mcp_grant_mint_intent(&intent, 10, vec![1; 32], [2; 32])
            .unwrap();
    let encoded = encode_standing_outbound_grant_body(&grant).unwrap();
    assert_eq!(
        decode_standing_outbound_grant_body(&encoded).unwrap(),
        grant
    );
    for classes in [
        None,
        Some(Value::Array(vec![])),
        Some(Value::Array(vec![Value::from("unknown")])),
        Some(Value::Array(vec![
            Value::from("arguments"),
            Value::from("arguments"),
        ])),
        Some(Value::Array(vec![
            Value::from("x_mcp_header"),
            Value::from("arguments"),
        ])),
    ] {
        let mut value = rmpv::decode::read_value(&mut Cursor::new(&encoded)).unwrap();
        let Value::Map(entries) = &mut value else {
            panic!("grant map")
        };
        let (_, Value::Map(scope)) = entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("scope"))
            .unwrap()
        else {
            panic!("scope map")
        };
        scope.retain(|(key, _)| key.as_str() != Some("tool_data_classes"));
        if let Some(classes) = classes {
            scope.push((Value::from("tool_data_classes"), classes));
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &value).unwrap();
        assert_eq!(
            decode_standing_outbound_grant_body(&bytes)
                .unwrap_err()
                .kind(),
            crate::ErrorKind::InvalidOutboundGrantBody
        );
    }
}
