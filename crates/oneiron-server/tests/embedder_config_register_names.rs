//! The embedder config names, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` on the R0 head before these
//! enums became Registers (Fable pass 25, the register conversion wave), for:
//! - `crates/oneiron-server/src/config/embedder.rs`
//! - `crates/oneiron-server/src/config/embedder_shape.rs`
//!
//! Green on the hand tables and on the adoption (the derive), so no stored or sent name
//! changed (M-1 keep). The second test of each enum pins each name to serde's; where the
//! adoption rewrites a parser's body, a third reads every name back through it.

use oneiron_server::config::embedder::{
    EmbedderDevice, EmbedderLocality, EmbedderProvider, EmbedderQuant,
};
use oneiron_server::config::{EmbedderAttention, EmbedderOutputQuantization};
use serde_json::Value;

/// Every `EmbedderProvider` row, as the hand `as_str` table spelled it.
const EMBEDDER_PROVIDER_ROWS: [(EmbedderProvider, &str); 3] = [
    (EmbedderProvider::Local, "local"),
    (EmbedderProvider::Endpoint, "endpoint"),
    (EmbedderProvider::None, "none"),
];

#[test]
fn every_embedder_provider_keeps_its_name() {
    assert_eq!(EmbedderProvider::Local.as_str(), "local");
    assert_eq!(EmbedderProvider::Endpoint.as_str(), "endpoint");
    assert_eq!(EmbedderProvider::None.as_str(), "none");
}

#[test]
fn every_embedder_provider_name_is_its_serde_name() {
    for (row, name) in EMBEDDER_PROVIDER_ROWS {
        let read: EmbedderProvider =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_embedder_provider_name_reads_back() {
    for (row, name) in EMBEDDER_PROVIDER_ROWS {
        assert_eq!(name.parse::<EmbedderProvider>(), Ok(row), "{name}");
    }
    assert_eq!(
        "not-a-name".parse::<EmbedderProvider>(),
        Err(
            "unknown embedder provider \"not-a-name\" (expected local, endpoint or none)"
                .to_owned()
        )
    );
}

/// Every `EmbedderQuant` row, as the hand `as_str` table spelled it.
const EMBEDDER_QUANT_ROWS: [(EmbedderQuant, &str); 2] =
    [(EmbedderQuant::Q8_0, "q8_0"), (EmbedderQuant::None, "none")];

#[test]
fn every_embedder_quant_keeps_its_name() {
    assert_eq!(EmbedderQuant::Q8_0.as_str(), "q8_0");
    assert_eq!(EmbedderQuant::None.as_str(), "none");
}

#[test]
fn every_embedder_quant_name_is_its_serde_name() {
    for (row, name) in EMBEDDER_QUANT_ROWS {
        let written = serde_json::to_value(row).expect("a embedder quant serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: EmbedderQuant =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_embedder_quant_name_reads_back() {
    for (row, name) in EMBEDDER_QUANT_ROWS {
        assert_eq!(name.parse::<EmbedderQuant>(), Ok(row), "{name}");
    }
    assert_eq!(
        "not-a-name".parse::<EmbedderQuant>(),
        Err("unknown embedder quant \"not-a-name\" (expected q8_0 or none)".to_owned())
    );
}

/// Every `EmbedderDevice` row, as the hand `as_str` table spelled it.
const EMBEDDER_DEVICE_ROWS: [(EmbedderDevice, &str); 4] = [
    (EmbedderDevice::Auto, "auto"),
    (EmbedderDevice::Cpu, "cpu"),
    (EmbedderDevice::Metal, "metal"),
    (EmbedderDevice::Cuda, "cuda"),
];

#[test]
fn every_embedder_device_keeps_its_name() {
    assert_eq!(EmbedderDevice::Auto.as_str(), "auto");
    assert_eq!(EmbedderDevice::Cpu.as_str(), "cpu");
    assert_eq!(EmbedderDevice::Metal.as_str(), "metal");
    assert_eq!(EmbedderDevice::Cuda.as_str(), "cuda");
}

#[test]
fn every_embedder_device_name_is_its_serde_name() {
    for (row, name) in EMBEDDER_DEVICE_ROWS {
        let read: EmbedderDevice =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_embedder_device_name_reads_back() {
    for (row, name) in EMBEDDER_DEVICE_ROWS {
        assert_eq!(name.parse::<EmbedderDevice>(), Ok(row), "{name}");
    }
    assert_eq!(
        "not-a-name".parse::<EmbedderDevice>(),
        Err(
            "unknown embedder device \"not-a-name\" (expected auto, cpu, metal or cuda)".to_owned()
        )
    );
}

/// Every `EmbedderLocality` row, as the hand `as_str` table spelled it.
const EMBEDDER_LOCALITY_ROWS: [(EmbedderLocality, &str); 3] = [
    (EmbedderLocality::OnDevice, "on-device"),
    (EmbedderLocality::OwnerServer, "owner-server"),
    (EmbedderLocality::ThirdParty, "third-party"),
];

#[test]
fn every_embedder_locality_keeps_its_name() {
    assert_eq!(EmbedderLocality::OnDevice.as_str(), "on-device");
    assert_eq!(EmbedderLocality::OwnerServer.as_str(), "owner-server");
    assert_eq!(EmbedderLocality::ThirdParty.as_str(), "third-party");
}

#[test]
fn every_embedder_locality_name_is_its_serde_name() {
    for (row, name) in EMBEDDER_LOCALITY_ROWS {
        let read: EmbedderLocality =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_embedder_locality_name_reads_back() {
    for (row, name) in EMBEDDER_LOCALITY_ROWS {
        assert_eq!(name.parse::<EmbedderLocality>(), Ok(row), "{name}");
    }
    assert_eq!(
        "not-a-name".parse::<EmbedderLocality>(),
        Err(
            "unknown embedder locality \"not-a-name\" (expected on-device or owner-server)"
                .to_owned()
        )
    );
}

/// Every `EmbedderAttention` row, as the hand `as_str` table spelled it.
const EMBEDDER_ATTENTION_ROWS: [(EmbedderAttention, &str); 3] = [
    (EmbedderAttention::Auto, "auto"),
    (EmbedderAttention::Causal, "causal"),
    (EmbedderAttention::Bidirectional, "bidirectional"),
];

#[test]
fn every_embedder_attention_keeps_its_name() {
    assert_eq!(EmbedderAttention::Auto.as_str(), "auto");
    assert_eq!(EmbedderAttention::Causal.as_str(), "causal");
    assert_eq!(EmbedderAttention::Bidirectional.as_str(), "bidirectional");
}

#[test]
fn every_embedder_attention_name_is_its_serde_name() {
    for (row, name) in EMBEDDER_ATTENTION_ROWS {
        let written = serde_json::to_value(row).expect("a embedder attention serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: EmbedderAttention =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_embedder_attention_name_reads_back() {
    for (row, name) in EMBEDDER_ATTENTION_ROWS {
        assert_eq!(name.parse::<EmbedderAttention>(), Ok(row), "{name}");
    }
    assert_eq!(
        "not-a-name".parse::<EmbedderAttention>(),
        Err(
            "unknown embedder attention \"not-a-name\" (expected auto, causal or bidirectional)"
                .to_owned()
        )
    );
}

/// Every `EmbedderOutputQuantization` row, as the hand `as_str` table spelled it.
const EMBEDDER_OUTPUT_QUANTIZATION_ROWS: [(EmbedderOutputQuantization, &str); 2] = [
    (EmbedderOutputQuantization::Int8, "int8"),
    (EmbedderOutputQuantization::Binary, "binary"),
];

#[test]
fn every_embedder_output_quantization_keeps_its_name() {
    assert_eq!(EmbedderOutputQuantization::Int8.as_str(), "int8");
    assert_eq!(EmbedderOutputQuantization::Binary.as_str(), "binary");
}

#[test]
fn every_embedder_output_quantization_name_is_its_serde_name() {
    for (row, name) in EMBEDDER_OUTPUT_QUANTIZATION_ROWS {
        let written = serde_json::to_value(row).expect("a embedder output quantization serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: EmbedderOutputQuantization =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn every_embedder_output_quantization_name_reads_back() {
    for (row, name) in EMBEDDER_OUTPUT_QUANTIZATION_ROWS {
        assert_eq!(
            name.parse::<EmbedderOutputQuantization>(),
            Ok(row),
            "{name}"
        );
    }
    assert_eq!(
        "not-a-name".parse::<EmbedderOutputQuantization>(),
        Err(
            "unknown embedder output quantization \"not-a-name\" (expected int8 or binary)"
                .to_owned()
        )
    );
}
