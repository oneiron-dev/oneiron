//! Corpus-driven, sustained mutation fuzzing of the atom wire and escaped renderer.

use super::*;
use std::time::{Duration, Instant};

// Fixed seed keeps a failed CI run reproducible. A corpus item is never accepted
// just because mutations of it happen to be rejected by the codec.
struct FuzzBytes(u64);

impl FuzzBytes {
    fn next(&mut self) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as usize
    }
}

fn check_render(
    bytes: &[u8],
    frame: &LensRenderFrame,
    read: &crate::claim::ScopedRead<'_>,
) -> bool {
    let Ok(atoms) = InstrumentAtoms::decode(bytes) else {
        return false;
    };
    // Unbound interpolation is allowed to fail closed. It must never panic.
    if let Ok(view) = render_instrument(&atoms, frame, read) {
        let count = serde_json::from_slice::<serde_json::Value>(bytes)
            .unwrap()
            .as_array()
            .unwrap()
            .len();
        assert!(view.html.starts_with("<article data-instrument=\"1\">"));
        assert!(view.html.ends_with("</article>"));
        assert_eq!(view.html.matches("<section data-atom=").count(), count);
        // Only the article and closed-enum sections can introduce markup.
        assert_eq!(view.html.matches('<').count(), 2 + 2 * count);
    }
    true
}

fn mutate(bytes: &[u8], rng: &mut FuzzBytes) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let position = rng.next() % (out.len() + 1);
    let occupied = position.min(out.len().saturating_sub(1));
    match rng.next() % 5 {
        0 if !out.is_empty() => out[occupied] ^= 1 << (rng.next() % 8),
        1 if !out.is_empty() => {
            out.remove(position.min(out.len() - 1));
        }
        2 => out.insert(position, rng.next() as u8),
        3 if !out.is_empty() => out.truncate(position),
        _ => out.extend_from_slice(&bytes[..bytes.len().min(32)]),
    }
    out
}

fn fuzz(iterations: usize, duration: Option<Duration>) -> crate::Result<()> {
    let (_dir, vault) = test_vault();
    let frame = LensRenderFrame::new(
        render_id("atom-fuzz"),
        LensPrincipalBinding::human_view("viewer", actor_key("viewer"), vec![actor_key("viewer")])?,
    );
    let read = vault.scoped_read(actor_key("viewer"));
    let golden = include_bytes!("fixtures/instrument.json");
    let all_atoms = serde_json::to_vec(&sample_atoms()).unwrap();
    let all_values: Vec<serde_json::Value> = serde_json::from_slice(&all_atoms).unwrap();
    assert_eq!(all_values.len(), GENERATED_LENS_ATOM_KINDS.len());
    assert!(check_render(golden, &frame, &read));
    assert_eq!(
        render_instrument(&InstrumentAtoms::decode(golden)?, &frame, &read)?.html,
        include_str!("fixtures/instrument.html").trim_end()
    );
    assert!(check_render(&all_atoms, &frame, &read));
    let mut rng = FuzzBytes(0x33e4_17f9_c95a_760b);
    let start = Instant::now();
    let mut valid = 0;
    for i in 0..iterations {
        if duration.is_some_and(|limit| start.elapsed() >= limit) {
            break;
        }
        let item = &all_values[i % all_values.len()];
        // A valid seed with an unknown kind must be rejected *even when its
        // props remain valid*. Exercise each known shape, not only one leaf.
        let mut unknown = item.clone();
        unknown["kind"] = format!("unknown_kind_{:x}", rng.next()).into();
        let unknown = serde_json::to_vec(&vec![unknown]).unwrap();
        assert!(InstrumentAtoms::decode(&unknown).is_err());

        // Alternate byte-level grammar attacks with valid JSON whose literal
        // is hostile HTML, quotes, ampersands, Unicode or a long string.
        let candidate = if i % 2 == 0 {
            mutate(if i % 4 == 0 { golden } else { &all_atoms }, &mut rng)
        } else {
            let text = format!(
                "<script src=\"https://evil.example/{}\">&\"\'💡{}",
                rng.next(),
                "x".repeat(rng.next() % 512)
            );
            serde_json::to_vec(&serde_json::json!([{
                "kind": "text_block",
                "props": { "spans": [{ "type": "literal", "value": text }] }
            }]))
            .unwrap()
        };
        valid += usize::from(check_render(&candidate, &frame, &read));
    }
    assert!(
        valid > 0,
        "the render path must be exercised by fuzz inputs"
    );
    assert!(duration.is_none_or(|limit| start.elapsed() >= limit));
    Ok(())
}

#[test]
fn atom_codec_render_corpus_smoke() -> crate::Result<()> {
    fuzz(128, None)
}

/// The separate CI step gives the fuzzer time to mutate the golden corpus;
/// ordinary module tests keep the quick, deterministic smoke pass.
#[test]
#[ignore = "run by CI with a bounded time budget"]
fn sustained_atom_codec_render_fuzz() -> crate::Result<()> {
    fuzz(10_000_000, Some(Duration::from_secs(30)))
}
