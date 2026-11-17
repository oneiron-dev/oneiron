//! Scratch probe (not for merge): prints the sound distances the entity
//! linker's NPD rung would see for name pairs, whole and part by part.

use oneiron_store::batch::phonetic_codes::{
    NPD_THRESHOLD, Segment, generate_phonetic_codes, ipa_segments, linking_codes, npd,
    phonetic_readings,
};

fn sound_keys(name: &str) -> Vec<(String, Vec<Segment>)> {
    generate_phonetic_codes(name)
        .into_iter()
        .filter_map(|code| {
            let rest = code.strip_prefix("ipa:")?.to_owned();
            let (_, ipa) = rest.split_once(':')?;
            Some((rest.clone(), ipa_segments(ipa)?))
        })
        .collect()
}

fn min_npd(query: &[Vec<Segment>], candidate: &[Vec<Segment>]) -> f32 {
    let mut best = f32::INFINITY;
    for q in query {
        for c in candidate {
            best = best.min(npd(q, c));
        }
    }
    best
}

fn parts(name: &str) -> Vec<String> {
    name.to_lowercase()
        .split(|c: char| c.is_whitespace() || c == '.' || c == ',' || c == '-' || c == '・')
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn readings(text: &str) -> Vec<Vec<Segment>> {
    phonetic_readings(text)
        .into_iter()
        .map(|reading| reading.segments)
        .collect()
}

fn code_rung(mention: &str, person: &str) -> bool {
    let codes = linking_codes(mention);
    let held = generate_phonetic_codes(person);
    codes.whole.iter().any(|code| held.contains(code))
        || (!codes.every_part.is_empty() && codes.every_part.iter().all(|code| held.contains(code)))
}

#[test]
fn print_name_pair_distances() {
    let pairs: &[(&str, &str)] = &[
        ("Owan Smyth", "Owen Smith"),
        ("Owan Smyth", "Owen Smyth"),
        ("Owan Smyth", "Owen R. Smith"),
        ("Owan Smyth", "John Smith"),
        ("Owan Smyth", "fixture speaker"),
        ("Jon Smyth", "John Smith"),
        ("Jon Smyth", "Owen Smith"),
        ("Jon Smyth", "Owen Smyth"),
        ("my manager", "May Manager"),
        ("my manager", "Moe Manager"),
        ("my manager", "Owen Smith"),
        ("my manager", "Mori Yuki"),
        ("my manager", "fixture speaker"),
        ("もり ゆき", "Mori Yuki"),
        ("Owan", "Owen Smith"),
        ("Owan", "Owen"),
        ("Robert Jones", "Robert Smith"),
        ("Owen Snow", "Owen Smith"),
        ("Morimoto Owen", "Morimoto Yuki"),
        ("Katherine Smith", "Catherine Smith"),
        ("Philip Novak", "Filip Novak"),
        ("Christina Lee", "Kristina Lee"),
        ("Geoff Brown", "Jeff Brown"),
        ("Cathy Nguyen", "Kathy Nguyen"),
        ("Carl Schmidt", "Karl Schmidt"),
        ("Sadou Kenji", "Satou Kenji"),
        ("Kenji Sadou", "Kenji Satou"),
        ("Robin Smith", "Robert Smith"),
        ("Ewan Smith", "Owen Smith"),
        ("Mark Jones", "Mary Jones"),
        ("Hannah Lee", "Anna Lee"),
        ("Owen Smart", "Owen Smith"),
        ("John Smith", "Jane Smith"),
        ("Owen Smith", "Owen Smithers"),
        ("Ann Lee", "Anne Lee"),
        ("Kristen Lee", "Christina Lee"),
        ("Tom Baker", "Tim Baker"),
        ("Dan Brown", "Don Brown"),
        ("Wang Xiaoming", "王小明"),
        ("王小明", "Wang Xiaoming"),
        ("ジョン スミス", "John Smith"),
        ("Yamada Taro", "やまだ たろう"),
        ("やまだ たろう", "Yamada Taro"),
        ("Kim Minjun", "김민준"),
    ];
    for (mention, person) in pairs {
        let query: Vec<Vec<Segment>> = sound_keys(mention).into_iter().map(|k| k.1).collect();
        let candidate: Vec<Vec<Segment>> = sound_keys(person).into_iter().map(|k| k.1).collect();
        let whole = min_npd(&query, &candidate);
        let mut worst = 0.0f32;
        let mut each = Vec::new();
        for part in parts(mention) {
            let part_readings = readings(&part);
            let mut best = f32::INFINITY;
            for other in parts(person) {
                best = best.min(min_npd(&part_readings, &readings(&other)));
            }
            worst = worst.max(best);
            each.push(format!("{part}={best:.3}"));
        }
        println!(
            "PIN pair m={mention:?} p={person:?} whole={whole:.3} under={} code={} parts=[{}] worst={worst:.3} part_under={}",
            whole <= NPD_THRESHOLD,
            code_rung(mention, person),
            each.join(" "),
            worst <= NPD_THRESHOLD,
        );
    }
    for name in [
        "Owen Smith",
        "Owan Smyth",
        "Robert Jones",
        "Robert Smith",
        "Owen Snow",
        "Katherine Smith",
        "Catherine Smith",
        "my manager",
        "May Manager",
    ] {
        let keys: Vec<String> = sound_keys(name).into_iter().map(|k| k.0).collect();
        println!("PIN keys name={name:?} {keys:?}");
    }
}
