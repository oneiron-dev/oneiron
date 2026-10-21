//! The house models the deploy scripts serve today, pinned file by file
//! (`deploy/house-model/`, `deploy/voxcpm2/`): the EXL3 27B target and its
//! DFlash2 draft, the llama.cpp GGUF target and its draft, and VoxCPM2.
//!
//! Each revision is the commit the deployed branch named on 2026-10-22 (the
//! EXL3 target's `4.00bpw` branch, every other repository's `main`). An LFS
//! file's digest is its Hugging Face LFS object id at that commit; every
//! other file was fetched at that commit and measured the same day, its git
//! blob id checked against the tree. Only the files a worker loads are
//! pinned, plus the licence evidence: the repository's licence file, or its
//! model card where the card is the only place the licence is declared.

use std::borrow::Cow;

use super::licence::LicenceTerms;
use super::manifest::{ArtifactClass, ArtifactFile, ArtifactFormat, ArtifactManifest};

/// Every house model, in no order the supervisor depends on.
pub(crate) static HOUSE_ARTIFACTS: [ArtifactManifest; 5] = [
    ArtifactManifest {
        id: Cow::Borrowed("qwen3.8-27b-exl3-4bpw"),
        repo: Cow::Borrowed("turboderp/Qwen3.8-27B-exl3"),
        revision: Cow::Borrowed("113cf7ab958054860e43fb7f3063b1af19171095"),
        class: ArtifactClass::Llm,
        format: ArtifactFormat::Exl3,
        quant: Cow::Borrowed("4.00bpw"),
        // The card declares none; the repository and its copied card name
        // the base.
        base_models: Cow::Borrowed(QWEN38_27B),
        files: Cow::Borrowed(EXL3_TARGET_FILES),
        licence: apache("LICENSE"),
    },
    ArtifactManifest {
        id: Cow::Borrowed("qwen3.8-27b-dflash2-exl3-5bpw"),
        repo: Cow::Borrowed("Mia-AiLab/Qwen3.8-27B-DFlash2-EXL3-5.0bpw"),
        revision: Cow::Borrowed("4f0436269bca761b071f05319e8e04a87cc633f9"),
        class: ArtifactClass::Drafter,
        format: ArtifactFormat::Exl3,
        quant: Cow::Borrowed("5.0bpw"),
        base_models: Cow::Borrowed(DFLASH2_BASES),
        files: Cow::Borrowed(DFLASH2_DRAFT_FILES),
        licence: apache("LICENSE"),
    },
    ArtifactManifest {
        id: Cow::Borrowed("qwen3.8-27b-ud-q4km-gguf"),
        repo: Cow::Borrowed("unsloth/Qwen3.8-27B-GGUF"),
        revision: Cow::Borrowed("4ca720788d1e01f1bff70c033e0d0028fd02e502"),
        class: ArtifactClass::Llm,
        format: ArtifactFormat::Gguf,
        quant: Cow::Borrowed("UD-Q4_K_M"),
        base_models: Cow::Borrowed(QWEN38_27B),
        files: Cow::Borrowed(LLAMA_TARGET_FILES),
        licence: apache("README.md"),
    },
    ArtifactManifest {
        id: Cow::Borrowed("qwen3.5-0.8b-q8-gguf"),
        repo: Cow::Borrowed("unsloth/Qwen3.5-0.8B-GGUF"),
        revision: Cow::Borrowed("6ab461498e2023f6e3c1baea90a8f0fe38ab64d0"),
        class: ArtifactClass::Drafter,
        format: ArtifactFormat::Gguf,
        quant: Cow::Borrowed("Q8_0"),
        base_models: Cow::Borrowed(QWEN35_08B),
        files: Cow::Borrowed(LLAMA_DRAFT_FILES),
        licence: apache("README.md"),
    },
    ArtifactManifest {
        id: Cow::Borrowed("voxcpm2"),
        repo: Cow::Borrowed("openbmb/VoxCPM2"),
        revision: Cow::Borrowed("32279effe8c19989596f05d353d1447f51d9e915"),
        class: ArtifactClass::Voice,
        format: ArtifactFormat::VoxCpm2Checkpoint,
        quant: Cow::Borrowed("bf16"),
        base_models: Cow::Borrowed(ORIGINAL),
        files: Cow::Borrowed(VOXCPM2_FILES),
        licence: apache("README.md"),
    },
];

/// The house model `id` names.
pub(crate) fn house_artifact(id: &str) -> Option<&'static ArtifactManifest> {
    HOUSE_ARTIFACTS.iter().find(|manifest| manifest.id == id)
}

/// An original release: converted or trained from nothing listed.
const ORIGINAL: &[Cow<'static, str>] = &[];

const QWEN38_27B: &[Cow<'static, str>] = &[Cow::Borrowed("Qwen/Qwen3.8-27B")];

const DFLASH2_BASES: &[Cow<'static, str>] = &[
    Cow::Borrowed("incoai/Qwen3.8-27B-DFlash2"),
    Cow::Borrowed("Qwen/Qwen3.8-27B"),
];

const QWEN35_08B: &[Cow<'static, str>] = &[Cow::Borrowed("Qwen/Qwen3.5-0.8B")];

/// What `exl3_server.py` loads through exllamav3 1.6.0: the config and the
/// vision preprocessor config its Qwen3.5-family config reads, the
/// tokenizer files, the chat template the server renders, and the shards.
const EXL3_TARGET_FILES: &[ArtifactFile] = &[
    file(
        "LICENSE",
        "bbedc3fda3305820b977265f01b8619d87570a6739de3a5582c3464840f1e57a",
        11_544,
    ),
    file(
        "config.json",
        "dab9abc478e1b1b928ef354f27a26fc90e8191a4a3ce5f3d19aa21558216b267",
        4_621,
    ),
    file(
        "preprocessor_config.json",
        "27225450ac9c6529872ee1924fcb0962ff5634834f817040f444118116f4e516",
        390,
    ),
    file(
        "generation_config.json",
        "e70c136c1b78ddc1fb0905bac8e733a4dc448d4f852a5dd75143fffc70be550e",
        202,
    ),
    file(
        "tokenizer_config.json",
        "b11349aafa7cdc6a320767cf7ceb29ed82f7eda5d65e8e0819e76f0ce947bf27",
        17_928,
    ),
    file(
        "chat_template.jinja",
        "c3cf9e34abf4f9e36c2d72165aa9c132d3e2a725b6c2586aaa3a8af9d7a81041",
        8_952,
    ),
    file(
        "tokenizer.json",
        "0997f410c57a1f4e53b09e4be8f4a172d90edd9564368fb0847030937229b9f3",
        12_809_320,
    ),
    file(
        "model-00001-of-00002.safetensors",
        "b1e7fcc53a2bb211460ebb65e329cdb7a5af8bd819dcbcd89e06f0ccc041e590",
        8_471_336_006,
    ),
    file(
        "model-00002-of-00002.safetensors",
        "c6d72f51b0cd99510239b264fef37bc26c950e6843f35421ce4830d4f87f8c05",
        8_389_473_789,
    ),
];

/// The DFlash2 draft: its config and weights; it shares the target's
/// tokenizer.
const DFLASH2_DRAFT_FILES: &[ArtifactFile] = &[
    file(
        "LICENSE",
        "bbedc3fda3305820b977265f01b8619d87570a6739de3a5582c3464840f1e57a",
        11_544,
    ),
    file(
        "config.json",
        "b7f916198b36fb8a1b2104c265ce055c2d128b72c5b0bad74b55e754aff60d3f",
        1_686,
    ),
    file(
        "model.safetensors",
        "6b2e3afc694a343b7f3f0edfe5925e460762fc9ede4699165b577ca0733c8e56",
        1_470_916_078,
    ),
];

/// The llama.cpp target `serve-llama.sh` names, one GGUF; the card carries
/// the licence.
const LLAMA_TARGET_FILES: &[ArtifactFile] = &[
    file(
        "README.md",
        "66088b22a4db15353288f45a570279f76d7d8b7f349a64dd28698b867c9bd2bb",
        7_455,
    ),
    file(
        "Qwen3.8-27B-UD-Q4_K_M.gguf",
        "322e194ff79741c7baa497c240f677f54b201b0efab44ca8e50f122b39123482",
        16_464_440_224,
    ),
];

/// The llama.cpp draft `serve-llama.sh` names; the card carries the
/// licence.
const LLAMA_DRAFT_FILES: &[ArtifactFile] = &[
    file(
        "README.md",
        "962978aa8e3c564c5aca3f8fc3b9a21b4d42a2a045475df38e8a570285047ea5",
        62_950,
    ),
    file(
        "Qwen3.5-0.8B-Q8_0.gguf",
        "0ad885ffd4bb022fc4f0d33a3308fa108ef8613159d3b3a67e23abca056b7a6c",
        811_843_840,
    ),
];

/// What `VoxCPM.from_pretrained` loads in voxcpm 2.0.3: the config, the
/// fast tokenizer's files, the audio VAE (read with `weights_only`) and the
/// weights. The repository's `tokenization_voxcpm2.py` is code and is not
/// pinned; the card carries the licence.
const VOXCPM2_FILES: &[ArtifactFile] = &[
    file(
        "README.md",
        "c18d2ffbfb2f0aec770481c967842aee6c200cde65f6b033efd892a849986fda",
        7_939,
    ),
    file(
        "config.json",
        "405f0dcd92f7feba6011ed4eac5c8d4f74cba9712f07fd5cfa3063bbdd95402c",
        4_336,
    ),
    file(
        "special_tokens_map.json",
        "068594063e37662c02b21acf42ebb334ef6a74fb810e68a2368f88f08351de76",
        1_632,
    ),
    file(
        "tokenizer_config.json",
        "e78a3ebb48a0b9437efd1823b6b726c823da89e49dd8bcc90c02419d9baa772b",
        5_059,
    ),
    file(
        "tokenizer.json",
        "f8984687e4a92a3503d521396d454b7d68e9fdaab2a0288eb3536c7c1aa4bc20",
        3_676_772,
    ),
    file(
        "audiovae.pth",
        "94b5d51e107e0507d4acc976cfdadb64edd6fd06d1f751dadbf2fd1594274bf1",
        376_951_122,
    ),
    file(
        "model.safetensors",
        "f7f964cfa9da23653baec6e6f7750719977ad944ed9f95fe52fe3a620506891d",
        4_580_080_592,
    ),
];

const fn file(path: &'static str, sha256: &'static str, bytes: u64) -> ArtifactFile {
    ArtifactFile {
        path: Cow::Borrowed(path),
        sha256: Cow::Borrowed(sha256),
        bytes,
    }
}

/// Apache-2.0, as every house model's card declares it, carried by
/// `licence_file`.
const fn apache(licence_file: &'static str) -> LicenceTerms {
    LicenceTerms {
        id: Cow::Borrowed("apache-2.0"),
        file: Cow::Borrowed(licence_file),
        decision: None,
    }
}
