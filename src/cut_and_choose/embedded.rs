//! Embedded test-utils fixtures for cut-and-choose flows.
//!
//! This module loads rkyv-serialized garbled instances from the
//! `.test-utils-data` directory when the `test-utils` feature is enabled.
use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalSerialize;
use blake3::Hasher as Blake3;
use rkyv::{
    Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, rancor::Failure,
    util::AlignedVec,
};
#[cfg(feature = "sp1-soldering")]
use sp1_prover::Groth16Bn254Proof;

#[cfg(feature = "sp1-soldering")]
use crate::sp1_soldering::SolderingProof;
use crate::{
    GarbledWire, S,
    cut_and_choose::{Config, Seed, garbler::GarbledInstance},
    garbled_groth16::GarblerCompressedInput,
};

/// Groth16 fixture blob embedded at compile time.
const GROTH16_FIXTURE_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/.test-utils-data/groth16/v1/instances.bin"
));

#[cfg(feature = "sp1-soldering")]
const GROTH16_SOLDERING_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/.test-utils-data/groth16/v1/soldering.bin"
));

const MAGIC: &[u8; 8] = b"GSVFIX01";

#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
struct HeaderV1 {
    magic: [u8; 8],
    version: u32,
    live_capacity: u32,
    public_params_len: u32,
    vk_hash_blake3: [u8; 32],
    seed_start: u64,
    seed_count: u32,
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
struct SWire {
    bytes: [u8; 16],
}

impl From<SWire> for S {
    fn from(value: SWire) -> Self {
        S::from_bytes(value.bytes)
    }
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
struct GarbledWireWire {
    label0: SWire,
    label1: SWire,
}

impl From<GarbledWireWire> for GarbledWire {
    fn from(value: GarbledWireWire) -> Self {
        GarbledWire {
            label0: value.label0.into(),
            label1: value.label1.into(),
        }
    }
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
struct GarbledInstanceWire {
    false_wire_constant: GarbledWireWire,
    true_wire_constant: GarbledWireWire,
    output_wire_values: GarbledWireWire,
    input_wire_values: Vec<GarbledWireWire>,
    ciphertext_handler_result: [u8; 16],
}

impl From<GarbledInstanceWire> for GarbledInstance {
    fn from(value: GarbledInstanceWire) -> Self {
        GarbledInstance {
            false_wire_constant: value.false_wire_constant.into(),
            true_wire_constant: value.true_wire_constant.into(),
            output_wire_values: value.output_wire_values.into(),
            input_wire_values: value
                .input_wire_values
                .into_iter()
                .map(Into::into)
                .collect(),
            ciphertext_handler_result: value.ciphertext_handler_result,
        }
    }
}

#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
struct FixtureFileV1 {
    header: HeaderV1,
    instances: Vec<GarbledInstanceWire>,
}

/// Embedded groth16 fixture (seeds + instances).
pub struct EmbeddedFixture {
    pub seed_start: Seed,
    pub instances: Vec<GarbledInstance>,
}

#[cfg(feature = "sp1-soldering")]
const SOLDER_MAGIC: &[u8; 8] = b"GSVSOL01";

#[cfg(feature = "sp1-soldering")]
#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
struct SolderHeaderV1 {
    magic: [u8; 8],
    version: u32,
    live_capacity: u32,
    public_params_len: u32,
    vk_hash_blake3: [u8; 32],
    total: u32,
    to_finalize: u32,
    nonce: u128,
    seed_start: u64,
    seed_count: u32,
}

#[cfg(feature = "sp1-soldering")]
#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
struct SolderingProofWire {
    public_inputs: [String; 2],
    encoded_proof: String,
    raw_proof: String,
    groth16_vkey_hash: [u8; 32],
    deltas: Vec<Vec<(u128, u128)>>,
}

#[cfg(feature = "sp1-soldering")]
impl From<SolderingProofWire> for SolderingProof {
    fn from(value: SolderingProofWire) -> Self {
        SolderingProof {
            proof: Groth16Bn254Proof {
                public_inputs: value.public_inputs,
                encoded_proof: value.encoded_proof,
                raw_proof: value.raw_proof,
                groth16_vkey_hash: value.groth16_vkey_hash,
            },
            deltas: value.deltas,
        }
    }
}

#[cfg(feature = "sp1-soldering")]
#[derive(Archive, RkyvSerialize, RkyvDeserialize)]
struct SolderFixtureV1 {
    header: SolderHeaderV1,
    finalize_indexes: Vec<u32>,
    proof: SolderingProofWire,
}

#[cfg(feature = "sp1-soldering")]
pub struct EmbeddedSolderingFixture {
    pub finalize_indexes: Vec<usize>,
    pub proof: SolderingProof,
    pub nonce: S,
    pub seed_start: Seed,
    pub seed_count: usize,
}

fn load_fixture_bytes() -> Option<FixtureFileV1> {
    let mut aligned = AlignedVec::<16>::new();
    aligned.extend_from_slice(GROTH16_FIXTURE_BYTES);
    unsafe { rkyv::from_bytes_unchecked::<FixtureFileV1, Failure>(&aligned).ok() }
}

#[cfg(feature = "sp1-soldering")]
fn load_soldering_bytes() -> Option<SolderFixtureV1> {
    let mut aligned = AlignedVec::<16>::new();
    aligned.extend_from_slice(GROTH16_SOLDERING_BYTES);
    unsafe { rkyv::from_bytes_unchecked::<SolderFixtureV1, Failure>(&aligned).ok() }
}

fn vk_hash(vk: &VerifyingKey<Bn254>) -> [u8; 32] {
    let mut buf = Vec::new();
    vk.serialize_compressed(&mut buf).expect("serialize vk");
    let mut hasher = Blake3::new();
    hasher.update(&buf);
    *hasher.finalize().as_bytes()
}

/// Try to load embedded Groth16 fixtures for the provided configuration.
pub fn try_load_groth16(
    config: &Config<GarblerCompressedInput>,
    live_capacity: usize,
) -> Option<EmbeddedFixture> {
    let fixture = load_fixture_bytes()?;

    if fixture.header.magic != *MAGIC || fixture.header.version != 1 {
        return None;
    }

    if fixture.header.live_capacity as usize != live_capacity {
        return None;
    }

    let input = &**config.input();

    if fixture.header.public_params_len as usize != input.public_params_len {
        return None;
    }

    if fixture.header.seed_count == 0 {
        return None;
    }

    if config.total() > fixture.header.seed_count as usize {
        return None;
    }

    let expected_vk_hash = vk_hash(&input.vk);
    if fixture.header.vk_hash_blake3 != expected_vk_hash {
        return None;
    }

    let seed_start = fixture.header.seed_start;

    let instances = fixture
        .instances
        .into_iter()
        .take(config.total())
        .map(Into::into)
        .collect::<Vec<_>>();

    Some(EmbeddedFixture {
        seed_start,
        instances,
    })
}

#[cfg(feature = "sp1-soldering")]
pub fn try_load_groth16_soldering(
    config: &Config<GarblerCompressedInput>,
    live_capacity: usize,
    finalize_indexes: &[usize],
    nonce: S,
) -> Option<EmbeddedSolderingFixture> {
    let fixture = load_soldering_bytes()?;

    if fixture.header.magic != *SOLDER_MAGIC || fixture.header.version != 1 {
        return None;
    }

    if fixture.header.live_capacity as usize != live_capacity {
        return None;
    }

    let input = &**config.input();

    if fixture.header.public_params_len as usize != input.public_params_len {
        return None;
    }

    if fixture.header.total as usize != config.total() {
        return None;
    }

    if fixture.header.to_finalize as usize != config.to_finalize() {
        return None;
    }

    if (fixture.header.seed_count as usize) < config.total() {
        return None;
    }

    let expected_vk_hash = vk_hash(&input.vk);
    if fixture.header.vk_hash_blake3 != expected_vk_hash {
        return None;
    }

    if fixture.header.nonce != nonce.to_u128() {
        return None;
    }

    if fixture.finalize_indexes.len() != finalize_indexes.len() {
        return None;
    }

    let mut expected = finalize_indexes.to_vec();
    expected.sort_unstable();

    let mut recorded = fixture
        .finalize_indexes
        .iter()
        .map(|&idx| idx as usize)
        .collect::<Vec<_>>();
    recorded.sort_unstable();

    if recorded != expected {
        return None;
    }

    Some(EmbeddedSolderingFixture {
        finalize_indexes: fixture
            .finalize_indexes
            .into_iter()
            .map(|idx| idx as usize)
            .collect(),
        proof: fixture.proof.into(),
        nonce,
        seed_start: fixture.header.seed_start,
        seed_count: fixture.header.seed_count as usize,
    })
}

/// Returns true when the embedded groth16 fixture matches the provided configuration.
pub fn is_groth16_available(config: &Config<GarblerCompressedInput>, live_capacity: usize) -> bool {
    try_load_groth16(config, live_capacity).is_some()
}
