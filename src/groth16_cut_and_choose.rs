//! Groth16-specialized cut-and-choose API (compressed) built on the generic module.

use ark_bn254::Bn254;
use ark_groth16::VerifyingKey;

use crate::{
    AesNiHasher, GarbleMode, GarbledWire,
    circuit::streaming::{CircuitMode, StreamingMode, WiresObject},
    cut_and_choose,
    garbled_groth16::{self as gg, ProofCompressedWires},
};

/// Inputs adapter for compressed Groth16: allocates wires and issues garbled labels.
#[derive(Debug, Clone)]
pub struct GarbledCompressedInputs {
    pub public_params_len: usize,
    pub vk: VerifyingKey<Bn254>,
}

impl crate::circuit::streaming::CircuitInput for GarbledCompressedInputs {
    type WireRepr = ProofCompressedWires;
    fn allocate(&self, mut issue: impl FnMut() -> crate::WireId) -> Self::WireRepr {
        gg::ProofCompressedWires {
            public: (0..self.public_params_len)
                .map(|_| crate::FrWire::new(&mut issue))
                .collect(),
            a: crate::gadgets::groth16::CompressedG1Wires::new(&mut issue),
            b: crate::gadgets::groth16::CompressedG2Wires::new(&mut issue),
            c: crate::gadgets::groth16::CompressedG1Wires::new(issue),
            vk: self.vk.clone(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<H: crate::hashers::GateHasher>
    crate::circuit::streaming::EncodeInput<crate::circuit::streaming::modes::GarbleMode<H>>
    for GarbledCompressedInputs
{
    fn encode(
        &self,
        repr: &ProofCompressedWires,
        cache: &mut crate::circuit::streaming::modes::GarbleMode<H>,
    ) {
        // Issue fresh labels for all bits in public inputs
        for w in &repr.public {
            for &wire in w.iter() {
                let gw = cache.issue_garbled_wire();
                cache.feed_wire(wire, gw);
            }
        }
        for &wire_id in repr.a.to_wires_vec().iter() {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
        for &wire_id in repr.b.to_wires_vec().iter() {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
        for &wire_id in repr.c.to_wires_vec().iter() {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
    }
}

/// Re-export the generic Config specialized to compressed Groth16 inputs.
pub type Config = cut_and_choose::Config<GarbledCompressedInputs>;

/// Type aliases for the Groth16 cut-and-choose specializations.
pub type Groth16Garbler = cut_and_choose::Garbler<GarbledCompressedInputs, GarbledWire>;
pub type Groth16Open = cut_and_choose::GarbleOpen;
pub type Groth16Inputs = GarbledCompressedInputs;
/// Alias to the semantic compressed input wrapper (non-garbling) for convenience.
pub type CompressedInput = gg::Compressed;

/// Create a Groth16Garbler from `Config`, baking in the compressed verify function.
pub fn create(rng: impl rand::Rng, cfg: Config) -> Groth16Garbler {
    cut_and_choose::Garbler::create(
        rng,
        cfg,
        |ctx: &mut StreamingMode<GarbleMode<AesNiHasher>>, wires: &ProofCompressedWires| {
            gg::verify_compressed(ctx, wires)
        },
    )
}

/// Open a subset of instances using the compressed Groth16 verification circuit.
pub fn open(garbler: &Groth16Garbler, indexes_to_evaluate: &[usize]) -> Groth16Open {
    garbler.open(
        indexes_to_evaluate,
        |ctx: &mut StreamingMode<GarbleMode<AesNiHasher>>, wires: &ProofCompressedWires| {
            gg::verify_compressed(ctx, wires)
        },
    )
}
