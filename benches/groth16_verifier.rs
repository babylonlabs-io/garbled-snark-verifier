use std::hint::black_box;

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};

use criterion::{criterion_group, criterion_main, Criterion};

use garbled_snark_verifier::circuits::{
    bn254::{fr::Fr, g1::G1Affine, g2::G2Affine},
    groth16::groth16_verifier_evaluate,
};

#[derive(Copy, Clone)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

fn bench_groth16_verifier_evaluate(criterion: &mut Criterion) {
    // Setup - done once outside the benchmark iteration
    let k = 6;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
        a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
    let c = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    // Convert to garbled circuit wires - setup once
    let public = Fr::wires_set(c);
    let proof_a = G1Affine::wires_set(proof.a);
    let proof_b = G2Affine::wires_set(proof.b);
    let proof_c = G1Affine::wires_set(proof.c);

    criterion.bench_function("groth16_verifier_evaluate", |b| {
        b.iter(|| {
            // Only benchmark the garbled circuit evaluation
            let (result, _gate_count) = groth16_verifier_evaluate(
                black_box(public.clone()),
                black_box(proof_a.clone()),
                black_box(proof_b.clone()),
                black_box(proof_c.clone()),
                black_box(vk.clone()),
            );
            black_box(result.borrow().get_value())
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10); // Set sample size to 10
    targets = bench_groth16_verifier_evaluate
);

criterion_main!(benches);
