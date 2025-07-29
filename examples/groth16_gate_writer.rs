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
use garbled_snark_verifier::bag::*;
use garbled_snark_verifier::circuits::{
    bn254::{fr::Fr, g1::G1Affine, g2::G2Affine},
    groth16::groth16_verifier_evaluate_montgomery,
};
use garbled_snark_verifier::core::serialization::{read_gates, GateWriter};

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

fn main() -> std::io::Result<()> {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<ark_bn254::Bn254 as Pairing>::ScalarField> {
        a: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 64,
    };
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).unwrap();
    let c = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).unwrap();
    let public = Fr::wires_set(c);
    let proof_a = G1Affine::wires_set_montgomery(proof.a);
    let proof_b = G2Affine::wires_set_montgomery(proof.b);
    let proof_c = G1Affine::wires_set_montgomery(proof.c);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("verifier_gates.bin");
    Circuit::start_gate_recording(&path)?;
    let (result, _gc) =
        groth16_verifier_evaluate_montgomery(public, proof_a, proof_b, proof_c, vk, false);
    Circuit::finish_gate_recording()?;
    println!("Verification result: {}", result.borrow().get_value());
    let records = read_gates(&path)?;
    println!("Stored {} gate records", records);
    Ok(())
}
